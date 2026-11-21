import { loadThresholds } from '../lib/config.mjs';
import { daysBetween } from '../lib/time.mjs';
import { nextScheduledTime } from '../lib/schedule.mjs';
import { priorityRank } from '../match/priority.mjs';
import { staleSources, overdueOptionalSources } from './health.mjs';
import { changedItems } from '../normalize/aws-bulletins.mjs';
import { LABELS } from './issue-body.mjs';
import { sanitizeInline } from '../lib/sanitize-md.mjs';
import { cell, issueRef, projectLinks, projectSections } from './digest-project.mjs';
import { runtimeGroups } from './runtime-groups.mjs';

const jst = (iso) => (iso ? new Date(iso).toLocaleString('sv-SE', { timeZone: 'Asia/Tokyo' }).replace(' ', ' ') + ' JST' : '—');

function countIssues(snapshot, project) {
  if (!snapshot) return null;
  const mine = snapshot.filter((i) => i.project === project);
  const open = mine.filter((i) => i.state === 'open' && typeof i.superseded_by !== 'number'); // 移行済み（sb 由来）は数えない
  const byPriority = (p) => open.filter((i) => !i.labels.includes(LABELS.fixed) && i.labels.includes(p)).length;
  return {
    p0: byPriority('P0'), p1: byPriority('P1'), p2: byPriority('P2'),
    fixed: open.filter((i) => i.labels.includes(LABELS.fixed)).length,
    accepted: mine.filter((i) => i.state === 'closed' && i.labels.includes(LABELS.accepted)).length,
  };
}

function projectTable({ projects, findingsByProject, snapshot, centralRepo }) {
  const rows = projects.map((p) => {
    const f = findingsByProject.get(p.project);
    const c = countIssues(snapshot, p.project);
    const repo = p.repo ? `[${cell(p.repo)}](https://github.com/${p.repo})` : '（export）';
    return `| ${cell(p.project)} | ${repo} | ${cell(f?.monitor_ref ?? p.monitor_ref)} | ${p.repo ? 'pull' : 'export'} | ${jst(f?.scanned_at)} | ${f?.scan_status ?? '未照合'} | ${f?.inventory_status ?? '未取得'} | ${c ? `${c.p0} / ${c.p1} / ${c.p2}` : '不明'} | ${c ? c.fixed : '不明'} | ${c ? c.accepted : '不明'} | ${projectLinks(centralRepo, p.project)} |`;
  });
  return ['| 案件 | リポジトリ | 監視ブランチ | 方式 | 最終照合 | scan_status | inventory_status | 未解決 P0 / P1 / P2 | fixed-in-repo 待ち | リスク受容中 | 一覧 |', '|---|---|---|---|---|---|---|---|---|---|---|', ...rows];
}

const itemLine = (centralRepo, project, item) => `- **${item.priority}** \`${cell(project)}\` \`${cell(item.advisory_key)}\` ${cell(item.locations[0]?.package)} ${item.kev ? '【KEV】' : ''}${issueRef(centralRepo, item.issue_number)}`;

// 自動で下げなかった優先度の欄。run-match だけが出す。まとめ項目に入る項目は、まとめのキーを併記する
const NOTE_PREFIX = '計算上は';
function keptPriorityLines({ projects, findingsByProject }) {
  const lines = projects.flatMap((p) => {
    const items = findingsByProject.get(p.project)?.items ?? [];
    const groupsOf = [...runtimeGroups(items).memberKeys];
    return items.filter((i) => i.priority_note?.startsWith(NOTE_PREFIX)).sort((a, b) => priorityRank(a.priority) - priorityRank(b.priority) || a.advisory_key.localeCompare(b.advisory_key))
      .map((i) => {
        const groups = groupsOf.filter(([, members]) => members.includes(i.advisory_key)).map(([key]) => key);
        return `- \`${cell(p.project)}\` \`${cell(i.advisory_key)}\`${groups.length ? `（まとめ: ${groups.map((g) => `\`${cell(g)}\``).join(', ')}）` : ''} **${i.priority}** ${cell(i.priority_note)}`;
      });
  });
  return lines.length === 0 ? [] : ['### 自動で下げなかった優先度', '', ...lines, ''];
}

// フィードを確認できなかった回は「新着なし」と区別する（不変条件4）
const UNAVAILABLE_LINE = '- 取得できませんでした';

// 成功と判定できなかった情報源（run-match の予定枠の判定）は、OK と出さずに理由を添える
function statusOf(name, source, stale, verdicts) {
  const base = stale.includes(name) ? '**情報が古い（36時間超）**' : source.last_error ? '直近の取得に失敗' : null;
  const verdict = verdicts?.[name];
  if (verdict && !verdict.ok) return `${base ?? '**成功と判定できません**'}（${cell(verdict.reason)}）`;
  return base ?? 'OK';
}

// 実行のたびに変わる「生成日時」は入れない。内容が前回と同じならファイルを更新しない（呼び出し側が比較）
export function renderDigest({ projects, findingsByProject, snapshot, digestInfo, health, schedule, now, centralRepo, kevRecords, jpItems, awsBulletins = null, thresholds = loadThresholds(), priorityNotes = false, feedUnavailable = false, sourceVerdicts = null }) {
  const entries = projects.flatMap((p) => (findingsByProject.get(p.project)?.items ?? []).map((item) => ({ project: p.project, item, scanned_at: findingsByProject.get(p.project).scanned_at })));
  const order = (a, b) => priorityRank(a.item.priority) - priorityRank(b.item.priority) || a.project.localeCompare(b.project) || a.item.advisory_key.localeCompare(b.item.advisory_key);
  const recent = entries.filter((e) => e.item.first_detected_at === e.scanned_at).sort(order);
  const recurrences = (digestInfo?.transitions ?? []).filter((t) => ['recurrence', 'risk_reopen', 'misclose'].includes(t.kind));
  const stale = staleSources(health, now, thresholds);

  const kev = (kevRecords ?? []).filter((r) => r.dateAdded && daysBetween(r.dateAdded, now) <= thresholds.digest_new_days && (/\b(php|node\.?js|python)\b/i.test(`${r.vendorProject} ${r.product}`) || (r.vendorProject === 'Linux' && r.product === 'Kernel')));
  const jp = (jpItems ?? []).filter((i) => i.first_seen_at && daysBetween(i.first_seen_at, now) <= thresholds.digest_new_days);

  const aws = awsBulletins ? changedItems(awsBulletins, now, thresholds.digest_new_days) : { added: [], updated: [] };
  // 表のセルではないので cell() の80文字制限は使わない。cves はタイトルから抽出したものなので重ねて書かない
  const awsLine = (prefix) => (i) => `- ${prefix}[${cell(i.id)}](${i.url}) ${sanitizeInline(i.title)} 掲載日時（RSS）: ${jst(i.rss_pub_date)}`;
  const overdue = new Set(overdueOptionalSources(health, now, thresholds).map((s) => s.name));

  const lines = [
    '# セキュリティ情報 digest', '',
    `- 最終成功日時: ${jst(health.last_success_at)}`,
    `- 次の予定時刻: ${jst(nextScheduledTime(schedule, now)?.toISOString())}`, '',
    '## 1. 監視対象の案件', '', ...projectTable({ projects, findingsByProject, snapshot, centralRepo }), '',
    '## 2. この回の新規検出・再発', '',
    ...(recent.length + recurrences.length === 0 ? ['- なし'] : [...recent.map((e) => itemLine(centralRepo, e.project, e.item)), ...recurrences.map((t) => `- ${t.kind === 'recurrence' ? '再発' : t.kind === 'risk_reopen' ? 'リスク受容の解除' : '誤クローズの再オープン'}: \`${cell(t.project)}\` ${issueRef(centralRepo, t.issue_number)}`)]), '',
    ...(priorityNotes ? keptPriorityLines({ projects, findingsByProject }) : []),
    '## 3. 案件別の状況', '', ...projectSections({ projects, findingsByProject, snapshot, digestInfo, centralRepo, now, thresholds }),
    '## 4. リスク受容中', '',
    ...((digestInfo?.riskAccepted ?? []).length === 0 ? ['- なし'] : digestInfo.riskAccepted.map((r) => `- \`${cell(r.project)}\` ${issueRef(centralRepo, r.issue_number)}（付与 ${jst(r.accepted_at)}、${r.expires_after_days}日で期限）`)), '',
    '## 5. 新着情報', '', '### KEV（PHP / Node.js / Python / Linux カーネル）', '',
    ...(feedUnavailable ? [UNAVAILABLE_LINE] : kev.length === 0 ? ['- なし'] : kev.map((r) => `- ${cell(r.cveID)} ${cell(r.vendorProject)} ${cell(r.product)}（${cell(r.dateAdded)}）`)), '',
    '### 国内の注意喚起（JPCERT / IPA / JVN）', '',
    ...(feedUnavailable ? [UNAVAILABLE_LINE] : jp.length === 0 ? ['- なし'] : jp.map((i) => `- [${cell(i.source)}] ${cell(i.title)} ${i.cves.length ? `（${i.cves.map(cell).join(', ')}）` : ''}`)), '',
    '### AWS の公開注意喚起（Security Bulletins）', '',
    ...(feedUnavailable ? [UNAVAILABLE_LINE] : aws.added.length + aws.updated.length === 0 ? ['- なし'] : [...aws.added.map(awsLine('')), ...aws.updated.map(awsLine('（更新）'))]), '',
    '## 6. 情報源の状態', '', '| 情報源 | 最終成功 | 状態 |', '|---|---|---|',
    ...Object.entries(health.sources).sort(([a], [b]) => a.localeCompare(b)).map(([name, s]) => `| ${cell(name)} | ${jst(s.last_success_at)} | ${statusOf(name, s, stale, sourceVerdicts)} |`),
    ...Object.entries(health.optional_sources ?? {}).sort(([a], [b]) => a.localeCompare(b)).map(([name, s]) => `| ${cell(name)}（任意） | ${jst(s.last_success_at)} | ${overdue.has(name) ? `**${thresholds.optional_source_alert_days}日以上取得できていません**` : s.last_error ? '直近の取得に失敗' : 'OK'} |`), '',
  ];
  return `${lines.join('\n')}`;
}
