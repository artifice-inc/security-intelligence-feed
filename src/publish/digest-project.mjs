import { daysBetween } from '../lib/time.mjs';
import { sanitizeInline } from '../lib/sanitize-md.mjs';
import { priorityRank } from '../match/priority.mjs';
import { LABELS, projectLabel } from './issue-body.mjs';
import { runtimeGroups } from './runtime-groups.mjs';

export const cell = (text) => sanitizeInline(String(text ?? ''), 80).replace(/\|/g, '\\|');
export const issueRef = (centralRepo, number) => (number ? `[#${number}](https://github.com/${centralRepo}/issues/${number})` : '—');

// GitHub の検索クエリを URL にする。Markdown のリンクを壊さないよう括弧もエンコードする
const searchUrl = (centralRepo, query) => `https://github.com/${centralRepo}/issues?q=${encodeURIComponent(query).replace(/\(/g, '%28').replace(/\)/g, '%29')}`;
const quoted = (name) => `"${projectLabel(name).replace(/"/g, '\\"')}"`;

// 案件ごとの絞り込みリンク（ラベルで絞る。タイトルの部分一致は案件名が混ざるため使わない）
export function projectLinks(centralRepo, name) {
  const open = `[未解決](${searchUrl(centralRepo, `is:issue is:open label:${LABELS.finding} label:${quoted(name)} -label:${LABELS.fixed} -label:${LABELS.superseded}`)})`;
  const waiting = `[本番反映待ち](${searchUrl(centralRepo, `is:issue is:open label:${quoted(name)} label:${LABELS.fixed}`)})`;
  return `${open} / ${waiting}`;
}

const byPriorityThenKey = (a, b) => priorityRank(a.priority) - priorityRank(b.priority) || (a.advisory_key < b.advisory_key ? -1 : a.advisory_key > b.advisory_key ? 1 : 0);

// lockfile ごとの件数。ランタイムは lockfile ではないので数えない（まとめの1行で示す）
function lockfileLines(items) {
  const counts = new Map();
  for (const item of items) {
    for (const lockfile of new Set(item.locations.filter((l) => l.ecosystem !== 'runtime' && l.ecosystem !== 'os').map((l) => l.lockfile))) {
      if (!counts.has(lockfile)) counts.set(lockfile, { P0: 0, P1: 0, P2: 0, P3: 0 });
      counts.get(lockfile)[item.priority] += 1;
    }
  }
  return [...counts].sort(([a], [b]) => (a < b ? -1 : 1)).map(([lockfile, c]) => `- ${cell(lockfile)}：${Object.entries(c).filter(([, n]) => n > 0).map(([p, n]) => `${p} ${n}`).join(' / ')}`);
}

// 案件別の状況。Issue の状態は findings ではなく snapshot から作る（解消した項目は findings に残らないため）
export function projectSections({ projects, findingsByProject, snapshot, digestInfo, centralRepo, now, thresholds }) {
  const lines = [];
  for (const project of projects) {
    const name = project.project;
    const findings = findingsByProject.get(name);
    const mine = (snapshot ?? []).filter((i) => i.project === name);
    const numberOfGroup = (key) => mine.find((i) => i.aliases.includes(key))?.issue_number ?? null;
    const items = findings?.items ?? [];
    const issueItems = runtimeGroups(items).issueItems.sort(byPriorityThenKey);
    const line = (item) => `- **${item.priority}** ${item.members ? '' : `\`${cell(item.advisory_key)}\` ${cell(item.locations[0]?.package)} `}${item.members ? `${cell(item.title)} ` : ''}${item.kev ? '【KEV】' : ''}${issueRef(centralRepo, item.members ? numberOfGroup(item.advisory_key) : item.issue_number)}`;
    const needAction = issueItems.filter((i) => ['P0', 'P1', 'P2'].includes(i.priority));
    const review = issueItems.filter((i) => i.priority === 'P3');
    const since = new Map((digestInfo?.fixedInRepo ?? []).map((f) => [f.issue_number, f.since]));
    const waiting = mine.filter((i) => i.state === 'open' && i.labels.includes(LABELS.fixed));
    const superseded = (digestInfo?.superseded ?? []).filter((s) => s.project === name);
    const sections = [
      ['', lockfileLines(items)],
      ['#### 対応が必要（P0〜P2）', needAction.map(line)],
      ['#### 要確認（P3）', review.map(line)],
      ['#### 本番反映待ち（fixed-in-repo）', waiting.map((i) => `- ${issueRef(centralRepo, i.issue_number)} \`${cell(i.aliases[0])}\`${since.get(i.issue_number) && daysBetween(since.get(i.issue_number), now) > thresholds.fixed_in_repo_reminder_days ? '（14日超）' : ''}`)],
      ['#### まとめ先へ移行済み（superseded）', superseded.map((s) => `- ${issueRef(centralRepo, s.issue_number)} → まとめ先 ${issueRef(centralRepo, s.superseded_by)}${snapshot && !snapshot.some((i) => i.issue_number === s.superseded_by) ? '（見つかりません）' : ''}`)],
    ].filter(([, body]) => body.length > 0);
    lines.push(`### ${cell(name)}`, '');
    if (sections.length === 0) lines.push(findings ? '- 未解決なし' : '- 未照合（結果なし）', '');
    for (const [heading, body] of sections) lines.push(...(heading ? [heading, ''] : []), ...body, '');
  }
  return lines;
}
