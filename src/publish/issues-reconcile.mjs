import { randomUUID } from 'node:crypto';
import { sharesAlias } from '../lib/aliases.mjs';
import { daysBetween } from '../lib/time.mjs';
import { loadThresholds } from '../lib/config.mjs';
import { isHigherPriority } from '../match/priority.mjs';
import { LABELS, projectLabel, issueTitle, renderBody, bodyHash, buildMarker, withMarker, markerLine, parseMarker } from './issue-body.mjs';
import { newNoticeId, noticeBody, sentNoticeIds } from './notices.mjs';
import { runtimeGroups, memberNumbers } from './runtime-groups.mjs';
import { emptyDigestInfo, collectDigestInfo } from './digest-info.mjs';
import { migrationDestination, movedMembers, migratedTarget, vanishedGroupTarget, withdrawnMembers, isKernelGroupIssue } from './runtime-migration.mjs';

const LABEL_COLORS = { 'security-finding': 'b60205', 'fixed-in-repo': '0e8a16', 'risk-accepted': 'fbca04', 'advisory-withdrawn': 'cccccc', 'duplicate-candidate': 'cccccc', superseded: 'cccccc', health: 'd93f0b', P0: 'b60205', P1: 'd93f0b', P2: 'fbca04', P3: 'c2e0c6' };
const PROJECT_LABEL_COLOR = 'ededed';
const ALL_LABELS = Object.keys(LABEL_COLORS);

const FAILED = Symbol('failed');
const priorityLabelOf = (labels) => LABELS.priorities.find((p) => labels.has(p)) ?? null;
const markerShape = (m) => ({ project: m.project, aliases: [...m.aliases].sort(), h: m.h, pending: m.pending ?? [], sb: m.sb ?? null, mk: m.mk ? [...m.mk].sort() : null });
const sameSet = (left, right) => left.size === right.size && [...left].every((v) => right.has(v));

// 脆弱性 Issue の reconcile。毎回「目標の状態」を findings と GitHub の現状から計算し、差分だけを操作する（D1）
// 一覧 API は作成直後の Issue を返さないことがある。この回の書き込み結果を覚えておき、スナップショットに必ず含める
function trackWrites(rawApi, known, live) {
  const apply = (number, next) => live.set(number, { ...(live.get(number) ?? known.get(number) ?? { number }), ...next });
  return {
    botLogin: rawApi.botLogin,
    listLabels: () => rawApi.listLabels(),
    createLabel: (...args) => rawApi.createLabel(...args),
    listIssues: (args) => rawApi.listIssues(args),
    getIssue: (number) => rawApi.getIssue(number),
    listIssueEvents: (number) => rawApi.listIssueEvents(number),
    listComments: (number) => rawApi.listComments(number),
    createComment: (...args) => rawApi.createComment(...args),
    async createIssue(data) { const created = await rawApi.createIssue(data); live.set(created.number, created); return created; },
    async updateIssue(number, patch) {
      const result = await rawApi.updateIssue(number, patch);
      apply(number, Object.fromEntries(['state', 'title', 'body', 'labels'].filter((k) => patch[k] !== undefined).map((k) => [k, patch[k]])));
      return result;
    },
  };
}

// previousSnapshot: 前回の data/issues.json。一覧に出ない既存 Issue を番号で取りに行くための補助（同一性の正本はあくまで本文のマーカー）
export async function reconcileIssues({ api: rawApi, projects, findingsByProject, isWithdrawnAliases = () => false, now, thresholds = loadThresholds(), generateId = randomUUID, previousSnapshot = [] }) {
  const known = new Map();
  const live = new Map();
  const api = trackWrites(rawApi, known, live);
  const errors = [];
  const warnings = [];
  const issueNumbers = new Map();
  const attempt = async (label, work) => { try { return await work(); } catch (error) { errors.push({ target: label, message: error.message }); return FAILED; } };

  const labelResult = await attempt('labels', () => api.listLabels());
  const existingLabels = labelResult === FAILED ? null : labelResult;
  for (const name of ALL_LABELS.filter((n) => existingLabels && !existingLabels.includes(n))) {
    await attempt(`label:${name}`, () => api.createLabel(name, LABEL_COLORS[name], 'security-intelligence'));
  }

  for (const { project } of existingLabels ? projects : []) {
    const name = projectLabel(project);
    if (!existingLabels.includes(name)) await attempt(`label:${name}`, () => api.createLabel(name, PROJECT_LABEL_COLOR, 'security-intelligence'));
  }

  const listed = await attempt('issues', () => api.listIssues({ label: LABELS.finding }));
  if (listed === FAILED) return { issueNumbers, snapshot: null, errors, warnings, digestInfo: emptyDigestInfo() };
  for (const issue of listed) known.set(issue.number, issue);
  for (const { issue_number: number } of previousSnapshot) {
    if (known.has(number)) continue;
    try {
      const issue = await api.getIssue(number);
      if (issue.labels.includes(LABELS.finding)) known.set(number, issue);
    } catch (error) {
      if (error.http_status === 404) warnings.push(`前回の Issue #${number} を取得できませんでした（削除された可能性）`);
      else errors.push({ target: `issue:#${number}`, message: error.message });
    }
  }
  const parsed = [];
  for (const issue of known.values()) {
    const marker = parseMarker(issue.body);
    if (!marker) { warnings.push(`Issue #${issue.number} のマーカーを解析できないため無視しました`); continue; }
    for (const key of marker.ignored) warnings.push(`Issue #${issue.number} のマーカーの ${key} の型が不正なため、そのキーを無視しました`);
    parsed.push({ ...issue, marker });
  }
  parsed.sort((a, b) => a.number - b.number);

  const digestInfo = emptyDigestInfo();
  for (const project of projects) {
    const findings = findingsByProject.get(project.project);
    if (!findings) continue;
    const ofProject = parsed.filter((i) => i.marker.project === project.project);
    // 移行済み（sb あり）の Issue は、item との対応づけにも重複の判定にも使わない（閉じた移行済み Issue を再オープンしないため）
    const migrated = ofProject.filter((i) => i.marker.sb !== undefined);
    const mine = ofProject.filter((i) => i.marker.sb === undefined);
    const claimed = new Set();
    const numbers = new Map();
    const { issueItems } = runtimeGroups(findings.items);
    const context = { api, project, findings, now, thresholds, generateId, attempt, isWithdrawnAliases, digestInfo, errors, warnings, issueItems, numbers };

    for (const item of issueItems) {
      const matches = mine.filter((i) => sharesAlias(i.marker.aliases, item.aliases));
      const canonical = matches.find((i) => !claimed.has(i.number));
      if (!canonical) {
        if (matches.length > 0) { numbers.set(item.advisory_key, matches[0].number); continue; } // 同じ Issue に複数の項目が対応している
        const created = await createFor(context, item);
        if (created) numbers.set(item.advisory_key, created);
        continue;
      }
      claimed.add(canonical.number);
      numbers.set(item.advisory_key, canonical.number);
      await processExisting(context, canonical, item);
      for (const duplicate of matches.filter((i) => i.number !== canonical.number && !claimed.has(i.number))) {
        claimed.add(duplicate.number);
        await processDuplicate(context, duplicate);
      }
    }
    const groupItems = issueItems.filter((i) => i.members);
    for (const issue of mine.filter((i) => !claimed.has(i.number))) {
      if (!(await migrateLegacy(context, issue, groupItems, numbers))) await processUnmatched(context, issue);
    }
    for (const issue of migrated) await applyChange(context, issue, { ...migratedTarget(issue, context), text: null });
    for (const [key, number] of memberNumbers(findings.items, numbers)) numbers.set(key, number);
    issueNumbers.set(project.project, numbers);
  }

  // 一覧（最新）→ この回の書き込み結果の順に上書きする。一覧の反映遅れで抜けないようにする
  const snapshot = await attempt('snapshot', async () => {
    const merged = new Map(known);
    for (const issue of await api.listIssues({ label: LABELS.finding })) merged.set(issue.number, issue);
    for (const [number, issue] of live) merged.set(number, { ...(merged.get(number) ?? {}), ...issue });
    return [...merged.values()];
  }).then((all) => (all === FAILED ? FAILED : all.flatMap((i) => {
    const marker = parseMarker(i.body);
    return marker ? [{ issue_number: i.number, project: marker.project, aliases: marker.aliases, state: i.state, labels: [...i.labels].sort(), superseded_by: marker.sb ?? null, member_keys: marker.mk ?? [] }] : [];
  }).sort((a, b) => a.issue_number - b.issue_number)));
  const ok = snapshot !== FAILED;
  await collectDigestInfo({ api, snapshot: ok ? snapshot : [], digestInfo, now, thresholds, errors });
  return { issueNumbers, snapshot: ok ? snapshot : null, errors, warnings, digestInfo };
}

async function createFor(context, item) {
  if (!['P0', 'P1', 'P2'].includes(item.priority)) return null; // P3 は digest に載せるだけ
  const { api, project } = context;
  const text = renderBody({ project: project.project, item, owners: project.owners, scannedAt: context.findings.scanned_at });
  const marker = buildMarker({ project: project.project, aliases: item.aliases, hash: bodyHash(text), mk: item.members?.map((m) => m.advisory_key) });
  const created = await context.attempt(`create:${item.advisory_key}`, () => api.createIssue({
    title: issueTitle(project.project, item), body: withMarker(text, marker), labels: [LABELS.finding, item.priority, projectLabel(project.project)], assignees: project.owners,
  }));
  return created === FAILED ? null : created.number;
}

// settle: マーカーの pending を調べ、投稿済みなら外し、未投稿なら投稿する（再試行）
async function settlePending(context, issue, pending) {
  if (pending.length === 0) return { remaining: [] };
  const { api } = context;
  const comments = await context.attempt(`comments:#${issue.number}`, () => api.listComments(issue.number));
  if (comments === FAILED) return { remaining: pending };
  const sent = sentNoticeIds(comments, api.botLogin);
  const remaining = [];
  for (const notice of pending) {
    if (sent.has(notice.id)) continue;
    const posted = await context.attempt(`notice:#${issue.number}`, () => api.createComment(issue.number, noticeBody(notice, context.project.owners)));
    if (posted === FAILED) remaining.push(notice);
  }
  return { remaining };
}

// 状態・ラベル・本文の変更を PATCH 1回にまとめ、新しい通知を pending に入れる。続いてコメントを投稿し、成功したら pending を外す
async function applyChange(context, issue, { labels, state, title, text, aliases, notices, sb = issue.marker.sb, mk = issue.marker.mk }) {
  const { api, project } = context;
  const { remaining } = await settlePending(context, issue, issue.marker.pending);
  for (const [kind] of notices) context.digestInfo.transitions.push({ project: project.project, issue_number: issue.number, kind });
  const fresh = notices.map(([kind, reason]) => ({ id: newNoticeId(kind, context.generateId), kind, reason: reason ?? '' }));
  const hash = text === null ? issue.marker.h : bodyHash(text);
  const marker = buildMarker({ project: project.project, aliases: aliases ?? issue.marker.aliases, hash, pending: [...remaining, ...fresh], sb, mk });
  const bodyText = text ?? issue.body.trimEnd().split('\n').slice(0, -1).join('\n').trimEnd();
  const body = `${bodyText}\n\n${markerLine(marker)}`;
  const patch = {};
  if (state && state !== issue.state) patch.state = state;
  labels.add(projectLabel(project.project)); // 絞り込みリンク用。同一性の判定には使わない（D1）
  if (!sameSet(new Set(labels), new Set(issue.labels))) patch.labels = [...labels].sort();
  if (title !== undefined && title !== issue.title) patch.title = title;
  if (JSON.stringify(markerShape(issue.marker)) !== JSON.stringify(markerShape(marker))) patch.body = body;
  if (Object.keys(patch).length === 0) return;
  if ((await context.attempt(`patch:#${issue.number}`, () => api.updateIssue(issue.number, patch))) === FAILED) return;
  if (fresh.length === 0) return;
  const stillPending = [...remaining];
  for (const notice of fresh) {
    const posted = await context.attempt(`notice:#${issue.number}`, () => api.createComment(issue.number, noticeBody(notice, project.owners)));
    if (posted === FAILED) stillPending.push(notice);
  }
  if (stillPending.length === remaining.length + fresh.length) return;
  const cleared = buildMarker({ project: project.project, aliases: marker.aliases, hash, pending: stillPending, sb, mk });
  await context.attempt(`patch:#${issue.number}`, () => api.updateIssue(issue.number, { body: `${bodyText}\n\n${markerLine(cleared)}` }));
}

async function riskReasons(context, issue, item) {
  const { api, now, thresholds } = context;
  const events = await context.attempt(`events:#${issue.number}`, () => api.listIssueEvents(issue.number));
  const labeled = (events === FAILED ? [] : events).filter((e) => e.event === 'labeled' && e.label?.name === LABELS.accepted).map((e) => e.created_at).sort().at(-1);
  if (!labeled) return ['unknown_date']; // 付与日時を取得できなければ安全側（再オープン）
  const reasons = [];
  if (daysBetween(labeled, now) > thresholds.risk_accepted_days) reasons.push('expired');
  const issuePriority = priorityLabelOf(new Set(issue.labels));
  if (item.kev && issuePriority !== 'P0') reasons.push('kev');
  if (issuePriority && isHigherPriority(item.priority, issuePriority)) reasons.push('priority_up');
  return reasons;
}

async function processExisting(context, issue, item) {
  const { project } = context;
  const labels = new Set(issue.labels);
  const notices = [];
  let reopen = false;
  if (issue.state === 'closed') {
    if (labels.has(LABELS.fixed)) { reopen = true; labels.delete(LABELS.fixed); notices.push(['recurrence']); }
    else if (labels.has(LABELS.accepted)) {
      const reasons = await riskReasons(context, issue, item);
      if (reasons.length > 0) { reopen = true; labels.delete(LABELS.accepted); notices.push(['risk_reopen', reasons.join(',')]); }
    } else { reopen = true; notices.push(['misclose']); }
  } else if (labels.has(LABELS.fixed)) { labels.delete(LABELS.fixed); notices.push(['recurrence']); }

  const open = issue.state === 'open' || reopen;
  let wanted = { labels, state: reopen ? 'open' : undefined, notices };
  if (item.members) {
    // まとめ Issue: 前回の members のうち取り下げ済みで消えたものを知らせ、保存する members を今回の内容にする
    const keys = item.members.map((m) => m.advisory_key);
    const gone = withdrawnMembers(issue.marker.mk ?? [], keys, context);
    if (gone.length > 0) notices.push(['member_withdrawn', gone.join(',')]);
    wanted.mk = keys;
    // カーネルのまとめだけ、新しい重大な CVE が加わったことを通知する（本文の編集ではメールが届かないため）
    const before = new Set(issue.marker.mk ?? []);
    const added = item.members.filter((m) => !before.has(m.advisory_key) && ['P0', 'P1'].includes(m.priority) && Array.isArray(issue.marker.mk));
    if (isKernelGroupIssue(issue) && added.length > 0) notices.push(['member_added', added.map((m) => `${m.advisory_key}:${m.priority}`).join(',')]);
  }
  if (open) {
    for (const p of LABELS.priorities) labels.delete(p);
    labels.add(item.priority);
    const text = renderBody({ project: project.project, item, owners: project.owners, scannedAt: context.findings.scanned_at });
    wanted = { ...wanted, title: issueTitle(project.project, item), text, aliases: [...new Set([...issue.marker.aliases, ...item.aliases])] };
  }
  if (!item.members && context.isWithdrawnAliases(item.aliases) && !labels.has(LABELS.withdrawn)) { labels.add(LABELS.withdrawn); notices.push(['withdrawn']); }
  await applyChange(context, issue, { title: undefined, text: null, aliases: undefined, ...wanted });
}

// 旧来の CVE ごとのランタイム Issue を、まとめ先の番号が確定した回にだけ移行する。確定していなければ何もしない（再試行される）
async function migrateLegacy(context, issue, groupItems, groupNumbers) {
  const { matched, number } = migrationDestination(issue, groupItems, groupNumbers);
  if (!matched) return false;
  if (number === null) context.warnings.push(`まとめ先がないため移行を見送りました #${issue.number}`);
  else await applyChange(context, issue, { ...migratedTarget(issue, context), text: null, sb: number });
  return true;
}

async function processUnmatched(context, issue) {
  if ((issue.marker.mk ?? []).length > 0) {
    // member が混在 item などに移っていれば、解消ではなく移行として扱う（CVE は残っているため）
    const moved = movedMembers(issue, context.issueItems, context.numbers);
    if (moved.matched) {
      if (moved.number === null) context.warnings.push(`移行先の Issue が未作成のため、まとめ Issue #${issue.number} の移行を見送りました`);
      else await applyChange(context, issue, { ...migratedTarget(issue, context), text: null, sb: moved.number });
      return;
    }
    const target = vanishedGroupTarget(issue, { isWithdrawnAliases: context.isWithdrawnAliases, scanComplete: context.findings.scan_status === 'complete' });
    return applyChange(context, issue, { ...target, text: null });
  }
  const labels = new Set(issue.labels);
  const notices = [];
  // 取り下げは照合の完全性と無関係なので scan_status に関係なく判定し、fixed-in-repo は付けない
  if (context.isWithdrawnAliases(issue.marker.aliases)) {
    if (!labels.has(LABELS.withdrawn)) { labels.add(LABELS.withdrawn); notices.push(['withdrawn']); }
  } else if (context.findings.scan_status === 'complete' && !labels.has(LABELS.fixed) && !isKernelGroupIssue(issue)) { // カーネルは mk が空になった次の回以降も付けない
    labels.add(LABELS.fixed); // ラベルだけ付け、コメントはしない（2026-10-25 U1: 解消時のメール大量送信の防止）
  }
  await applyChange(context, issue, { labels, notices, text: null });
}

async function processDuplicate(context, issue) {
  const labels = new Set(issue.labels);
  const notices = [];
  if (!labels.has(LABELS.duplicate)) { labels.add(LABELS.duplicate); notices.push(['duplicate']); }
  await applyChange(context, issue, { labels, notices, text: null });
}
