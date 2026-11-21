import { loadThresholds } from '../lib/config.mjs';
import { hoursBetween, daysBetween } from '../lib/time.mjs';
import { sha256Hex } from '../lib/hash.mjs';
import { sanitizeInline } from '../lib/sanitize-md.mjs';
import { LABELS } from './issue-body.mjs';
import { SOURCE_NAMES } from '../collect/index.mjs';

export const HEALTH_TITLE = '[health] 収集・照合の異常';
const HEALTH_MARKER = /<!-- si-health:([0-9a-f]{64}) -->/;

// sourceResults: その回に試行した情報源の結果。試行しなかったものは前回の値を保つ
export function buildHealth({ previous, now, startedAt, status, sourceResults, optionalResults = {}, projectStates, osvMeta, packagistUpdatedSince }) {
  const sources = {};
  for (const name of SOURCE_NAMES) {
    const before = previous?.sources?.[name] ?? { last_attempt_at: null, last_success_at: null, last_error: null };
    const result = sourceResults[name];
    if (!result) { sources[name] = before; continue; }
    sources[name] = result.ok
      ? { last_attempt_at: now, last_success_at: now, last_error: null }
      : { last_attempt_at: now, last_success_at: before.last_success_at, last_error: { ...result.error, at: now } };
  }
  // 任意の情報源は sources と分ける（staleSources と /security-check の対象外）。試行しなかった回は前回の値を残す
  const optionalSources = { ...previous?.optional_sources };
  for (const [name, result] of Object.entries(optionalResults)) {
    const before = previous?.optional_sources?.[name];
    optionalSources[name] = {
      first_attempt_at: before?.first_attempt_at ?? now, last_attempt_at: now,
      last_success_at: result.ok ? now : before?.last_success_at ?? null,
      last_error: result.ok ? null : { ...result.error, at: now },
    };
  }
  return {
    last_run: { started_at: startedAt, finished_at: now, status },
    // 成功した回だけ更新する（スキルの鮮度判定と 36 時間判定の基準）
    last_success_at: status === 'success' ? now : previous?.last_success_at ?? null,
    sources, projects: projectStates, osv_db: osvMeta, packagist_updated_since: packagistUpdatedSince ?? previous?.packagist_updated_since ?? null,
    ...(Object.keys(optionalSources).length > 0 ? { optional_sources: optionalSources } : {}),
  };
}

export function staleSources(health, now, thresholds = loadThresholds()) {
  return Object.entries(health.sources)
    .filter(([, s]) => !s.last_success_at || hoursBetween(s.last_success_at, now) > thresholds.stale_source_hours)
    .map(([name]) => name).sort();
}

// 最終成功（なければ初回の試行）から alert_days を過ぎた任意の情報源
export function overdueOptionalSources(health, now, thresholds = loadThresholds()) {
  return Object.entries(health.optional_sources ?? {})
    .map(([name, s]) => ({ name, base: s.last_success_at ?? s.first_attempt_at, hasSuccess: Boolean(s.last_success_at) }))
    .filter((s) => s.base && daysBetween(s.base, now) > thresholds.optional_source_alert_days);
}

// 文言に回ごとに変わる値（last_attempt_at・エラー本文）を入れない（health Issue の本文のハッシュを安定させる）
export function optionalSourceProblems(health, now, thresholds = loadThresholds()) {
  const days = thresholds.optional_source_alert_days;
  return overdueOptionalSources(health, now, thresholds).map((s) => (s.hasSuccess
    ? `情報源 ${s.name} は ${days}日以上取得できていません（最終成功: ${s.base}）`
    : `情報源 ${s.name} は ${days}日以上取得できていません（成功の記録なし、初回の試行: ${s.base}）`));
}

const line = (text) => `- ${sanitizeInline(text, 300)}`;

// 異常の一覧（health Issue の本文になる）。実行のたびに変わる値は入れない
const MAX_LISTED_RETRY = 5;

// ALAS の詳細を取れない CVE が続いているものを、人が気づけるように出す
function staleRetryProblem(retry, now, thresholds) {
  const old = retry.filter((r) => hoursBetween(`${r.since}T00:00:00Z`, now) > thresholds.stale_source_hours);
  if (old.length === 0) return [];
  const listed = old.slice(0, MAX_LISTED_RETRY).map((r) => `${r.cve}（${r.since} から）`).join('、');
  return [`ALAS の詳細を取得できない CVE があります: ${listed}${old.length > MAX_LISTED_RETRY ? ` ほか${old.length - MAX_LISTED_RETRY}件` : ''}`];
}

// 判定が保留のままの PSF の記録（pending）を、人が気づけるように出す
function pythonPendingProblem(pending, now, thresholds) {
  const old = pending.filter((p) => hoursBetween(p.since, now) > thresholds.stale_source_hours);
  if (old.length === 0) return [];
  const listed = old.slice(0, MAX_LISTED_RETRY).map((p) => `${p.id}（${p.reason}、${p.since} から）`).join('、');
  const hint = old.some((p) => p.reason === 'no_versions') ? '。影響する正式版がないことを確かめたら config/python-no-release-impact.json に足してください' : '';
  return [`CPython の判定が保留のままの PSF アドバイザリがあります: ${listed}${old.length > MAX_LISTED_RETRY ? ` ほか${old.length - MAX_LISTED_RETRY}件` : ''}${hint}`];
}

export function collectProblems({ findingsByProject, sourceResults, stale, reconcileErrors = [], warnings = [], extra = [], alasRetry = [], pythonPending = [], optionalProblems = [], now = null, thresholds = loadThresholds() }) {
  const problems = [];
  for (const [name, result] of Object.entries(sourceResults)) if (!result.ok) problems.push(`情報源 ${name} の取得に失敗: ${result.error?.message ?? ''}`);
  for (const name of stale) problems.push(`情報源 ${name} は最終成功から36時間を過ぎています（情報が古い）`);
  for (const [project, findings] of findingsByProject) {
    for (const e of findings.scan_errors.filter((x) => x.kind !== 'source' || false)) problems.push(`[${project}] ${e.kind}: ${e.target}: ${e.message}`);
    if (findings.inventory_status === 'unavailable') problems.push(`[${project}] 依存関係は照合不能（インベントリを取得できませんでした）`);
  }
  if (now) problems.push(...staleRetryProblem(alasRetry, now, thresholds), ...pythonPendingProblem(pythonPending, now, thresholds));
  problems.push(...reconcileErrors.map((e) => `Issue 操作の失敗: ${e.target}: ${e.message}`), ...warnings, ...optionalProblems, ...extra);
  return [...new Set(problems)].sort();
}

export function renderHealthBody(problems) {
  const text = ['以下の異常を検出しました。復旧すると、この Issue は自動でクローズされます。', '', ...problems.map(line)].join('\n');
  return `${text}\n\n<!-- si-health:${sha256Hex(text)} -->`;
}

// health Issue は常に最大1件。異常がなくなったら「復旧」とコメントして自動でクローズする（例外として許可）
export async function reconcileHealthIssue({ api, problems }) {
  const issues = (await api.listIssues({ label: LABELS.health })).filter((i) => i.title === HEALTH_TITLE && i.state === 'open').sort((a, b) => a.number - b.number);
  const current = issues[0];
  if (problems.length === 0) {
    if (!current) return { action: 'none' };
    await api.createComment(current.number, '復旧しました。異常は検出されなくなったため、この Issue をクローズします。');
    await api.closeHealthIssue(current.number);
    return { action: 'closed', number: current.number };
  }
  const body = renderHealthBody(problems);
  if (!current) {
    const created = await api.createIssue({ title: HEALTH_TITLE, body, labels: [LABELS.health] });
    return { action: 'created', number: created.number };
  }
  if (HEALTH_MARKER.exec(current.body)?.[1] === HEALTH_MARKER.exec(body)[1]) return { action: 'unchanged', number: current.number };
  await api.updateIssue(current.number, { body });
  return { action: 'updated', number: current.number };
}
