import path from 'node:path';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdirSync, rmSync } from 'node:fs';
import { loadData, readJsonIfExists, writeJson, writeText, advisoryMapOf } from '../publish/central-data.mjs';
import { refreshOsvAdvisories } from '../publish/stage-collect.mjs';
import { resolveAndDetect, absorbAdvisories, finalizeProjects } from '../publish/stage-match.mjs';
import { reconcileIssues } from '../publish/issues-reconcile.mjs';
import { renderDigest } from '../publish/digest.mjs';
import { buildHealth, collectProblems, reconcileHealthIssue, staleSources, optionalSourceProblems } from '../publish/health.mjs';
import { validateOutDir } from '../publish/validate-out.mjs';
import { copyDirectory } from '../publish/guard-commit.mjs';
import { mergeAdvisories } from '../normalize/advisories.mjs';
import { enrichAdvisories } from '../normalize/enrich.mjs';
import { buildAdvisoryIndex } from '../match/assemble.mjs';
import { combineAdvisoryViews, keepMatchedOnly } from '../match/advisory-view.mjs';
import { feedSignals } from '../match/priority-inputs.mjs';
import { ECOSYSTEMS, readMeta } from '../collect/osv-db.mjs';
import { COMMON_DATA_FILES } from '../feed/definition.mjs';
import { needlesFromPrivateConfig } from '../feed/inspect-tree.mjs';
import { loadCentral, loadSchedule, loadThresholds } from '../lib/config.mjs';
import { fetchFeed } from './feed-source.mjs';
import { judgeSlots } from './slot-judgement.mjs';
import { isFirstMatchRun, nextFeedState, newJpItems, mapFeedSources, mapFeedOptionalSources } from './private-state.mjs';

const run = promisify(execFile);
const COMMIT_MESSAGE = '[data] 照合の結果を更新';
const NO_FEED_DATA = { runtimes: {}, packagist: null, amazonLinuxKernel: null };

const headCommit = (root) => run('git', ['rev-parse', 'HEAD'], { cwd: root }).then((r) => r.stdout.trim(), () => null);

// 非公開側の照合。runCentral と同じ順序・同じ write-set で、収集の結果の代わりに検証済みのフィードを使う（指示書 T4）。
// thresholds・schedule・central は privateRoot の値を明示的に渡す（コードの展開先の config/ は公開側の値）
export async function runMatch({ privateRoot, projectsConfig, feedUrl, now, deps, env }) {
  const dataDir = path.join(privateRoot, 'data');
  const workDir = path.join(privateRoot, '.work');
  const outDataDir = path.join(workDir, 'out', 'data');
  const osvDbDir = path.join(workDir, 'osv-db');
  const startedAt = now;
  const thresholds = loadThresholds(privateRoot);
  const schedule = loadSchedule(privateRoot);
  const central = loadCentral(privateRoot);
  const outcome = { status: 'success', reasons: [], committed: false, heartbeat: null, healthIssue: null, feedMode: null };
  const fail = (reason) => { outcome.status = 'failed'; outcome.reasons.push(reason); };
  const downgrade = (reason) => { if (outcome.status === 'success') outcome.status = 'partial'; outcome.reasons.push(reason); };

  // 1: 前回のデータの検証
  rmSync(path.join(workDir, 'out'), { recursive: true, force: true });
  mkdirSync(outDataDir, { recursive: true });
  copyDirectory(dataDir, outDataDir);
  const previousViolations = validateOutDir(outDataDir);
  if (previousViolations.length > 0) {
    fail(`前回までのデータがスキーマに合いません: ${previousViolations[0].file}: ${previousViolations[0].message}`);
    try { outcome.healthIssue = await reconcileHealthIssue({ api: deps.api, problems: [outcome.reasons[0]] }); } catch { /* 記録先がなければ終了状態だけ返す */ }
    return outcome;
  }
  const data = loadData(dataDir);
  const previousState = readJsonIfExists(path.join(dataDir, 'feed-state.json'));
  const firstRun = isFirstMatchRun(dataDir);
  const cutoverCommit = firstRun ? await headCommit(privateRoot) : null;

  // 2: フィードの取得・検証と、OSV の DB（取得に失敗した回は前回の DB で続ける）
  const feed = await (deps.fetchFeed ?? fetchFeed)({
    url: feedUrl, lastValidatedSha: previousState?.last_validated?.sha ?? null, needles: needlesFromPrivateConfig({ projectsConfig, central }), workDir: path.join(workDir, 'feed'),
  });
  outcome.feedMode = feed.mode;
  const degraded = feed.mode === 'degraded';
  const feedData = degraded ? null : loadData(feed.dataDir);
  const kev = degraded ? null : readJsonIfExists(path.join(feed.dataDir, 'kev.json'));
  const epssHigh = degraded ? null : readJsonIfExists(path.join(feed.dataDir, 'epss-high.json'));
  const feedHealth = feedData?.health ?? null;
  mkdirSync(osvDbDir, { recursive: true });
  const fetched = await deps.fetchOsvDb({ ecosystems: ECOSYSTEMS, dest: osvDbDir, now });
  const osvFetchedThisRun = Object.fromEntries(ECOSYSTEMS.map((e) => [e, fetched.outcomes[e]?.ok === true]));
  const osvFailed = ECOSYSTEMS.filter((e) => !osvFetchedThisRun[e]);
  for (const e of osvFailed) downgrade(`OSV の DB（${e}）を取得できませんでした`);
  const osvMeta = await readMeta(osvDbDir);
  if (feed.mode !== 'latest') downgrade(`フィードが最新ではありません（${feed.mode}）`);

  // 3: 非公開側のアドバイザリ。最初の回は公開由来を含む記録を捨て、DB から読み直す
  const privateBase = firstRun ? keepMatchedOnly(data.advisories) : data.advisories;
  const advisories = advisoryMapOf(privateBase);
  const refreshed = await refreshOsvAdvisories({ advisories: privateBase, osvDbDir, osvFetchedThisRun, now });
  for (const [key, value] of mergeAdvisories({ previous: privateBase, records: refreshed, now })) advisories.set(key, value);

  // 4: 照合 → 非公開側の記録の更新 → KEV の付与 → 公開側との合成
  const runs = await resolveAndDetect({
    projectsConfig, data, matchData: degraded ? NO_FEED_DATA : { runtimes: feedData.runtimes, packagist: feedData.packagist, amazonLinuxKernel: feedData.amazonLinuxKernel },
    deps, osvDbDir, env, now, workRoot: path.join(workDir, 'repos'), exportRoot: path.join(dataDir, 'inventory-export'), feedAvailable: !degraded, thresholds,
  });
  for (const [key, value] of absorbAdvisories({ runs, advisories: [...advisories.values()], now })) advisories.set(key, value);
  const enriched = enrichAdvisories({
    advisories: [...advisories.values()], kevRecords: kev?.ok ? kev.records : null, epssRecords: null, jpItems: degraded ? [] : feedData.jpAlerts?.items ?? [], now,
  });
  for (const [key, value] of enriched) advisories.set(key, value);
  const index = buildAdvisoryIndex(combineAdvisoryViews({ publicAdvisories: feedData?.advisories ?? [], privateAdvisories: [...advisories.values()] }));

  // 5: 予定枠の判定と、前回との統合
  const judged = judgeSlots({ feedMode: feed.mode, feedHealth, kev, epssHigh, now, thresholds, schedule });
  const signals = feedSignals({ kev, epssHigh, feedMode: feed.mode, targetSlot: judged.targetSlot, feedHealth, now, thresholds, schedule });
  const extraErrors = Object.fromEntries(projectsConfig.projects.map((p) => [p.project, judged.extraErrors]));
  const { findings, inventories } = finalizeProjects({
    runs, data, index, sourceResults: judged.sourceResults, extraErrors, osvMeta, osvFetchedThisRun, packagistFullSyncAt: feedData?.packagist?.full_sync_at ?? null,
    provenanceBase: { scanner_version: deps.scannerVersion, script_version: env.SI_CODE_SHA ?? deps.scriptVersion ?? null, feed_version: feed.sha },
    now, signals, ctx: { epssState: signals.epssState, feedMode: feed.mode }, thresholds,
  });
  const badSources = Object.entries(judged.verdicts).filter(([, v]) => !v.ok).map(([name]) => name);
  if (badSources.length > 0) downgrade(`情報源の取得を確認できません: ${badSources.join(', ')}`);
  for (const [project, f] of findings) if (f.scan_status !== 'complete') downgrade(`${project}: scan_status=${f.scan_status}`);

  // 6: 一時出力。共通の生成物と公開由来の記録は消し、照合由来の記録だけを書く（合成した記録は書かない）
  const write = (issueSnapshot) => {
    for (const entry of COMMON_DATA_FILES) rmSync(path.join(outDataDir, entry), { recursive: true, force: true });
    for (const advisory of advisories.values()) writeJson(outDataDir, `advisories/${advisory.key}.json`, advisory);
    for (const [project, inventory] of inventories) writeJson(outDataDir, `inventory/${project}.json`, inventory);
    for (const [project, f] of findings) writeJson(outDataDir, `findings/${project}.json`, f);
    if (issueSnapshot) writeJson(outDataDir, 'issues.json', issueSnapshot);
  };
  write(null);

  const projectStates = Object.fromEntries([...findings].map(([p, f]) => [p, { scan_status: f.scan_status, inventory_status: f.inventory_status }]));
  const buildHealthFile = (status) => {
    const { optional_sources: _unused, ...base } = buildHealth({ previous: data.health, now, startedAt, status, sourceResults: {}, projectStates, osvMeta, packagistUpdatedSince: feedHealth?.packagist_updated_since });
    const optional = mapFeedOptionalSources({ previous: data.health, feedHealth });
    return { ...base, sources: mapFeedSources({ previous: data.health, feedHealth }), ...(Object.keys(optional).length > 0 ? { optional_sources: optional } : {}) };
  };
  const failedSources = Object.fromEntries(badSources.map((name) => [name, { ok: false, error: { message: judged.verdicts[name].reason } }]));
  const problemsOf = (extra = []) => {
    const health = buildHealthFile(outcome.status);
    return collectProblems({
      findingsByProject: findings, sourceResults: failedSources, stale: staleSources(health, now, thresholds), reconcileErrors: outcome.reconcileErrors ?? [],
      alasRetry: degraded ? [] : feedData.amazonLinuxKernel?.retry ?? [], pythonPending: degraded ? [] : feedData.runtimes.python?.pending ?? [], now, thresholds, warnings: outcome.warnings ?? [],
      extra: [...feed.problems, ...osvFailed.map((e) => `OSV の DB（${e}）を更新できませんでした`), ...extra], optionalProblems: optionalSourceProblems(health, now, thresholds),
    });
  };
  const updateHealthIssue = async (extra) => {
    try { outcome.healthIssue = await reconcileHealthIssue({ api: deps.api, problems: problemsOf(extra) }); } catch (error) { outcome.reasons.push(`health Issue の更新に失敗: ${error.message}`); }
  };

  // 7: 1回目の検証。失敗した回は Issue を操作しない
  const firstViolations = validateOutDir(outDataDir);
  if (firstViolations.length > 0) {
    fail(`スキーマ検証（1回目）に失敗: ${firstViolations[0].file}: ${firstViolations[0].message}`);
    await updateHealthIssue([outcome.reasons.at(-1)]);
    return outcome;
  }

  // 8: reconcile。取り下げは合成した索引で判定し、公開側の状態を確かめられない回は確定しない
  const rec = await reconcileIssues({
    api: deps.api, projects: projectsConfig.projects, findingsByProject: findings, now, previousSnapshot: data.issues, thresholds,
    isWithdrawnAliases: (aliases) => !degraded && aliases.some((id) => index.get(id)?.status === 'withdrawn'),
  });
  outcome.reconcileErrors = rec.errors;
  outcome.warnings = rec.warnings;
  if (rec.errors.length > 0) downgrade(`Issue 操作の失敗が ${rec.errors.length} 件`);
  for (const [project, numbers] of rec.issueNumbers) {
    for (const item of findings.get(project).items) item.issue_number = numbers.get(item.advisory_key) ?? item.issue_number;
  }

  // 9-10: health と digest
  write(rec.snapshot);
  const health = buildHealthFile(outcome.status);
  const digest = renderDigest({
    projects: projectsConfig.projects, findingsByProject: findings, snapshot: rec.snapshot, digestInfo: rec.digestInfo, health, schedule, now, centralRepo: deps.centralRepo,
    kevRecords: kev?.records ?? [], jpItems: degraded ? [] : newJpItems(feedData.jpAlerts, previousState), thresholds, awsBulletins: degraded ? null : feedData.awsBulletins,
    priorityNotes: true, feedUnavailable: degraded, sourceVerdicts: judged.verdicts,
  });
  writeText(outDataDir, 'digest/latest.md', digest);
  writeJson(outDataDir, 'health.json', health);
  writeJson(outDataDir, 'feed-state.json', nextFeedState({ previous: previousState, feed, feedHealth, jpAlerts: feedData?.jpAlerts, now, firstRun, cutoverCommit }));

  // 11: 最終検証。通過したものだけがコミットされる
  const finalViolations = validateOutDir(outDataDir);
  if (finalViolations.length > 0) {
    fail(`スキーマ検証（最終）に失敗: ${finalViolations[0].file}: ${finalViolations[0].message}`);
    await updateHealthIssue([outcome.reasons.at(-1)]);
    return outcome;
  }

  // 12-14: コミット・health Issue・完了通知（success のときだけ）
  try {
    outcome.committed = (await deps.guardCommit({ repoDir: privateRoot, outDataDir, message: COMMIT_MESSAGE })).committed;
  } catch (error) {
    fail(`コミットまたは push に失敗: ${error.message}`);
  }
  await updateHealthIssue(outcome.status === 'failed' ? [outcome.reasons.at(-1)] : []);
  if (outcome.status === 'success') {
    outcome.heartbeat = await deps.sendHeartbeat({ url: env.HEALTHCHECK_PING_URL });
    if (!outcome.heartbeat.ok) outcome.reasons.push('完了通知に失敗しました（警告）');
  }
  return outcome;
}
