import path from 'node:path';
import { mkdirSync, rmSync } from 'node:fs';
import { loadData, writeJson, writeText } from './central-data.mjs';
import { collectAll, normalizeAll } from './stage-collect.mjs';
import { matchAll } from './stage-match.mjs';
import { startOptional, settleOptional, applyAwsBulletins } from './stage-optional.mjs';
import { reconcileIssues } from './issues-reconcile.mjs';
import { renderDigest } from './digest.mjs';
import { buildHealth, collectProblems, reconcileHealthIssue, staleSources, optionalSourceProblems } from './health.mjs';
import { validateOutDir } from './validate-out.mjs';
import { copyDirectory } from './guard-commit.mjs';
import { ECOSYSTEMS, readMeta } from '../collect/osv-db.mjs';
import { loadSchedule, loadThresholds } from '../lib/config.mjs';

const COMMIT_MESSAGE = '[data] 収集・照合の結果を更新';

// 指示書 §9.1 の処理順。依存はすべて deps で注入する（テストでは GitHub・ファイルシステム・スキャナをフェイクにする）
export async function runCentral({ rootDir, projectsConfig, now, deps, env }) {
  const dataDir = path.join(rootDir, 'data');
  const workDir = path.join(rootDir, '.work');
  const outDataDir = path.join(workDir, 'out', 'data');
  const osvDbDir = path.join(workDir, 'osv-db');
  const startedAt = now;
  const outcome = { status: 'success', reasons: [], committed: false, heartbeat: null, healthIssue: null };
  const fail = (reason) => { outcome.status = 'failed'; outcome.reasons.push(reason); };
  const downgrade = (reason) => { if (outcome.status === 'success') outcome.status = 'partial'; outcome.reasons.push(reason); };
  const thresholds = loadThresholds();

  rmSync(path.join(workDir, 'out'), { recursive: true, force: true });
  mkdirSync(outDataDir, { recursive: true });
  copyDirectory(dataDir, outDataDir);

  // 前回のデータが壊れていたら、処理に入らず health Issue だけ更新して終わる（壊れたデータの上に結果を積まない）
  const previousViolations = validateOutDir(outDataDir);
  if (previousViolations.length > 0) {
    fail(`前回までのデータがスキーマに合いません: ${previousViolations[0].file}: ${previousViolations[0].message}`);
    try { outcome.healthIssue = await reconcileHealthIssue({ api: deps.api, problems: [outcome.reasons[0]] }); } catch { /* 記録先がなければ終了状態だけ返す */ }
    return outcome;
  }
  const data = loadData(dataDir);

  // 1: OSV の DB（失敗した回は partial）
  mkdirSync(osvDbDir, { recursive: true });
  const fetched = await deps.fetchOsvDb({ ecosystems: ECOSYSTEMS, dest: osvDbDir, now });
  const osvFetchedThisRun = Object.fromEntries(ECOSYSTEMS.map((e) => [e, fetched.outcomes[e]?.ok === true]));
  for (const e of ECOSYSTEMS.filter((x) => !osvFetchedThisRun[x])) downgrade(`OSV の DB（${e}）を取得できませんでした`);
  const osvMeta = await readMeta(osvDbDir);

  // 任意の情報源（S7）は必須の収集と並行して開始し、待たない。失敗しても status・完了通知・照合に影響させない
  const optionalTasks = startOptional({ collectors: deps.optionalCollectors, http: deps.http, now, thresholds });

  // 2-3: 収集と正規化
  const { results, packagistPlan } = await collectAll({ collectors: deps.collectors, http: deps.http, env, now, data });
  const norm = await normalizeAll({ results, packagistPlan, data, osvDbDir, osvFetchedThisRun, now });

  // 4-5: インベントリ取得・照合・統合
  const matched = await matchAll({
    projectsConfig, data, norm, results, deps, osvDbDir, osvMeta, osvFetchedThisRun, env, now,
    workRoot: path.join(workDir, 'repos'), exportRoot: path.join(dataDir, 'inventory-export'),
    provenanceBase: { scanner_version: deps.scannerVersion, script_version: deps.scriptVersion },
  });
  const { findings, inventories, sourceResults } = matched;
  for (const [name, result] of Object.entries(sourceResults)) if (!result.ok) downgrade(`情報源 ${name} の取得に失敗`);
  for (const [project, f] of findings) if (f.scan_status !== 'complete') downgrade(`${project}: scan_status=${f.scan_status}`);

  // 締め切り: 照合が終わった時点で未完了なら中断して見送る
  const optionalSettled = settleOptional(optionalTasks);
  const optionalResults = { ...optionalSettled };
  let awsBulletins = data.awsBulletins;
  if (optionalSettled['aws-bulletins']) {
    const applied = applyAwsBulletins({ result: optionalSettled['aws-bulletins'], previous: data.awsBulletins, outDataDir, now, overrides: deps.optionalOverrides });
    optionalResults['aws-bulletins'] = applied.result;
    awsBulletins = applied.data;
  }

  const write = (issueSnapshot) => {
    for (const advisory of norm.advisories.values()) writeJson(outDataDir, `advisories/${advisory.key}.json`, advisory);
    writeJson(outDataDir, 'runtimes/php.json', norm.runtimes.php);
    writeJson(outDataDir, 'runtimes/nodejs.json', norm.runtimes.nodejs);
    writeJson(outDataDir, 'runtimes/python.json', norm.runtimes.python);
    writeJson(outDataDir, 'jp-alerts.json', norm.jpAlerts);
    writeJson(outDataDir, 'packagist-advisories.json', norm.packagist);
    writeJson(outDataDir, 'os/amazon-linux-kernel.json', norm.amazonLinuxKernel);
    for (const [project, inventory] of inventories) writeJson(outDataDir, `inventory/${project}.json`, inventory);
    for (const [project, f] of findings) writeJson(outDataDir, `findings/${project}.json`, f);
    if (issueSnapshot) writeJson(outDataDir, 'issues.json', issueSnapshot);
  };
  write(null);

  const projectStates = Object.fromEntries([...findings].map(([p, f]) => [p, { scan_status: f.scan_status, inventory_status: f.inventory_status }]));
  const buildHealthFile = (status) => buildHealth({ previous: data.health, now, startedAt, status, sourceResults, optionalResults, projectStates, osvMeta, packagistUpdatedSince: norm.packagist.updated_since });
  const problemsOf = (extra = []) => collectProblems({
    findingsByProject: findings, sourceResults, stale: staleSources(buildHealthFile(outcome.status), now, thresholds), reconcileErrors: outcome.reconcileErrors ?? [], alasRetry: norm.amazonLinuxKernel.retry, pythonPending: norm.runtimes.python.pending, now, thresholds, warnings: outcome.warnings ?? [], extra,
    optionalProblems: optionalSourceProblems(buildHealthFile(outcome.status), now, thresholds),
  });
  const updateHealthIssue = async (extra) => {
    try { outcome.healthIssue = await reconcileHealthIssue({ api: deps.api, problems: problemsOf(extra) }); } catch (error) { outcome.reasons.push(`health Issue の更新に失敗: ${error.message}`); }
  };

  // 6: スキーマ検証（1回目）。失敗した回はコミットも脆弱性 Issue の操作もしない
  const firstViolations = validateOutDir(outDataDir);
  if (firstViolations.length > 0) {
    fail(`スキーマ検証（1回目）に失敗: ${firstViolations[0].file}: ${firstViolations[0].message}`);
    await updateHealthIssue([outcome.reasons.at(-1)]);
    return outcome;
  }

  // 7: reconcile（Issue の操作。冪等なので 9 が失敗しても次回に重複しない）
  const projectCfgs = projectsConfig.projects;
  const rec = await reconcileIssues({
    api: deps.api, projects: projectCfgs, findingsByProject: findings, now, previousSnapshot: data.issues,
    isWithdrawnAliases: (aliases) => aliases.some((id) => matched.index.get(id)?.status === 'withdrawn'),
  });
  outcome.reconcileErrors = rec.errors;
  outcome.warnings = rec.warnings;
  if (rec.errors.length > 0) downgrade(`Issue 操作の失敗が ${rec.errors.length} 件`);
  for (const [project, numbers] of rec.issueNumbers) {
    for (const item of findings.get(project).items) item.issue_number = numbers.get(item.advisory_key) ?? item.issue_number;
  }

  // 8: digest と health
  write(rec.snapshot);
  const digest = renderDigest({
    projects: projectCfgs, findingsByProject: findings, snapshot: rec.snapshot, digestInfo: rec.digestInfo,
    health: buildHealthFile(outcome.status), schedule: loadSchedule(), now, centralRepo: deps.centralRepo,
    kevRecords: sourceResults.kev?.ok ? sourceResults.kev.records : [], jpItems: norm.jpAlerts.items.filter((i) => norm.jpNew.some((n) => n.source === i.source && n.id === i.id)), thresholds, awsBulletins,
  });
  writeText(outDataDir, 'digest/latest.md', digest);
  writeJson(outDataDir, 'health.json', buildHealthFile(outcome.status));

  // 8b: 最終検証。通過したものだけがコミットされる
  const finalViolations = validateOutDir(outDataDir);
  if (finalViolations.length > 0) {
    fail(`スキーマ検証（最終）に失敗: ${finalViolations[0].file}: ${finalViolations[0].message}`);
    await updateHealthIssue([outcome.reasons.at(-1)]);
    return outcome;
  }

  // 9: guard-commit
  try {
    const committed = await deps.guardCommit({ repoDir: rootDir, outDataDir, message: COMMIT_MESSAGE });
    outcome.committed = committed.committed;
  } catch (error) {
    fail(`コミットまたは push に失敗: ${error.message}`);
  }
  await updateHealthIssue(outcome.status === 'failed' ? [outcome.reasons.at(-1)] : []);

  // 10: 完了通知は success のときだけ
  if (outcome.status === 'success') {
    outcome.heartbeat = await deps.sendHeartbeat({ url: env.HEALTHCHECK_PING_URL });
    if (!outcome.heartbeat.ok) outcome.reasons.push('完了通知に失敗しました（警告）');
  }
  return outcome;
}
