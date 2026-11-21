import path from 'node:path';
import { mkdirSync, rmSync } from 'node:fs';
import { loadData, readJsonIfExists, writeJson } from '../publish/central-data.mjs';
import { collectAll, normalizeAll } from '../publish/stage-collect.mjs';
import { startOptional, settleOptional, applyAwsBulletins } from '../publish/stage-optional.mjs';
import { enrichAdvisories } from '../normalize/enrich.mjs';
import { ECOSYSTEMS } from '../collect/osv-db.mjs';
import { SOURCE_NAMES } from '../collect/index.mjs';
import { failResult } from '../collect/result.mjs';
import { loadSchedule, loadThresholds } from '../lib/config.mjs';
import { guardCommit as realGuardCommit } from '../publish/guard-commit.mjs';
import { validateFeed } from './validate-feed.mjs';
import { inspectTree } from './inspect-tree.mjs';
import { buildFeedHealth } from './health.mjs';
import { FEED_FORMAT_VERSION, NEVER_FETCHED_AT } from './definition.mjs';

const COMMIT_MESSAGE = '[data] 公開フィードを更新';
const FEED_BRANCH = 'feed';

const kevFileOf = (result, previous, now) => (result.ok
  ? { fetched_at: now, ok: true, catalog_version: result.meta?.catalogVersion ?? null, records: result.records }
  : { fetched_at: previous?.fetched_at ?? NEVER_FETCHED_AT, ok: false, catalog_version: previous?.catalog_version ?? null, records: previous?.records ?? [] });

const epssFileOf = (result, previous, now, threshold) => (result.ok
  ? {
    fetched_at: now, ok: true, model_version: result.meta?.model_version ?? null, score_date: result.meta?.score_date ?? null, threshold,
    records: result.records.map(({ cve, epss, percentile }) => ({ cve, epss, percentile })).sort((a, b) => (a.cve < b.cve ? -1 : 1)),
  }
  : {
    fetched_at: previous?.fetched_at ?? NEVER_FETCHED_AT, ok: false, model_version: previous?.model_version ?? null, score_date: previous?.score_date ?? null,
    threshold: previous?.threshold ?? threshold, records: previous?.records ?? [],
  });

// 公開側の収集。照合・Issue・digest は持たない。依存はすべて deps で注入する（テストではネットワークと Git をフェイクにする）
export async function runCollect({ rootDir, feedRoot, now, deps, env }) {
  const dataDir = path.join(feedRoot, 'data');
  const workDir = path.join(rootDir, '.work');
  const outDataDir = path.join(workDir, 'feed-out', 'data');
  const outcome = { status: 'success', reasons: [], committed: false, pushed: false };
  const fail = (reason) => { outcome.status = 'failed'; outcome.reasons.push(reason); return outcome; };
  const thresholds = loadThresholds();
  const startedAt = now;

  rmSync(path.join(workDir, 'feed-out'), { recursive: true, force: true });
  mkdirSync(outDataDir, { recursive: true });
  const data = loadData(dataDir);
  const previousKev = readJsonIfExists(path.join(dataDir, 'kev.json'));
  const previousEpss = readJsonIfExists(path.join(dataDir, 'epss-high.json'));

  const optionalTasks = startOptional({ collectors: deps.optionalCollectors, http: deps.http, now, thresholds });
  const { results, packagistPlan } = await collectAll({ collectors: deps.collectors, http: deps.http, env, now, data });
  const osvFetchedThisRun = Object.fromEntries(ECOSYSTEMS.map((e) => [e, false]));
  const norm = await normalizeAll({ results, packagistPlan, data, osvDbDir: path.join(workDir, 'osv-db'), osvFetchedThisRun, now });

  const kev = results.kev ?? failResult({ kind: 'skipped', message: 'KEV が実行されませんでした' });
  const epss = await Promise.resolve()
    .then(() => deps.collectors.epss({ http: deps.http, env, now, minPercentile: thresholds.epss_percentile_p1 }))
    .catch((error) => failResult({ kind: 'exception', message: error.message }));
  const kevFile = kevFileOf(kev, previousKev, now);
  const epssFile = epssFileOf(epss, previousEpss, now, thresholds.epss_percentile_p1);

  // 取得に失敗した値は null にして、アドバイザリの前回の値を残す
  const enriched = enrichAdvisories({
    advisories: [...norm.advisories.values()], kevRecords: kev.ok ? kevFile.records : null,
    epssRecords: epss.ok ? epssFile.records.map((r) => ({ ...r, score_date: epssFile.score_date })) : null, jpItems: norm.jpAlerts.items, now,
    clearMissingEpss: true,
  });
  for (const [key, value] of enriched) norm.advisories.set(key, value);

  // 締め切り: 照合がないので、ここまでが終わった時点で未完了なら見送る
  const optionalResults = settleOptional(optionalTasks);
  let awsBulletins = data.awsBulletins;
  if (optionalResults['aws-bulletins']) {
    const applied = applyAwsBulletins({ result: optionalResults['aws-bulletins'], previous: data.awsBulletins, outDataDir, now, overrides: deps.optionalOverrides });
    optionalResults['aws-bulletins'] = applied.result;
    awsBulletins = applied.data;
  }
  const sourceResults = { ...results, epss };
  for (const name of SOURCE_NAMES) if (sourceResults[name] && !sourceResults[name].ok) { outcome.status = 'partial'; outcome.reasons.push(`情報源 ${name} の取得に失敗`); }

  for (const advisory of norm.advisories.values()) writeJson(outDataDir, `advisories/${advisory.key}.json`, advisory);
  writeJson(outDataDir, 'runtimes/php.json', norm.runtimes.php);
  writeJson(outDataDir, 'runtimes/nodejs.json', norm.runtimes.nodejs);
  writeJson(outDataDir, 'runtimes/python.json', norm.runtimes.python);
  writeJson(outDataDir, 'jp-alerts.json', norm.jpAlerts);
  writeJson(outDataDir, 'packagist-advisories.json', norm.packagist);
  writeJson(outDataDir, 'os/amazon-linux-kernel.json', norm.amazonLinuxKernel);
  if (awsBulletins) writeJson(outDataDir, 'aws-bulletins.json', awsBulletins);
  writeJson(outDataDir, 'kev.json', kevFile);
  writeJson(outDataDir, 'epss-high.json', epssFile);
  writeJson(outDataDir, 'feed-format.json', { format_version: FEED_FORMAT_VERSION });
  writeJson(outDataDir, 'health.json', buildFeedHealth({
    previous: data.health, now, startedAt, status: outcome.status, schedule: loadSchedule(), sourceResults, optionalResults, packagistUpdatedSince: norm.packagist.updated_since,
  }));

  // 検証に外れたものは push しない
  const violations = validateFeed(outDataDir);
  if (violations.length > 0) return fail(`フィードの検証に失敗: ${violations[0].file}: ${violations[0].message}`);
  const secrets = inspectTree({ dir: outDataDir, needles: [] });
  if (secrets.length > 0) return fail(`秘密情報の形に一致するものがあります: ${secrets[0].file}（${secrets[0].patternName}）`);

  try {
    const committed = await (deps.guardCommit ?? realGuardCommit)({ repoDir: feedRoot, outDataDir, message: COMMIT_MESSAGE, branch: FEED_BRANCH });
    outcome.committed = committed.committed;
    outcome.pushed = committed.pushed;
  } catch (error) {
    fail(`コミットまたは push に失敗: ${error.message}`);
  }
  return outcome;
}
