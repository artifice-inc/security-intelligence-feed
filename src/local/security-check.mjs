import { readFileSync, existsSync, statSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import path from 'node:path';
import YAML from 'yaml';
import { buildInventory } from '../inventory/build-inventory.mjs';
import { detectProject } from '../match/match-project.mjs';
import { assembleItems, buildAdvisoryIndex } from '../match/assemble.mjs';
import { combineAdvisoryViews } from '../match/advisory-view.mjs';
import { requiredOsvEcosystems } from '../match/scan-status.mjs';
import { dbFreshness, fetchOsvDb, readMeta, dbFileExists, ECOSYSTEMS } from '../collect/osv-db.mjs';
import { isCentralStale } from '../lib/schedule.mjs';
import { sharesAlias } from '../lib/aliases.mjs';
import { canonicalJson } from '../lib/hash.mjs';
import { ROOT_DIR, loadSchedule, loadThresholds, loadToolVersions } from '../lib/config.mjs';
import { toIso } from '../lib/time.mjs';
import { runtimeGroups } from '../publish/runtime-groups.mjs';
import { buildSummary, buildLocalScan, buildCentralIssues } from './check-summary.mjs';
import { readJson, readJsonDir, readCentralData, loadLocalFeed, judgeLocalFeed } from './feed-input.mjs';

// exposure の優先順: 引数 → stack.yml（detect-stack が優先する）→ 中央の config/projects.yaml → 不明。lockfiles も同じ順
function configuredProject(cacheRoot, projectName) {
  const file = path.join(cacheRoot, 'config', 'projects.yaml');
  return existsSync(file) ? YAML.parse(readFileSync(file, 'utf8')).projects?.find((p) => p.project === projectName) ?? {} : {};
}

const gitHead = (dir) => { try { return execFileSync('git', ['-C', dir, 'rev-parse', 'HEAD'], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim(); } catch { return null; } };

// 書き込みは osv-db のキャッシュだけ。案件の作業ツリーと cacheRoot/data/ には書かない（指示書 §8.3）
// feedDir か noFeed があれば新しい経路（公開フィード＋任意の非公開側）。なければ今の動き（cacheRoot/data を読む）
export async function securityCheck({ cacheRoot, projectDir, projectName, deps, pullOk = true, scriptVersion, exposure = null, feedDir = null, feedSha = null, noFeed = false, privateRoot = null, osvDbDir = null, codeRoot = ROOT_DIR }) {
  const now = deps.now ?? new Date();
  const newRoute = Boolean(feedDir || noFeed);
  if (newRoute && !osvDbDir) throw new Error('新しい経路では osvDbDir が必要です');
  // 新しい経路の設定は非公開側（あれば）か公開側のコードのもの。既定引数に頼らず明示的に渡す
  const configRoot = newRoute ? (privateRoot ?? codeRoot) : undefined;
  const thresholds = loadThresholds(configRoot);
  const schedule = loadSchedule(configRoot);
  const privateData = privateRoot ? path.join(privateRoot, 'data') : null;
  const dataDir = newRoute ? privateData : path.join(cacheRoot, 'data');
  const osvDir = newRoute ? osvDbDir : path.join(cacheRoot, 'osv-db');
  const fetchHead = path.join(newRoute ? (privateRoot ?? cacheRoot) : cacheRoot, '.git', 'FETCH_HEAD');
  const cacheCommit = scriptVersion ?? gitHead(cacheRoot);

  const feed = newRoute ? loadLocalFeed({ feedDir, noFeed }) : null;
  const input = feed ?? readCentralData(dataDir);
  const { health } = input;
  const stale = isCentralStale(health?.last_success_at ?? null, schedule, now);

  const expected = loadToolVersions()['osv-scanner'].version;
  const scannerVersion = await deps.scannerVersion();

  const configured = newRoute ? (privateRoot ? configuredProject(privateRoot, projectName) : {}) : configuredProject(cacheRoot, projectName);
  const built = buildInventory({
    root: projectDir, project: projectName, mode: 'pull', monitorRef: 'local', sourceCommit: gitHead(projectDir), inventoryAsOf: toIso(now),
    exposure: exposure ?? configured.exposure ?? null, lockfileOverride: configured.lockfiles ?? null,
  });
  const { inventory } = built;
  const needed = requiredOsvEcosystems(inventory);

  // DB の準備: 12時間で更新、失敗しても72時間以内なら警告付きで使う。なければ照合不能（「影響なし」にしない）
  let meta = await readMeta(osvDir);
  const toRefresh = needed.filter((eco) => dbFreshness(meta[eco], now, thresholds).needs_refresh);
  const fetchErrors = {};
  if (toRefresh.length > 0) {
    const fetched = await deps.fetchOsvDb({ ecosystems: toRefresh, dest: osvDir, now });
    meta = fetched.meta;
    for (const eco of toRefresh) if (!fetched.outcomes[eco]?.ok) fetchErrors[eco] = fetched.outcomes[eco]?.error?.message ?? '取得に失敗';
  }
  const osvDb = {};
  const osvAvailable = Object.fromEntries(ECOSYSTEMS.map((eco) => [eco, false]));
  for (const eco of needed) {
    const freshness = dbFreshness(meta[eco], now, thresholds);
    const present = await dbFileExists(osvDir, eco);
    const state = present ? freshness.state : 'unavailable';
    osvDb[eco] = { fetched_at: meta[eco]?.fetched_at ?? null, sha256: meta[eco]?.sha256 ?? null, state, ...(fetchErrors[eco] ? { error: fetchErrors[eco] } : {}) };
    osvAvailable[eco] = state !== 'unavailable';
  }

  const provenance = {
    scanner_version: scannerVersion, script_version: cacheCommit,
    osv_db: Object.fromEntries(needed.filter((e) => meta[e]).map((e) => [e, { fetched_at: meta[e].fetched_at, sha256: meta[e].sha256 }])),
    inventory_commit: inventory.source_commit,
    ...(newRoute ? { feed_version: feed.mode === 'latest' ? feedSha : null } : {}),
  };
  const { runtimeData, kernelData } = input;
  const judged = newRoute ? judgeLocalFeed({ feed, inventory, thresholds, schedule, nowIso: toIso(now) }) : null;
  const advisories = newRoute ? combineAdvisoryViews({ publicAdvisories: feed.advisories, privateAdvisories: privateData ? readJsonDir(path.join(privateData, 'advisories')) : [] }) : input.advisories;
  const detection = await detectProject({
    inventory, workdir: projectDir, exec: deps.exec, scannerPath: deps.scannerPath, dbDir: osvDir, osvAvailable, runtimeData, packagistAdvisories: input.packagist, kernelData,
    ...(newRoute ? { feedAvailable: feed.mode === 'latest', thresholds } : {}),
  });
  const scanErrors = [...detection.errors, ...(judged?.errors ?? [])];
  const checks = detection.dependency_checks;
  const aggregate = Object.values(checks).includes('unavailable') ? 'unavailable' : 'ok';
  const items = assembleItems({ detections: detection.detections, index: buildAdvisoryIndex(advisories), exposure: inventory.exposure, now: toIso(now), provenance, ...(judged ? { signals: judged.signals } : {}) });

  const central = dataDir ? readJson(path.join(dataDir, 'findings', `${projectName}.json`)) : null;
  const summary = buildSummary({ inventory, osvAvailable, checks, scanErrors: detection.errors, items, runtimeData, kernelData, health, now, thresholds });
  const localScan = buildLocalScan({ summary, scanErrors, pullOk, localOsvDb: provenance.osv_db, central, inventory, extraReasons: judged?.reasons ?? [], compareCentral: !newRoute || Boolean(privateRoot) });
  const centralIssues = buildCentralIssues({ issuesFile: dataDir ? readJson(path.join(dataDir, 'issues.json')) : null, projectName, localScan, aliasSets: [...items, ...runtimeGroups(items).issueItems].map((i) => i.aliases), itemAliasSets: items.map((i) => i.aliases) });
  return {
    cache: { commit: cacheCommit, pull_ok: pullOk, pulled_at: existsSync(fetchHead) ? toIso(statSync(fetchHead).mtime) : null },
    central_health: { last_success_at: health?.last_success_at ?? null, expected_after: stale.expected_after, stale: stale.stale },
    scanner: { version: scannerVersion, expected, match: scannerVersion === expected },
    osv_db: osvDb,
    stack: { files: inventory.files, runtimes: inventory.runtimes, lockfiles: inventory.lockfiles, kernel: inventory.kernel ?? null, problems: built.problems },
    dependency_check: aggregate, dependency_checks: checks,
    results: items.map((i) => ({ advisory_key: i.advisory_key, aliases: i.aliases, judgement: i.judgement, priority: i.priority, locations: i.locations.map(({ lockfile, package: pkg, ecosystem, installed_version: version, fixed_versions: fixed, judgement }) => ({ lockfile, package: pkg, ecosystem, installed_version: version, ...(fixed ? { fixed_versions: fixed, judgement } : {}) })), fixed_versions: i.fixed_versions, title: i.title, source_urls: i.source_urls })),
    scan_errors: scanErrors,
    summary, local_scan: localScan, central_issues: centralIssues,
    central_diff: newRoute && !privateRoot ? null : centralDiff(central, items, provenance, newRoute ? localScan.complete : null),
    ...(judged ? { feed_signals: judged.state } : {}),
    provenance,
  };
}

// 中央の findings がある場合だけ差分を出す。provenance が同じなのに差があれば不具合として扱う
// 新しい経路（localComplete が null でない）は、中央が partial の回や手元が不完全・フィード未検証の回は不具合と報告しない
function centralDiff(central, localItems, provenance, localComplete) {
  if (!central) return {};
  const onlyLocal = localItems.filter((l) => !central.items.some((c) => sharesAlias(c.aliases, l.aliases))).map((i) => i.advisory_key);
  const onlyCentral = central.items.filter((c) => !localItems.some((l) => sharesAlias(c.aliases, l.aliases))).map((i) => i.advisory_key);
  const comparable = localComplete === null || (central.scan_status === 'complete' && localComplete && provenance.feed_version != null);
  const same = comparable && canonicalJson(central.provenance) === canonicalJson(provenance);
  return { only_local: onlyLocal, only_central: onlyCentral, ...(same && (onlyLocal.length > 0 || onlyCentral.length > 0) ? { mismatch_with_same_provenance: true } : {}) };
}
