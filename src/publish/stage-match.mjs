import { detectProject } from '../match/match-project.mjs';
import { assembleItems, buildAdvisoryIndex } from '../match/assemble.mjs';
import { decideScanStatus, requiredOsvEcosystems } from '../match/scan-status.mjs';
import { mergeFindings } from '../match/findings-merge.mjs';
import { fromOsv, fromPackagist } from '../normalize/sources.mjs';
import { mergeAdvisories } from '../normalize/advisories.mjs';
import { enrichAdvisories, wantedCves } from '../normalize/enrich.mjs';
import { dbFileExists, ECOSYSTEMS } from '../collect/osv-db.mjs';

const tokenFor = (owner, env, projectOwner) => env[`SI_APP_TOKEN_${owner.toUpperCase().replace(/[^A-Z0-9]/g, '_')}`] ?? (owner === projectOwner ? env.SI_APP_TOKEN : undefined);

// 案件ごとのインベントリ取得と照合。matchData は { runtimes: { php, nodejs, python }, packagist, amazonLinuxKernel }
// feedAvailable: false のときはフィード依存の照合（ランタイム・Packagist の API・カーネル）を止める
export async function resolveAndDetect({ projectsConfig, data, matchData, deps, osvDbDir, env, now, workRoot, exportRoot, feedAvailable = true, thresholds = undefined }) {
  const osvAvailable = Object.fromEntries(await Promise.all(ECOSYSTEMS.map(async (eco) => [eco, await dbFileExists(osvDbDir, eco)])));
  const runs = [];
  for (const cfg of projectsConfig.projects) {
    const owner = cfg.repo?.split('/')[0] ?? projectsConfig.project_owner;
    const token = tokenFor(owner, env, projectsConfig.project_owner);
    const missingToken = cfg.repo && !token;
    const resolved = await deps.resolveInventory({
      cfg, previous: data.inventory.get(cfg.project) ?? null, workRoot, exportRoot, token, now, thresholds,
      ...(missingToken ? { fetchImpl: async () => { throw new Error(`${owner} 用の App トークンがありません`); } } : {}),
    });
    let detection;
    let matchFailed = false;
    try {
      detection = await detectProject({
        inventory: resolved.inventory, workdir: resolved.workdir, exec: deps.exec, scannerPath: deps.scannerPath, dbDir: osvDbDir, osvAvailable,
        runtimeData: { php: matchData.runtimes?.php, nodejs: matchData.runtimes?.nodejs, python: matchData.runtimes?.python },
        packagistAdvisories: matchData.packagist, kernelData: matchData.amazonLinuxKernel, feedAvailable, thresholds,
      });
    } catch (error) {
      matchFailed = true;
      detection = { detections: [], errors: [{ kind: 'scanner', target: cfg.project, message: error.message }], dependency_checks: {} };
    }
    runs.push({ cfg, resolved, detection, matchFailed });
  }
  return runs;
}

// 照合で見つかったアドバイザリを取り込む（②）。OSV のレコードはスキャナの出力に含まれる。変わった記録の Map を返す
export function absorbAdvisories({ runs, advisories, now }) {
  const records = runs.flatMap((r) => r.detection.detections).flatMap((d) => (d.record ? [fromOsv(d.record, { now, dbEcosystem: d.ecosystem })] : d.packagist ? [fromPackagist(d.packagist.entry, d.packagist.advisoryId)] : []));
  return mergeAdvisories({ previous: advisories, records, now });
}

// 案件ごとの項目の組み立て・scan_status の判定・前回との統合。extraErrors は案件名 → 足す scan_errors
export function finalizeProjects({ runs, data, index, sourceResults, extraErrors = {}, osvMeta, osvFetchedThisRun, packagistFullSyncAt, provenanceBase, now, signals = null, ctx = null, thresholds = undefined }) {
  const findings = new Map();
  const inventories = new Map();
  for (const { cfg, resolved, detection, matchFailed } of runs) {
    const { inventory } = resolved;
    const ecosystems = requiredOsvEcosystems(inventory);
    const provenance = { ...provenanceBase, osv_db: Object.fromEntries(ecosystems.filter((e) => osvMeta[e]).map((e) => [e, osvMeta[e]])), inventory_commit: inventory.source_commit };
    const items = assembleItems({ detections: detection.detections, index, exposure: inventory.exposure, now, provenance, ...(signals ? { signals } : {}) });
    const { scan_status: scanStatus, scan_errors: scanErrors } = decideScanStatus({
      inventory, inventoryStatus: resolved.inventory_status, sourceResults, osvDb: osvFetchedThisRun, packagistFullSyncAt,
      scanErrors: [...resolved.scan_errors, ...detection.errors, ...(extraErrors[cfg.project] ?? [])], matchFailed,
    });
    findings.set(cfg.project, mergeFindings({
      previous: data.findings.get(cfg.project) ?? null, current: items,
      status: { project: cfg.project, monitor_ref: inventory.monitor_ref, inventory_status: resolved.inventory_status, scan_status: scanStatus, scan_errors: scanErrors, provenance, scanned_at: now, inventory_as_of: inventory.inventory_as_of },
      ...(signals ? { signals, ctx } : {}),
    }));
    inventories.set(cfg.project, inventory);
  }
  return { findings, inventories };
}

// 段4・5: インベントリ取得 → 照合 → 新しいアドバイザリの取り込み → KEV/EPSS の付与 → 優先度 → 前回との統合（旧処理の入口。動きは変えない）
export async function matchAll({ projectsConfig, data, norm, results, deps, osvDbDir, osvMeta, osvFetchedThisRun, env, now, workRoot, exportRoot, provenanceBase }) {
  const runs = await resolveAndDetect({ projectsConfig, data, matchData: norm, deps, osvDbDir, env, now, workRoot, exportRoot });
  const merged = absorbAdvisories({ runs, advisories: [...norm.advisories.values()], now });
  for (const [key, value] of merged) norm.advisories.set(key, value);

  const epss = await deps.collectors.epss({ http: deps.http, env, now, wantedCves: wantedCves([...norm.advisories.values()], results.kev?.ok ? results.kev.records : []) });
  const sourceResults = { ...results, epss };
  const enriched = enrichAdvisories({ advisories: [...norm.advisories.values()], kevRecords: results.kev?.ok ? results.kev.records : null, epssRecords: epss.ok ? epss.records : null, jpItems: norm.jpAlerts.items, now });
  for (const [key, value] of enriched) norm.advisories.set(key, value);
  const index = buildAdvisoryIndex([...norm.advisories.values()]);

  const { findings, inventories } = finalizeProjects({ runs, data, index, sourceResults, osvMeta, osvFetchedThisRun, packagistFullSyncAt: norm.packagist.full_sync_at, provenanceBase, now });
  return { findings, inventories, sourceResults, index, dependencyChecks: Object.fromEntries(runs.map((r) => [r.cfg.project, r.detection.dependency_checks])) };
}
