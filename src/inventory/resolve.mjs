import path from 'node:path';
import { buildInventory } from './build-inventory.mjs';
import { evaluateExport } from './export-inventory.mjs';
import { fetchRepo } from './fetch-repo.mjs';
import { toIso } from '../lib/time.mjs';
import { canonicalJson } from '../lib/hash.mjs';

const emptyRuntimes = () => ({ php: { version: null, constraint: null, source: null }, node: { version: null, constraint: null, source: null } });

// 取得できなかった回の縮退（D6）: ランタイムは前回の値を使い、依存関係は照合しない（workdir: null）
function unavailable({ cfg, previous, message }) {
  return {
    inventory: {
      project: cfg.project, mode: cfg.repo ? 'pull' : 'export', monitor_ref: cfg.monitor_ref,
      source_commit: previous?.source_commit ?? null, inventory_as_of: previous?.inventory_as_of ?? null,
      files: previous?.files ?? [], runtimes: previous?.runtimes ?? emptyRuntimes(),
      exposure: previous?.exposure ?? cfg.exposure ?? null, lockfiles: previous?.lockfiles ?? [],
    },
    inventory_status: 'unavailable', workdir: null,
    scan_errors: [{ kind: 'inventory', target: cfg.project, message }],
  };
}

const problemErrors = (problems) => problems.map((p) => ({ kind: p.kind, target: p.target, message: p.message }));

async function resolvePull({ cfg, previous, workRoot, token, now, cloneUrl, fetchImpl }) {
  try {
    const fetched = await fetchImpl({
      url: cloneUrl(cfg.repo), monitorRef: cfg.monitor_ref, dir: path.join(workRoot, cfg.project), token, lockfileOverride: cfg.lockfiles ?? null,
    });
    const built = buildInventory({
      root: fetched.dir, project: cfg.project, mode: 'pull', monitorRef: fetched.monitorRef,
      sourceCommit: fetched.sourceCommit, inventoryAsOf: toIso(now), exposure: cfg.exposure, lockfileOverride: cfg.lockfiles ?? null,
    });
    return { inventory: built.inventory, inventory_status: 'fresh', workdir: fetched.dir, scan_errors: problemErrors(built.problems) };
  } catch (error) {
    return unavailable({ cfg, previous, message: error.message });
  }
}

function resolveExport({ cfg, previous, exportRoot, now, thresholds }) {
  const evaluated = evaluateExport({ dir: path.join(exportRoot, cfg.project), now, thresholds });
  if (evaluated.status === 'unavailable') return unavailable({ cfg, previous, message: `export を使えません: ${evaluated.reason}` });
  const { manifest, filesDir } = evaluated;
  const built = buildInventory({
    root: filesDir, project: cfg.project, mode: 'export', monitorRef: manifest.source_ref,
    sourceCommit: manifest.source_commit, inventoryAsOf: manifest.exported_at, exposure: cfg.exposure, lockfileOverride: cfg.lockfiles ?? null,
  });
  const errors = problemErrors(built.problems);
  // 申告された検出結果と中央の再検出が食い違う場合は記録して partial にする
  if (canonicalJson(manifest.runtimes_detected) !== canonicalJson(built.inventory.runtimes)) {
    errors.push({ kind: 'inventory', target: cfg.project, message: 'export 時の runtimes_detected と中央の検出結果が一致しません' });
  }
  return { inventory: built.inventory, inventory_status: evaluated.status, workdir: filesDir, scan_errors: errors };
}

// 案件ごとにインベントリを取得する。戻り値の workdir が null なら依存関係は照合しない
export async function resolveInventory({
  cfg, previous = null, workRoot, exportRoot, token, now, thresholds, fetchImpl = fetchRepo,
  cloneUrl = (repo) => `https://github.com/${repo}.git`,
}) {
  if (cfg.source === 'export') return resolveExport({ cfg, previous, exportRoot, now, thresholds });
  return resolvePull({ cfg, previous, workRoot, token, now, cloneUrl, fetchImpl });
}
