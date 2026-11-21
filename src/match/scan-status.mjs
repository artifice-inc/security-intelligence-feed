import { relevantRuntimes } from './runtime-match.mjs';
import path from 'node:path';
import { ecosystemOfLockfile } from '../inventory/detect-stack.mjs';
import { ECOSYSTEMS } from '../collect/osv-db.mjs';

// 設計書 §6.6 と指示書 §6.6: その回に必要な情報源。runtimes は relevantRuntimes の結果
export function requiredSources(inventory) {
  const base = ['kev', 'epss', 'endoflife'];
  const relevant = relevantRuntimes(inventory);
  const names = inventory.lockfiles.map((f) => path.basename(f));
  const sources = [...base];
  if (relevant.php) sources.push('php-ghsa', 'php-releases');
  if (relevant.node) sources.push('node-core', 'node-dist');
  if (relevant.python) sources.push('python-psf', 'python-releases', 'endoflife-python');
  if (names.includes('composer.lock')) sources.push('packagist');
  if (inventory.kernel) sources.push('alas');
  return sources;
}

export function requiredOsvEcosystems(inventory) {
  const used = new Set(inventory.lockfiles.map(ecosystemOfLockfile));
  // 順序は ECOSYSTEMS の順（既存案件の provenance のキーの順を変えない）
  return ECOSYSTEMS.filter((eco) => used.has(eco));
}

// sourceResults: { <name>: { ok } }（その回の取得結果）、osvDb: { <eco>: boolean（その回に取得・検証できたか） }
export function decideScanStatus({ inventory, inventoryStatus, sourceResults, osvDb, packagistFullSyncAt, scanErrors, matchFailed = false }) {
  const errors = [...scanErrors];
  for (const name of requiredSources(inventory)) {
    if (!sourceResults[name]?.ok) errors.push({ kind: 'source', target: name, message: `情報源 ${name} をその回に取得できませんでした` });
  }
  if (inventory.lockfiles.some((f) => path.basename(f) === 'composer.lock') && !packagistFullSyncAt) {
    errors.push({ kind: 'source', target: 'packagist', message: 'Packagist の全件取得がまだ一度も成功していません' });
  }
  for (const eco of requiredOsvEcosystems(inventory)) {
    if (!osvDb[eco]) errors.push({ kind: 'osv_db', target: eco, message: `OSV の DB（${eco}）をその回に取得・検証できませんでした` });
  }
  const unique = errors.filter((e, i) => errors.findIndex((o) => o.kind === e.kind && o.target === e.target && o.message === e.message) === i);
  let status = 'complete';
  if (matchFailed || unique.some((e) => e.kind === 'scanner')) status = 'failed';
  else if (inventoryStatus !== 'fresh' || unique.length > 0) status = 'partial';
  return { scan_status: status, scan_errors: unique };
}
