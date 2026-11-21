import { readFileSync } from 'node:fs';
import path from 'node:path';
import { runOsvScan } from './osv-scan.mjs';
import { matchRuntimes, relevantRuntimes } from './runtime-match.mjs';
import { runtimeErrors } from './python-runtime.mjs';
import { matchKernel } from './kernel-match.mjs';
import { matchPackagist } from './packagist-match.mjs';
import { assembleItems } from './assemble.mjs';
import { hasNoMaterial, ecosystemOfLockfile, isRequirementsFile } from '../inventory/detect-stack.mjs';
import { prepareRequirementsInputs, unpinnedErrors } from './requirements-input.mjs';

// フィードを使えない回に、その案件が使う対象ぶんだけ照合できなかったことを記録する
function feedUnavailableErrors({ inventory, names }) {
  const relevant = relevantRuntimes(inventory);
  const targets = [
    ...(relevant.php ? ['runtime:php'] : []), ...(relevant.node ? ['runtime:nodejs'] : []), ...(relevant.python ? ['runtime:python'] : []),
    ...(names.includes('composer.lock') ? ['packagist'] : []), ...(inventory.kernel ? ['kernel'] : []),
  ];
  return targets.map((target) => ({ kind: 'feed', target, message: 'フィードを使えないため照合していません' }));
}

// 中央とローカルで共用する照合の本体。workdir が null（インベントリ未取得）なら依存関係は照合しない
// osvAvailable: { npm: boolean, Packagist: boolean, PyPI: boolean }（その回に使える OSV の DB）
export async function detectProject({
  inventory, workdir, exec, scannerPath, dbDir, osvAvailable, runtimeData, packagistAdvisories, kernelData = null, feedAvailable = true, thresholds = undefined,
}) {
  const errors = [];
  const detections = [];
  const names = inventory.lockfiles.map((f) => path.basename(f));
  const checks = { osv: 'not_applicable', packagist: 'not_applicable' };

  const osvTargets = inventory.lockfiles.filter((f) => { const eco = ecosystemOfLockfile(f); return eco !== null && osvAvailable[eco]; });
  // 表にない名前は黙って読み飛ばさず、照合不能にする
  for (const f of inventory.lockfiles.filter((file) => ecosystemOfLockfile(file) === null)) {
    errors.push({ kind: 'lockfile', target: f, message: 'この lockfile の形式には対応していません' });
  }
  if (names.length > 0) checks.osv = 'ok';
  if (names.includes('composer.lock')) checks.packagist = 'ok';
  const needsOsv = names.length > 0;
  if (needsOsv && (!workdir || osvTargets.length < inventory.lockfiles.length)) checks.osv = 'unavailable';
  if (checks.packagist === 'ok' && (!workdir || !packagistAdvisories || !feedAvailable)) checks.packagist = 'unavailable';

  if (workdir && osvTargets.length > 0) {
    const requirements = prepareRequirementsInputs({ workdir, files: osvTargets.filter(isRequirementsFile), inventory });
    try {
      const inputs = [...osvTargets.filter((f) => !isRequirementsFile(f)).map((file) => ({ file, scanPath: path.join(workdir, file) })), ...requirements.inputs];
      const scan = await runOsvScan({ exec, scannerPath, root: workdir, inputs, dbDir });
      errors.push(...requirements.errors, ...scan.errors);
      if (!scan.ok || requirements.errors.length > 0) checks.osv = 'unavailable';
      detections.push(...scan.detections);
    } finally {
      requirements.cleanup();
    }
  }
  // 版を固定していない requirements は、スキャナに渡さず「照合不能」にする
  if (workdir) {
    const unpinned = unpinnedErrors({ workdir, inventory });
    if (unpinned.length > 0) { errors.push(...unpinned); checks.osv = 'unavailable'; }
  }

  if (workdir && checks.packagist === 'ok' && feedAvailable) {
    for (const lockfile of inventory.lockfiles.filter((f) => path.basename(f) === 'composer.lock')) {
      try {
        const composerLock = JSON.parse(readFileSync(path.join(workdir, lockfile), 'utf8'));
        detections.push(...matchPackagist({ composerLock, lockfile, advisories: packagistAdvisories.advisories }));
      } catch {
        errors.push({ kind: 'lockfile', target: lockfile, message: 'composer.lock を JSON として解析できません' });
        checks.packagist = 'unavailable';
      }
    }
  }

  // 材料が何もないのに「影響なし」にしない。インベントリ未取得（workdir なし）は別の経路で partial になる
  if (workdir && hasNoMaterial(inventory)) {
    errors.push({ kind: 'inventory', target: inventory.project, message: 'lockfile も検出用のファイルも見つかりません（対応しているのは npm・Composer・PyPI の lockfile と、PHP・Node.js・Python のランタイムです）。lockfile がサブフォルダにある場合は、案件の .security/stack.yml の lockfiles（中央の照合では config/projects.yaml の lockfiles）に書いてください' });
    checks.osv = 'unavailable';
    checks.packagist = 'unavailable';
  }

  if (!feedAvailable) {
    errors.push(...feedUnavailableErrors({ inventory, names }));
    return { errors, dependency_checks: checks, detections };
  }
  detections.push(...matchRuntimes({ inventory, runtimeData }));
  errors.push(...runtimeErrors({ inventory, runtimeData, graceDays: thresholds?.python_release_grace_days })); // 取得済みの検出は捨てず、照合の不完全さを知らせる（python のみ）
  const kernel = matchKernel({ inventory, kernelData });
  detections.push(...kernel.detections);
  errors.push(...kernel.errors);
  return { errors, dependency_checks: checks, detections };
}

// 検出から findings の item を作るところまで（ローカルの /security-check 用）
export async function matchProject({ advisoryIndex, provenance, now, ...rest }) {
  const result = await detectProject(rest);
  const items = assembleItems({ detections: result.detections, index: advisoryIndex, exposure: rest.inventory.exposure, now, provenance });
  return { ...result, items };
}
