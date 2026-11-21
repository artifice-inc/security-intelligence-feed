import path from 'node:path';
import { relevantRuntimes } from '../match/runtime-match.mjs';
import { requiredOsvEcosystems } from '../match/scan-status.mjs';
import { sharesAlias } from '../lib/aliases.mjs';
import { ecosystemOfLockfile } from '../inventory/detect-stack.mjs';
import { declaredKernel } from '../match/kernel-match.mjs';
import { hoursBetween } from '../lib/time.mjs';
import { loadThresholds } from '../lib/config.mjs';
import { releaseOf, inGrace } from '../match/python-runtime.mjs';

const RUNTIME_DATA_KEY = { php: 'php', node: 'nodejs', python: 'python' };
const emptyCounts = () => ({ P0: 0, P1: 0, P2: 0, P3: 0 });

// 件数の数え方: 1つの item が複数の対象にあれば対象ごとに数える。total は item の数（重複を数えない）
function countRows(rows, items) {
  const total = emptyCounts();
  for (const item of items) {
    total[item.priority] += 1;
    for (const row of rows) {
      const hit = item.locations.some((l) => (row.kind === 'runtime' ? l.ecosystem === 'runtime' && l.package === row.target : row.kind === 'os' ? l.ecosystem === 'os' : l.lockfile === row.target));
      if (hit) row[item.priority] += 1;
    }
  }
  return total;
}

// 「0件」と「照合できていない」を区別するため、行は検出結果ではなく inventory から作る
// カーネルの行が ok になれる条件。古いデータや取得に失敗した回のデータで「照合できた」と扱わない（中央の partial と揃える）
function kernelState({ inventory, kernelData, health, now, thresholds }) {
  const alas = health?.sources?.alas;
  const fresh = alas?.last_success_at && hoursBetween(alas.last_success_at, now) <= thresholds.stale_source_hours;
  const ok = kernelData?.backfill_complete === true && kernelData.retry.length === 0 && alas && alas.last_error === null && fresh
    && kernelData.known_packages.includes(declaredKernel(inventory.kernel).key);
  return ok ? 'ok' : 'unavailable';
}

const PYTHON_SOURCES = ['python-psf', 'python-releases', 'endoflife-python'];

// Python 用の3つの情報源が新しい（成功していて、36時間以内）か。中央が取得に失敗した回のデータで「照合できた」と扱わない
export function pythonSourcesFresh({ health, now, thresholds }) {
  return PYTHON_SOURCES.every((name) => {
    const source = health?.sources?.[name];
    return source && source.last_error === null && source.last_success_at && hoursBetween(source.last_success_at, now) <= thresholds.stale_source_hours;
  });
}

function runtimeState({ name, inventory, data, items, health, now, thresholds }) {
  const runtime = inventory.runtimes[name];
  const grace = name === 'python' && runtime.version && (() => { const r = releaseOf(data, runtime.version); return Boolean(r) && inGrace(data, r, thresholds.python_release_grace_days); })();
  if (items.some((i) => i.advisory_key === `RUNTIME-UNKNOWN-${name}`) || grace) return 'unknown';
  if (name === 'python' && (!data || (data.pending ?? []).length > 0 || !pythonSourcesFresh({ health, now, thresholds }))) return 'unavailable';
  return !runtime.version ? 'unknown' : data ? 'ok' : 'unavailable';
}

export function buildSummary({ inventory, osvAvailable, checks, scanErrors, items, runtimeData, kernelData = null, health = null, now = new Date(), thresholds = loadThresholds() }) {
  const erroredTargets = new Set(scanErrors.map((e) => e.target));
  const rows = inventory.lockfiles.map((target) => {
    const isComposer = path.basename(target) === 'composer.lock';
    const covered = isComposer
      ? osvAvailable.Packagist && checks.packagist === 'ok' && checks.osv === 'ok'
      : Boolean(osvAvailable[ecosystemOfLockfile(target)]) && checks.osv === 'ok';
    return { target, kind: 'lockfile', state: covered && !erroredTargets.has(target) ? 'ok' : 'unavailable', ...emptyCounts() };
  });
  // 版を固定していない requirements は照合していない。行がないとレポートに出ない
  for (const f of inventory.files.filter((file) => file.kind === 'requirements-unpinned')) rows.push({ target: f.path, kind: 'lockfile', state: 'unavailable', ...emptyCounts() });
  const relevant = relevantRuntimes(inventory);
  for (const name of ['php', 'node', 'python'].filter((n) => relevant[n])) {
    const state = runtimeState({ name, inventory, data: runtimeData[RUNTIME_DATA_KEY[name]], items, health, now, thresholds });
    rows.push({ target: name, kind: 'runtime', state, ...emptyCounts() });
  }
  if (inventory.kernel) rows.push({ target: `kernel:${declaredKernel(inventory.kernel).key}`, kind: 'os', state: kernelState({ inventory, kernelData, health, now, thresholds }), ...emptyCounts() });
  return { rows, total: countRows(rows, items) };
}

const isOlder = (local, central) => !local || !central || Date.parse(local) < Date.parse(central);

// クローズ候補を出してよいかの判定。満たさない条件は理由として日本語で返す
export function buildLocalScan({ summary, scanErrors, pullOk, localOsvDb, central, inventory, extraReasons = [], compareCentral = true }) {
  const reasons = [...extraReasons];
  const notOk = summary.rows.filter((r) => r.state !== 'ok');
  if (notOk.length > 0) reasons.push(`照合できていない対象があります: ${notOk.map((r) => `${r.target}（${r.state}）`).join('、')}`);
  if (scanErrors.length > 0) reasons.push(`スキャンでエラーがありました（${scanErrors.length}件）`);
  if (!pullOk) reasons.push('中央のデータの更新（pull）に失敗しており、手元のデータが古い可能性があります');
  // 配布先（compareCentral が false）には中央の findings がないので比べない
  if (compareCentral && !central) reasons.push('中央の findings がないため、OSV DB の取得時点を比べられません');
  else if (compareCentral) {
    for (const eco of requiredOsvEcosystems(inventory)) {
      if (isOlder(localOsvDb[eco]?.fetched_at, central.provenance?.osv_db?.[eco]?.fetched_at)) reasons.push(`手元の OSV DB（${eco}）が中央より古い、または取得時点を比べられません`);
    }
  }
  return { complete: reasons.length === 0, reasons };
}

// issuesFile: cacheRoot/data/issues.json の中身（なければ null）。aliasSets: 手元の結果の aliases の配列の一覧
// itemAliasSets: 手元の item そのもの（まとめに入ったかどうかを問わない）の aliases の配列。まとめ Issue の member が混在 item に移っていないかを見る
export function buildCentralIssues({ issuesFile, projectName, localScan, aliasSets, itemAliasSets = aliasSets }) {
  if (!issuesFile) return null;
  const open = { P0: 0, P1: 0, P2: 0 };
  const fixedInRepo = [];
  const superseded = [];
  const candidates = [];
  for (const issue of issuesFile.filter((i) => i.project === projectName && i.state === 'open')) {
    const { issue_number: number, aliases } = issue;
    if (typeof issue.superseded_by === 'number') { superseded.push({ issue_number: number, aliases, superseded_by: issue.superseded_by }); continue; }
    if (issue.labels.includes('fixed-in-repo')) { fixedInRepo.push({ issue_number: number, aliases }); continue; }
    for (const p of Object.keys(open)) if (issue.labels.includes(p)) open[p] += 1;
    // カーネルは配布元のデータだけを見ていて、手元で消えても「解消した」とは言えない
    if (aliases.some((a) => a.startsWith('KERNEL-'))) continue;
    // 中央が移行を済ませる前に、まとめの member が手元の item に移っていれば、解消とは言えない
    const memberKeys = issue.member_keys ?? [];
    if (memberKeys.length > 0 && itemAliasSets.some((set) => sharesAlias(memberKeys, set))) continue;
    if (!aliasSets.some((set) => sharesAlias(aliases, set))) candidates.push({ issue_number: number, aliases });
  }
  return { open, fixed_in_repo: fixedInRepo, superseded, resolved_locally: localScan.complete ? candidates : null };
}
