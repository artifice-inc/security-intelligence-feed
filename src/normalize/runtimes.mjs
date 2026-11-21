import { toIso } from '../lib/time.mjs';
import { phpBranch } from '../lib/versions-php.mjs';
import { pythonBranch, comparePython } from '../lib/versions-python.mjs';

const sourceUrls = (advisory) => advisory.sources.filter((s) => !s.withdrawn_at).map((s) => s.url).filter(Boolean).sort();

// EOL ブランチの見逃し判定に使う。複数の情報源のうち最も古い公開日時（ISO 8601 の文字列比較で足りる）
const earliestPublished = (advisory) => advisory.sources.map((s) => s.published_at).filter(Boolean).sort()[0] ?? null;

// affected: 使う要素（python は python の要素だけ。PyPI の要素の範囲を混ぜない）
function advisoryEntry(advisory, affected = advisory.affected) {
  const ranges = affected.flatMap((a) => a.ranges).filter((r) => ['PHP_BRANCH', 'NODE_SEMVER', 'PY_VERSIONS', 'UNPARSED'].includes(r.type));
  const fixed = ranges.flatMap((r) => (r.type === 'PHP_BRANCH' ? [r.fixed] : r.type === 'NODE_SEMVER' ? r.fixed_versions : r.type === 'PY_VERSIONS' ? r.fixed : []));
  return {
    key: advisory.key, aliases: [advisory.key, ...advisory.aliases.cve, ...advisory.aliases.ghsa, ...advisory.aliases.other].filter((v, i, all) => all.indexOf(v) === i).sort(),
    ranges, fixed_versions: [...new Set(fixed)].sort(), source_urls: sourceUrls(advisory), published_at: earliestPublished(advisory),
  };
}

// 範囲はそのランタイムの要素だけから作る（同じ CVE の PSF の記録が統合されると、PY_VERSIONS が混ざるため）
const runtimeAdvisories = (advisories, ecosystem) => advisories
  .filter((a) => a.category === 'runtime' && a.ecosystem === ecosystem && !a.superseded_by && a.status === 'active')
  .sort((a, b) => (a.key < b.key ? -1 : 1)).map((a) => advisoryEntry(a, a.affected.filter((e) => e.package?.ecosystem === ecosystem)));

// category を問わず、affected に python の要素があるものを拾う（同じ CVE の PyPI のアドバイザリが先にあると category が dependency のままになるため）
export function pythonRuntimeAdvisories(advisories) {
  return advisories
    .filter((a) => !a.superseded_by && a.status === 'active')
    .map((a) => [a, a.affected.filter((e) => e.package?.ecosystem === 'python')])
    .filter(([, elements]) => elements.length > 0)
    .sort(([a], [b]) => (a.key < b.key ? -1 : 1)).map(([a, elements]) => advisoryEntry(a, elements));
}

// php.net のブランチ状態と endoflife.date を突き合わせる。どちらか一方でも EOL なら EOL とする（安全側）
export function buildPhpRuntime({ previous, phpReleases, endoflife, advisories, now }) {
  if (!phpReleases || !endoflife) return finish('php', previous, previous?.branches ?? [], runtimeAdvisories(advisories, 'php'), now);
  const eolByBranch = new Map(endoflife.filter((r) => r.product === 'php').map((r) => [r.name, r]));
  const branches = phpReleases.filter((r) => r.type === 'branch' && r.state).map((r) => {
    const eol = eolByBranch.get(r.branch);
    return {
      branch: r.branch, state: r.state, security_support_end: r.security_support_end,
      is_eol: r.state === 'eol' || eol?.isEol === true, latest_version: eol?.latest ?? null,
    };
  }).sort((a, b) => a.branch.localeCompare(b.branch, undefined, { numeric: true }));
  return finish('php', previous, branches, runtimeAdvisories(advisories, 'php'), now);
}

export function buildNodeRuntime({ previous, nodeDist, endoflife, advisories, now }) {
  if (!nodeDist || !endoflife) return finish('nodejs', previous, previous?.branches ?? [], runtimeAdvisories(advisories, 'node'), now);
  const latestByMajor = new Map();
  for (const r of nodeDist) {
    const major = r.version.slice(1).split('.')[0];
    if (!latestByMajor.has(major)) latestByMajor.set(major, r.version.slice(1)); // dist/index.json は新しい順
  }
  const branches = endoflife.filter((r) => r.product === 'nodejs').map((r) => ({
    branch: r.name, state: r.isEol ? 'eol' : r.isLts ? 'lts' : 'maintained',
    security_support_end: r.eolFrom, is_eol: r.isEol, latest_version: r.latest ?? latestByMajor.get(r.name) ?? null,
  })).sort((a, b) => a.branch.localeCompare(b.branch, undefined, { numeric: true }));
  return finish('nodejs', previous, branches, runtimeAdvisories(advisories, 'node'), now);
}

// python.org の正式版（{ version, date }）と endoflife.date の python から。どちらかがなければ前回の branches を使う
// pending: 今回の [{ id, reason }]（PSF か python.org の取得に失敗した回は null → 前回の値を残す）
export function buildPythonRuntime({ previous, pythonReleases, endoflife, advisories, pending, now }) {
  const nextPending = pending === null || pending === undefined
    ? previous?.pending ?? []
    : pending.map((p) => ({ id: p.id, reason: p.reason, since: previous?.pending?.find((q) => q.id === p.id)?.since ?? toIso(now) })).sort((a, b) => (a.id < b.id ? -1 : 1));
  // 猶予期間の判定は「PSF を最後に取り込んだ時刻」で行う。取り込めなかった回は前回の値を残す
  const extra = { pending: nextPending, psf_synced_at: pending ? toIso(now) : previous?.psf_synced_at ?? null };
  const list = pythonRuntimeAdvisories(advisories);
  if (!pythonReleases || !endoflife) return finish('python', previous, previous?.branches ?? [], list, now, extra);
  const branches = endoflife.filter((r) => r.product === 'python').map((r) => {
    const versions = pythonReleases.filter((v) => pythonBranch(v.version) === r.name).sort((a, b) => comparePython(a.version, b.version))
      .map((v) => ({ version: v.version, date: v.date ? String(v.date).slice(0, 10) : null }));
    return {
      branch: r.name, state: r.isEol ? 'eol' : 'maintained', security_support_end: r.eolFrom, is_eol: r.isEol,
      latest_version: r.latest ?? versions.at(-1)?.version ?? null, versions,
    };
  }).sort((a, b) => a.branch.localeCompare(b.branch, undefined, { numeric: true }));
  return finish('python', previous, branches, list, now, extra);
}

// extra: python だけが持つ項目（pending・psf_synced_at）。更新日時の判定にも含める
function finish(runtime, previous, branches, advisories, now, extra = {}) {
  const next = { runtime, updated_at: previous?.updated_at ?? toIso(now), branches, advisories, ...extra };
  const before = { b: previous?.branches, a: previous?.advisories, ...Object.fromEntries(Object.keys(extra).map((k) => [k, previous?.[k]])) };
  if (JSON.stringify(before) !== JSON.stringify({ b: branches, a: advisories, ...extra })) next.updated_at = toIso(now);
  return next;
}

export const branchOf = (runtime, version) => (runtime === 'php' ? phpBranch(version) : runtime === 'python' ? pythonBranch(version) : String(version).split('.')[0]);
