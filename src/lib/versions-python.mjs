// CPython の版は「x.y.z の数値3要素の正式版」だけを扱う（rc・a・b は捨てる）。versions-php.mjs と同じ並び
const RELEASE_TAG = /^v(\d+\.\d+\.\d+)$/;
const MS_PER_DAY = 86_400_000;

const numbers = (version) => version.split('.').map(Number);

export function comparePython(a, b) {
  const left = numbers(a);
  const right = numbers(b);
  for (let i = 0; i < 3; i += 1) if (left[i] !== right[i]) return left[i] < right[i] ? -1 : 1;
  return 0;
}

// `3.12.7` → `3.12`。正式版の形でなければ null
export const pythonBranch = (version) => (/^\d+\.\d+\.\d+$/.test(String(version)) ? String(version).split('.').slice(0, 2).join('.') : null);

// OSV の記録の影響タグ（v3.12.13 など）のうち正式版だけを、重複なし・昇順で返す
export function pythonAffectedVersions(raw) {
  const versions = (raw.affected ?? []).flatMap((a) => a.versions ?? []).map((tag) => RELEASE_TAG.exec(tag)?.[1]).filter(Boolean);
  return [...new Set(versions)].sort(comparePython);
}

// affected に出てくるブランチごとに、「そのブランチの影響の最大の版より大きい正式版のうち最小のもの」。
// リリースから graceDays たっていない版は、OSV の補完を確認できないので候補にしない
// releases: [{ version, date }]。now は基準時刻（中央では PSF を取り込む回の時刻）
export function pythonFixedVersions(affected, releases, { now, graceDays }) {
  const maxByBranch = new Map();
  for (const version of affected) {
    const branch = pythonBranch(version);
    if (!maxByBranch.has(branch) || comparePython(version, maxByBranch.get(branch)) > 0) maxByBranch.set(branch, version);
  }
  const settled = (release) => release.date && new Date(now) - new Date(release.date) >= graceDays * MS_PER_DAY;
  const fixed = [];
  for (const [branch, max] of maxByBranch) {
    const candidates = releases.filter((r) => pythonBranch(r.version) === branch && comparePython(r.version, max) > 0 && settled(r)).map((r) => r.version);
    if (candidates.length > 0) fixed.push(candidates.sort(comparePython)[0]);
  }
  return fixed.sort(comparePython);
}
