// PHP 本体の版は「x.y.z の数値3要素」だけを扱う。丸めや補完はしない
export function parsePhpVersion(text) {
  const match = /^v?(\d+)\.(\d+)\.(\d+)$/.exec(String(text).trim());
  return match ? [Number(match[1]), Number(match[2]), Number(match[3])] : null;
}

export function comparePhp(a, b) {
  const left = parsePhpVersion(a);
  const right = parsePhpVersion(b);
  if (!left || !right) throw new Error(`PHP の版を比較できません: ${a} / ${b}`);
  for (let i = 0; i < 3; i += 1) {
    if (left[i] !== right[i]) return left[i] < right[i] ? -1 : 1;
  }
  return 0;
}

export function phpBranch(version) {
  const parts = parsePhpVersion(version);
  return parts ? `${parts[0]}.${parts[1]}` : null;
}

const VERSION = String.raw`(\d+\.\d+\.\d+)`;
const UPPER_TERMS = [
  { pattern: new RegExp(`^<\\s*${VERSION}$`), inclusive: false },
  { pattern: new RegExp(`^<=\\s*${VERSION}$`), inclusive: true },
  { pattern: new RegExp(`^${VERSION}\\s*-\\s*${VERSION}$`), inclusive: true, group: 2 },
  { pattern: new RegExp(`^${VERSION}$`), inclusive: true },
];
// 下限は使わない（下限より古い版まで影響ありに倒れるだけで、見逃しにはならない）
const LOWER_TERM = new RegExp(`^>=?\\s*${VERSION}$`);

// 影響範囲の1項を { version, inclusive } へ。下限なら 'lower'、解析できなければ null
function upperBound(term) {
  if (LOWER_TERM.test(term)) return 'lower';
  for (const { pattern, inclusive, group = 1 } of UPPER_TERMS) {
    const match = pattern.exec(term);
    if (match) return { version: match[group], inclusive };
  }
  return null;
}

// "8.1.29, 8.2.20, 8.3.8." のような修正版の列挙を版の配列へ。解析できなければ null
function patchedList(patched) {
  const terms = String(patched ?? '').split(',').map((t) => t.trim().replace(/\.$/, '')).filter(Boolean);
  return terms.every((t) => parsePhpVersion(t)) ? terms : null;
}

// php-src の GHSA の範囲表記を、ブランチごとの { branch, fixed } の配列へ。表記自体を解析できなければ null
// 1行に複数ブランチが並ぶ表記（"8.2.0 - 8.2.19, 8.3.0 - 8.3.7"）や、修正版にだけ出るブランチもある
// 修正版を決められないブランチは、他のブランチが決まった行に限り { type: 'UNPARSED', branch } として残す
export function parsePhpRange(range, patched) {
  const terms = String(range ?? '').split(',').map((t) => t.trim()).filter(Boolean);
  const fixedList = patchedList(patched);
  if (terms.length === 0 || !fixedList) return null;
  const uppers = new Map();
  for (const term of terms) {
    const bound = upperBound(term);
    if (bound === null) return null;
    if (bound === 'lower') continue;
    const branch = phpBranch(bound.version);
    if (uppers.has(branch)) return null;
    uppers.set(branch, bound);
  }
  const patchedByBranch = new Map();
  for (const version of fixedList) {
    const branch = phpBranch(version);
    if (patchedByBranch.has(branch)) return null;
    patchedByBranch.set(branch, version);
  }
  const result = [];
  for (const branch of new Set([...uppers.keys(), ...patchedByBranch.keys()])) {
    const bound = uppers.get(branch);
    const fixed = patchedByBranch.get(branch) ?? (bound && !bound.inclusive ? bound.version : null);
    // 修正版が影響範囲の内側に入るのは食い違い（"< 8.3.5" に修正版 8.3.6 は可。8.3.5 は未リリース）
    const conflict = fixed && bound && comparePhp(fixed, bound.version) < (bound.inclusive ? 1 : 0);
    result.push(fixed && !conflict ? { type: 'PHP_BRANCH', branch, fixed } : { type: 'UNPARSED', branch, raw: String(range).trim() });
  }
  // 1つも決まらない行はブランチの帰属も信用しない（"8.2.12" は再現環境の版で、範囲ではない例がある）
  if (!result.some((r) => r.type === 'PHP_BRANCH')) return null;
  return result.sort((a, b) => a.branch.localeCompare(b.branch, undefined, { numeric: true }));
}

// 「同じブランチで fixed 未満なら影響あり」。版が解釈できなければ null（needs_review 側へ）
export function isPhpBranchAffected(range, version) {
  if (!parsePhpVersion(version)) return null;
  if (phpBranch(version) !== range.branch) return false;
  return comparePhp(version, range.fixed) < 0;
}
