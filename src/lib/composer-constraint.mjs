import semver from 'semver';

// D7: 意味を変えずに semver へ変換できる構文だけを扱う。切り捨て・丸め・補完は禁止。
// 対応: 版は MAJOR.MINOR.PATCH の3要素の数値（先頭の v は可）、演算子 >= > <= < =、"," または空白 = AND、"|" "||" = OR
const COMPARATOR = /^(>=|<=|>|<|=)?\s*v?(\d+\.\d+\.\d+)$/;
const THREE_PART = /^v?(\d+\.\d+\.\d+)$/;

export const parseComposerVersion = (text) => THREE_PART.exec(String(text ?? '').trim())?.[1] ?? null;

function parseAndGroup(text) {
  // ">= 1.0.0, < 2.0.0" のように演算子と版の間に空白があっても、1つの比較として扱う
  const normalized = text.replace(/(>=|<=|>|<|=)\s+/g, '$1').trim();
  const parts = normalized.split(/[,\s]+/).filter(Boolean);
  if (parts.length === 0) return null;
  const comparators = [];
  for (const part of parts) {
    const match = COMPARATOR.exec(part);
    if (!match) return null;
    comparators.push({ operator: match[1] ?? '=', version: match[2] });
  }
  return comparators;
}

// 戻り値: { ok:true, range, groups } または { ok:false, reason }
export function convertComposerConstraint(constraint) {
  const text = String(constraint ?? '').trim();
  if (!text) return { ok: false, reason: '制約が空です' };
  const groups = [];
  for (const orPart of text.split(/\|\|?/)) {
    const group = parseAndGroup(orPart);
    if (!group) return { ok: false, reason: `未対応の構文です: ${orPart.trim()}` };
    groups.push(group);
  }
  const range = groups.map((g) => g.map((c) => `${c.operator === '=' ? '' : c.operator}${c.version}`).join(' ')).join(' || ');
  if (semver.validRange(range) === null) return { ok: false, reason: `semver に変換できません: ${range}` };
  return { ok: true, range, groups };
}

// 判定: affected / not_affected / needs_review。fixed は、導入版が当てはまった AND 群の「< 上限」
export function evaluateComposer(constraint, installed) {
  const version = parseComposerVersion(installed);
  if (!version) return { judgement: 'needs_review', reason: `導入版を3要素の数値として解釈できません: ${installed}`, fixed: [] };
  const converted = convertComposerConstraint(constraint);
  if (!converted.ok) return { judgement: 'needs_review', reason: converted.reason, fixed: [] };
  const hits = converted.groups.filter((group) => semver.satisfies(version, group.map((c) => `${c.operator === '=' ? '' : c.operator}${c.version}`).join(' ')));
  if (hits.length === 0) return { judgement: 'not_affected', reason: null, fixed: [] };
  const fixed = hits.flatMap((g) => g.filter((c) => c.operator === '<').map((c) => c.version));
  return { judgement: 'affected', reason: null, fixed: [...new Set(fixed)].sort(semver.compare) };
}
