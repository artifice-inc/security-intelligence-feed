// 箇所（lockfile・package・installed_version）ごとの判定・修正版の統合。新しい経路（signals あり）だけが使う純粋関数
export const locationKey = (l) => `${l.lockfile}|${l.package}|${l.installed_version}`;
export const locationOrder = (a, b) => a.lockfile.localeCompare(b.lockfile) || a.package.localeCompare(b.package) || String(a.installed_version).localeCompare(String(b.installed_version));
export const uniq = (values) => [...new Set(values)].sort();

const isMixed = (locations) => locations.some((l) => l.ecosystem === 'runtime') && locations.some((l) => l.ecosystem !== 'runtime');

// 箇所ごとの値がなければ、その箇所を持っていた項目の値を入れる
export const withValues = (location, item) => (location.judgement ? location : { ...location, fixed_versions: item.fixed_versions ?? [], judgement: item.judgement });

// 同じ箇所を1つにまとめる。judgement は affected 優先、fixed_versions は和集合、確認は最新（同時刻なら入力の先頭）。入力は値が揃っていること
export function dedupeValued(valued) {
  const byKey = new Map();
  for (const l of valued) {
    const before = byKey.get(locationKey(l));
    if (!before) { byKey.set(locationKey(l), l); continue; }
    const newer = l.last_confirmed_at > before.last_confirmed_at ? l : before;
    byKey.set(locationKey(l), {
      ...newer, judgement: [before, l].some((x) => x.judgement === 'affected') ? 'affected' : 'needs_review',
      fixed_versions: uniq([...before.fixed_versions, ...l.fixed_versions]),
    });
  }
  return [...byKey.values()].sort(locationOrder);
}

// 混在か、箇所ごとの値が違うときだけ箇所ごとの値を残す（Issue 本文は値のある箇所を混在の表で描画する）
export function compactValues(locations) {
  const differs = new Set(locations.map((l) => l.judgement)).size > 1 || new Set(locations.map((l) => JSON.stringify(l.fixed_versions))).size > 1;
  if (isMixed(locations) || differs) return locations;
  return locations.map(({ judgement, fixed_versions: fixedVersions, ...rest }) => rest);
}
