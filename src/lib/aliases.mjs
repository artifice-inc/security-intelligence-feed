// 別名の結合（union-find）。別名が1つでも共通すれば同じ脆弱性とみなす（指示書 §5.1）
const KEY_RANK = [/^CVE-/, /^GHSA-/, /^PKSA-/, /^NODE-CORE-/, /^EOL-/];
const SAFE_KEY = /[^A-Za-z0-9-]/g;

export function connectedComponents(items) {
  const parent = new Map();
  const find = (id) => {
    if (!parent.has(id)) parent.set(id, id);
    let root = id;
    while (parent.get(root) !== root) root = parent.get(root);
    for (let node = id; node !== root;) { const next = parent.get(node); parent.set(node, root); node = next; }
    return root;
  };
  for (const ids of items) {
    ids.forEach((id) => find(id));
    for (let i = 1; i < ids.length; i += 1) parent.set(find(ids[i]), find(ids[0]));
  }
  const groups = new Map();
  items.forEach((ids, index) => {
    if (ids.length === 0) return;
    const root = find(ids[0]);
    if (!groups.has(root)) groups.set(root, { indexes: [], ids: new Set() });
    const group = groups.get(root);
    group.indexes.push(index);
    ids.forEach((id) => group.ids.add(id));
  });
  return [...groups.values()].map((g) => ({ indexes: g.indexes, ids: [...g.ids].sort() }));
}

export function splitAliases(ids) {
  const unique = [...new Set(ids)].sort();
  return {
    cve: unique.filter((id) => /^CVE-/.test(id)),
    ghsa: unique.filter((id) => /^GHSA-/.test(id)),
    other: unique.filter((id) => !/^(CVE|GHSA)-/.test(id)),
  };
}

export const flatAliases = (advisory) => [
  ...advisory.aliases.cve, ...advisory.aliases.ghsa, ...advisory.aliases.other,
];

// 正規キー: CVE → GHSA → PKSA → NODE-CORE → EOL → その他。ファイル名に使える文字だけにする
export function canonicalKey(ids) {
  const sorted = [...ids].sort();
  for (const rank of KEY_RANK) {
    const found = sorted.find((id) => rank.test(id));
    if (found) return found.replace(SAFE_KEY, '-');
  }
  return sorted[0].replace(SAFE_KEY, '-');
}

export const sharesAlias = (left, right) => left.some((id) => right.includes(id));
