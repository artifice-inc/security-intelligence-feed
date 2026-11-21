import { connectedComponents, canonicalKey, splitAliases, flatAliases } from '../lib/aliases.mjs';

// 照合（OSV・Packagist）が作る情報源。これ以外が1つでも入った記録は公開由来を含む
const MATCHED_SOURCES = new Set(['osv', 'packagist']);

const byKey = (a, b) => (a.key < b.key ? -1 : a.key > b.key ? 1 : 0);

// 公開側と非公開側のアドバイザリを、照合の時だけ合成する。保存しない
export function combineAdvisoryViews({ publicAdvisories = [], privateAdvisories = [] }) {
  const live = (list) => list.filter((a) => !a.superseded_by).sort(byKey);
  const publicList = live(publicAdvisories);
  const all = [...publicList, ...live(privateAdvisories)];
  return connectedComponents(all.map((a) => [a.key, ...flatAliases(a)])).map((component) => {
    const members = component.indexes.map((i) => ({ advisory: all[i], isPublic: i < publicList.length }));
    const ordered = [...members.filter((m) => m.isPublic), ...members.filter((m) => !m.isPublic)].map((m) => m.advisory);
    // 単一の値は公開側が優先。先に非公開側を敷いて公開側で上書きする
    const base = [...ordered].reverse().reduce((merged, a) => ({ ...merged, ...a }), {});
    const seen = new Set();
    const sources = ordered.flatMap((a) => a.sources ?? []).filter((s) => { const tag = `${s.name}|${s.id}`; if (seen.has(tag)) return false; seen.add(tag); return true; });
    const kev = ordered.some((a) => a.known_exploited?.kev === true);
    return {
      ...base,
      key: canonicalKey(component.ids),
      aliases: splitAliases(component.ids),
      sources,
      affected: ordered.flatMap((a) => a.affected ?? []),
      known_exploited: { kev, date_added: ordered.map((a) => a.known_exploited?.date_added).find(Boolean) ?? null },
      status: sources.length > 0 && sources.every((s) => s.withdrawn_at) ? 'withdrawn' : 'active',
      superseded_by: null,
    };
  });
}

// 保存済みの記録のうち、照合由来の情報源だけの記録を返す（公開由来を含む記録と、出どころの分からない空の sources は捨て、作り直さない）
export const keepMatchedOnly = (advisories) => advisories.filter((a) => (a.sources ?? []).length > 0 && a.sources.every((s) => MATCHED_SOURCES.has(s.name)));
