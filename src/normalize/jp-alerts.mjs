import { toIso } from '../lib/time.mjs';

const MAX_ITEMS = 300;
const idOf = (item) => `${item.source}:${item.id}`;

// results: { jpcert: collectResult, ipa: ..., jvn: ... }。失敗した情報源は前回の項目をそのまま残す
export function normalizeJpAlerts({ previous, results, now }) {
  const merged = new Map((previous?.items ?? []).map((i) => [idOf(i), i]));
  for (const result of Object.values(results)) {
    if (!result.ok) continue;
    for (const record of result.records) {
      const before = merged.get(idOf(record));
      merged.set(idOf(record), {
        source: record.source, id: record.id, title: record.title, link: record.link, date: record.date,
        cves: record.cves, verification_status: record.verification_status,
        first_seen_at: before?.first_seen_at ?? toIso(now),
      });
    }
  }
  const items = [...merged.values()]
    .sort((a, b) => (b.date ?? '').localeCompare(a.date ?? '') || (idOf(a) < idOf(b) ? -1 : 1))
    .slice(0, MAX_ITEMS);
  const next = { updated_at: previous?.updated_at ?? toIso(now), items };
  // 内容が同じなら updated_at を更新しない（不要なコミットを避ける）
  if (JSON.stringify(previous?.items) !== JSON.stringify(items)) next.updated_at = toIso(now);
  return next;
}

// 今回初めて見た項目（digest の「新着」用）
export const newItems = (previous, next) => {
  const known = new Set((previous?.items ?? []).map(idOf));
  return next.items.filter((i) => !known.has(idOf(i)));
};
