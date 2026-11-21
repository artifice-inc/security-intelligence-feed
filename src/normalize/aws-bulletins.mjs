import { toIso, daysBetween } from '../lib/time.mjs';

const MAX_ITEMS = 300;
const URL_BASE = 'https://aws.amazon.com/security/security-bulletins/';

// 掲載日時の降順、同じなら ID の降順
const byNewest = (a, b) => b.rss_pub_date.localeCompare(a.rss_pub_date) || b.id.localeCompare(a.id);

// RSS から消えた項目は保持範囲の外に出ただけなので残す
export function normalizeAwsBulletins({ previous, records, now }) {
  const merged = new Map((previous?.items ?? []).map((item) => [item.id, item]));
  for (const record of records) {
    const before = merged.get(record.id);
    const changed = before && (before.title !== record.title || before.rss_pub_date !== record.rss_pub_date);
    merged.set(record.id, {
      id: record.id, title: record.title, url: `${URL_BASE}${record.id}/`, rss_pub_date: record.rss_pub_date,
      cves: record.cves, first_seen_at: before?.first_seen_at ?? toIso(now),
      last_changed_at: changed ? toIso(now) : (before?.last_changed_at ?? null),
    });
  }
  const items = [...merged.values()].sort(byNewest).slice(0, MAX_ITEMS);
  const unchanged = JSON.stringify(previous?.items) === JSON.stringify(items);
  return { updated_at: unchanged ? previous.updated_at : toIso(now), items };
}

// digest 用。新着（first_seen_at が days 以内）と、新着でない更新（last_changed_at が days 以内）
export function changedItems(next, now, days) {
  const within = (at) => at && daysBetween(at, now) <= days;
  const added = next.items.filter((item) => within(item.first_seen_at));
  const updated = next.items.filter((item) => !within(item.first_seen_at) && within(item.last_changed_at));
  return { added, updated };
}
