import { guarded, okResult, expect } from './result.mjs';

export const INDEX_URL = 'https://explore.alas.aws.amazon.com/index.json';
export const detailUrl = (cveId) => `https://explore.alas.aws.amazon.com/${cveId}.json`;

const MIN_INDEX_SIZE = 1000; // これ未満なら書式の変化とみなす
const KERNEL_DESCRIPTION = /^In the Linux kernel/;
const CVE_ID = /^CVE-\d{4}-\d+$/;
const NOT_FOUND_RATIO_LIMIT = 0.05;
const MS_PER_DAY = 86_400_000;

const keyOf = (entry) => `${entry.modified_date} ${entry.cve_id}`;
const compareEntries = (a, b) => (keyOf(a) < keyOf(b) ? -1 : keyOf(a) > keyOf(b) ? 1 : 0);
const cursorKey = (cursor) => `${cursor.modified_date} ${cursor.cve_id}`;
const utcDate = (now) => new Date(now).toISOString().slice(0, 10);
const dayBefore = (date) => new Date(new Date(`${date}T00:00:00Z`).getTime() - MS_PER_DAY).toISOString().slice(0, 10);

// 同時に concurrency 件ずつ処理する。結果は入力と同じ順で返す
async function mapLimit(items, concurrency, work) {
  const results = new Array(items.length);
  let next = 0;
  const worker = async () => {
    while (next < items.length) {
      const index = next;
      next += 1;
      results[index] = await work(items[index]);
    }
  };
  await Promise.all(Array.from({ length: Math.min(concurrency, items.length) }, worker));
  return results;
}

// 取得する CVE を決める。maxPerRun で切るのは「続き」だけ（他の集合は取りこぼし防止のため全件）
export function planFetch({ index, previous, kevLinuxCves, maxPerRun }) {
  const kev = kevLinuxCves ?? new Set();
  const targets = index.filter((e) => KERNEL_DESCRIPTION.test(e.description ?? '') || kev.has(e.cve_id)).sort(compareEntries);
  const cursor = previous?.cursor ?? null;
  const rest = (cursor ? targets.filter((e) => keyOf(e) > cursorKey(cursor)) : targets).slice(0, maxPerRun);
  const since = previous?.last_success_date ? dayBefore(previous.last_success_date) : null;
  const recent = since ? targets.filter((e) => e.modified_date >= since) : [];
  const inIndex = new Map(index.map((e) => [e.cve_id, e]));
  const kevEntries = [...kev].filter((id) => inIndex.has(id)).map((id) => inIndex.get(id));
  const retryEntries = (previous?.retry ?? []).filter((r) => inIndex.has(r.cve)).map((r) => inIndex.get(r.cve));
  const ids = [...new Set([...rest, ...recent, ...kevEntries, ...retryEntries].map((e) => e.cve_id))].sort();
  return { ids, rest, exhausted: rest.length < maxPerRun };
}

export const collect = ({ http, now, previous = null, kevLinuxCves = new Set(), maxPerRun = 4000, concurrency = 8 }) => guarded(async () => {
  const raw = await http.getJson(INDEX_URL);
  expect(Array.isArray(raw) && raw.length >= MIN_INDEX_SIZE, 'ALAS: index.json の形式が想定と違います');
  // URL に入れる前に ID を検査する。不正な要素は無視する
  const index = raw.filter((e) => CVE_ID.test(e?.cve_id ?? '') && typeof e.modified_date === 'string');

  const plan = planFetch({ index, previous, kevLinuxCves, maxPerRun });
  const today = utcDate(now);
  const outcomes = await mapLimit(plan.ids, concurrency, async (id) => {
    try {
      const raw = await http.getJson(detailUrl(id));
      expect(raw?.cve_id === id && Array.isArray(raw.affected_packages), `ALAS: ${id} の形式が不正です`);
      return { id, raw };
    } catch (error) {
      if (error.http_status === 404) return { id, notFound: true };
      throw error;
    }
  });
  const missing = outcomes.filter((o) => o.notFound);
  expect(missing.length <= plan.ids.length * NOT_FOUND_RATIO_LIMIT, `ALAS: 404 が多すぎます（${missing.length}/${plan.ids.length}件）`);

  const sinceOf = new Map((previous?.retry ?? []).map((r) => [r.cve, r.since]));
  const retry = missing.map((o) => ({ cve: o.id, since: sinceOf.get(o.id) ?? today })).sort((a, b) => (a.cve < b.cve ? -1 : 1));
  const last = plan.rest.at(-1);
  return okResult(outcomes.filter((o) => o.raw).map((o) => o.raw), {
    meta: {
      cursor: last ? { modified_date: last.modified_date, cve_id: last.cve_id } : previous?.cursor ?? null,
      backfill_complete: previous?.backfill_complete === true || plan.exhausted,
      last_success_date: today, retry, index_total: raw.length,
    },
  });
});
