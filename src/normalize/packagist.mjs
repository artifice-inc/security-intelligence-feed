import { hasGhsa } from '../collect/packagist.mjs';
import { daysBetween, toIso } from '../lib/time.mjs';
import { loadThresholds } from '../lib/config.mjs';

const OVERLAP_SECONDS = 300; // 差分取得の取りこぼし防止。上書きは冪等なので重複しても害はない

export const emptyPackagist = () => ({ full_sync_at: null, updated_since: null, advisories: {} });

// 初回、または前回の全件取得から7日を過ぎた回は全件（updatedSince=0）
export function planPackagistFetch(previous, now, thresholds = loadThresholds()) {
  const base = previous ?? emptyPackagist();
  const full = !base.full_sync_at || daysBetween(base.full_sync_at, now) >= thresholds.packagist_full_sync_days;
  return { full, updatedSince: full ? 0 : base.updated_since ?? 0 };
}

const toEntry = (r) => ({
  packageName: r.packageName, affectedVersions: r.affectedVersions, cve: r.cve, title: r.title,
  link: r.link, reportedAt: r.reportedAt, sources: r.sources,
});

// GHSA を持つものは OSV の all.zip で照合するので入れない（D5）。取得失敗の回はファイルを変えない
export function applyPackagist({ previous, plan, result, now }) {
  const base = previous ?? emptyPackagist();
  if (!result.ok) return base;
  const advisories = plan.full ? {} : { ...base.advisories };
  for (const record of result.records) {
    if (hasGhsa(record)) { delete advisories[record.advisoryId]; continue; }
    advisories[record.advisoryId] = toEntry(record);
  }
  const sorted = Object.fromEntries(Object.entries(advisories).sort(([a], [b]) => (a < b ? -1 : 1)));
  return {
    full_sync_at: plan.full ? toIso(now) : base.full_sync_at,
    updated_since: Math.floor(new Date(now).getTime() / 1000) - OVERLAP_SECONDS,
    advisories: sorted,
  };
}
