import { flatAliases } from '../lib/aliases.mjs';
import { toIso } from '../lib/time.mjs';

// KEV・EPSS・国内注意喚起を、現行のアドバイザリへ付与する（D3: 照合で見つかったアドバイザリへの KEV フラグ付与）
// kevRecords / epssRecords が null の回（取得失敗）は、その項目を前回のまま残す
// clearMissingEpss: 上位だけを取得する公開側用。取得に成功した回に、一覧に無い CVE の EPSS を空に戻す（古い値を残さない）
const EMPTY_EPSS = { score: null, percentile: null, date: null };
export function enrichAdvisories({ advisories, kevRecords, epssRecords, jpItems, now, clearMissingEpss = false }) {
  const kev = new Map((kevRecords ?? []).map((r) => [r.cveID, r]));
  const epss = new Map((epssRecords ?? []).map((r) => [r.cve, r]));
  const changed = new Map();
  for (const advisory of advisories.filter((a) => !a.superseded_by)) {
    const cves = advisory.aliases.cve;
    const hit = cves.map((c) => kev.get(c)).find(Boolean);
    const score = cves.map((c) => epss.get(c)).filter(Boolean).sort((a, b) => b.percentile - a.percentile)[0];
    const alerts = jpItems.filter((i) => i.cves.some((c) => cves.includes(c)))
      .map((i) => ({ source: i.source, id: i.id, title: i.title, link: i.link })).sort((a, b) => (a.source + a.id < b.source + b.id ? -1 : 1));
    const missingEpss = clearMissingEpss && epssRecords !== null ? { ...EMPTY_EPSS } : advisory.epss;
    const next = {
      ...advisory,
      known_exploited: kevRecords === null ? advisory.known_exploited
        : hit ? { kev: true, date_added: hit.dateAdded } : { kev: false, date_added: null },
      epss: score ? { score: score.epss, percentile: score.percentile, date: score.score_date?.slice(0, 10) ?? null } : missingEpss,
      jp_alerts: alerts,
    };
    if (next.known_exploited.kev !== advisory.known_exploited.kev) {
      next.history = [...advisory.history, { at: toIso(now), changes: ['kev'], significant: true }];
    }
    if (JSON.stringify(next) !== JSON.stringify(advisory)) changed.set(advisory.key, next);
  }
  return changed;
}

// EPSS は保存済みアドバイザリと KEV 新着の CVE だけを残す（収集側の絞り込み用）
export const wantedCves = (advisories, kevRecords) =>
  new Set([...advisories.flatMap((a) => flatAliases(a).filter((id) => id.startsWith('CVE-'))), ...kevRecords.map((r) => r.cveID)]);
