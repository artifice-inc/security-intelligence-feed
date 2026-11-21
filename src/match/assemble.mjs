import { connectedComponents, canonicalKey } from '../lib/aliases.mjs';
import { computePriority } from './priority.mjs';
import { resolvePriority, cvesOf } from './priority-inputs.mjs';
import { dedupeValued, compactValues } from './location-values.mjs';

const locationOrder = (a, b) => a.lockfile.localeCompare(b.lockfile) || a.package.localeCompare(b.package) || String(a.installed_version).localeCompare(String(b.installed_version));
const uniq = (values) => [...new Set(values)].sort();

// alias → 現行アドバイザリ。superseded のものは除く
export function buildAdvisoryIndex(advisories) {
  const index = new Map();
  for (const advisory of advisories.filter((a) => !a.superseded_by)) {
    for (const id of [advisory.key, ...advisory.aliases.cve, ...advisory.aliases.ghsa, ...advisory.aliases.other]) index.set(id, advisory);
  }
  return index;
}

// 検出（場所ごと）を、別名の連結成分ごとの findings item にまとめる（同じ脆弱性は1件）
export function assembleItems({ detections: rawDetections, index, exposure, now, provenance, signals = null }) {
  // 新しい経路：CVE と GHSA で別々に検出した同じ脆弱性が1項目になるよう、索引の別名を先に足す
  const detections = signals ? rawDetections.map((d) => ({ ...d, aliases: uniq(d.aliases.flatMap((id) => { const a = index.get(id); return a ? [id, a.key, ...a.aliases.cve, ...a.aliases.ghsa] : [id]; })) })) : rawDetections;
  const groups = connectedComponents(detections.map((d) => d.aliases));
  const items = groups.map((group) => {
    const members = group.indexes.map((i) => detections[i]);
    const advisory = group.ids.map((id) => index.get(id)).find(Boolean) ?? null;
    const malicious = group.ids.some((id) => id.startsWith('MAL-'));
    const judgement = members.some((m) => m.judgement === 'affected') ? 'affected' : 'needs_review';
    // カーネルの CVE は data/advisories にないので、検出側の kev_hint も見る
    const advisoryKev = advisory?.known_exploited?.kev === true || members.some((m) => m.kev_hint === true);
    const kev = signals ? advisoryKev || signals.isKev(cvesOf(group.ids)) : advisoryKev;
    const severity = advisory?.severity?.level ?? members.map((m) => m.severity_hint).find(Boolean) ?? null;
    const located = members.filter((m) => m.lockfile ?? m.locations).flatMap((m) => (m.locations ?? [{
      lockfile: m.lockfile, package: m.package, ecosystem: m.ecosystem, installed_version: m.installed_version,
    }]).map((l) => ({ l, m })));
    // CPython と依存パッケージの両方で検出された item（混在 item）に限り、箇所ごとの修正版と判定を持たせる。
    // 混在でない item には足さない（既存の findings を変えないため）
    const mixed = !signals && located.some(({ l }) => l.ecosystem === 'runtime') && located.some(({ l }) => l.ecosystem !== 'runtime');
    const locations = located.map(({ l, m }) => ({
      ...l, ...(mixed ? { fixed_versions: uniq(m.fixed_versions ?? []), judgement: m.judgement } : {}), last_confirmed_at: now, last_confirmed_provenance: provenance,
    }));
    const seen = new Set();
    const valuedLocations = signals ? located.map(({ l, m }) => ({ ...l, fixed_versions: uniq(m.fixed_versions ?? []), judgement: m.judgement, last_confirmed_at: now, last_confirmed_provenance: provenance })) : [];
    const uniqueLocations = signals ? compactValues(dedupeValued(valuedLocations)) : locations.filter((l) => { const key = `${l.lockfile}|${l.package}|${l.installed_version}`; if (seen.has(key)) return false; seen.add(key); return true; }).sort(locationOrder);
    const key = advisory?.key ?? canonicalKey(group.ids);
    const aliases = uniq([...group.ids, ...(advisory ? [advisory.key] : [])]);
    const base = {
      advisory_key: key,
      aliases,
      title: advisory?.title ?? members[0].title,
      locations: uniqueLocations,
      fixed_versions: uniq(members.flatMap((m) => m.fixed_versions ?? [])),
      source_urls: uniq([...members.flatMap((m) => m.source_urls ?? []), ...(advisory?.sources ?? []).filter((s) => !s.withdrawn_at).map((s) => s.url)].filter(Boolean)),
      judgement,
      priority: computePriority({ judgement, kev, severity, epssPercentile: advisory?.epss?.percentile, exposure, malicious }),
      evidence: members.map((m) => m.evidence ?? `${m.lockfile}: ${m.package}@${m.installed_version} は ${m.osv_id} の影響範囲内${m.reason ? `（${m.reason}）` : ''}`).sort()[0],
      kev, issue_number: null, first_detected_at: now,
      last_confirmed_at: now, last_confirmed_provenance: provenance,
    };
    if (!signals) return base;
    // 深刻度は索引のアドバイザリ、なければ検出の severity_hint。mergeFindings が束ねるときの入力として項目に残す
    const priorityInputs = { severity, exposure };
    const resolved = resolvePriority({ current: { ...base, priority_inputs: priorityInputs }, signals, thresholds: signals.thresholds });
    return { ...base, kev: resolved.kev, priority: resolved.priority, priority_inputs: { ...resolved.priority_inputs } };
  });
  return items.sort((a, b) => (a.advisory_key < b.advisory_key ? -1 : 1));
}
