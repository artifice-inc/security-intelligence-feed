import { feedSignals } from '../../src/match/priority-inputs.mjs';
import { assembleItems, buildAdvisoryIndex } from '../../src/match/assemble.mjs';
import { mergeFindings } from '../../src/match/findings-merge.mjs';
import { reconcileIssues } from '../../src/publish/issues-reconcile.mjs';
import { requiredSlot, slotOf } from '../../src/lib/schedule.mjs';
import { loadSchedule } from '../../src/lib/config.mjs';
import { FakeGitHub } from './fake-github.mjs';

export const SCHEDULE = loadSchedule();
export const THRESHOLDS = { stale_source_hours: 36, epss_percentile_p1: 0.95 };
export const T0 = '2026-11-20T07:30:00Z';
export const NOW = '2026-11-21T07:30:00Z';
export const SLOT = '2026-11-21T07:17Z';
export const FETCHED = '2026-11-21T07:20:00Z';
const PROVENANCE = { scanner_version: '1', script_version: 's', osv_db: {}, inventory_commit: 'c' };

const healthEntry = (ok, successAt) => ({ last_attempt_at: FETCHED, last_success_at: successAt, last_attempt_slot: SLOT, last_success_slot: SLOT, last_attempt_ok: ok, last_error: null });

// 架空の KEV・EPSS からシグナルを作る。epss: 'fresh' | 'previous' | 'expired'
export function makeSignals({ kev = [], epssRows = [], epss = 'fresh', feedMode = 'latest', epssThreshold = 0.5, thresholds = THRESHOLDS } = {}) {
  const old = epss === 'expired' ? '2026-11-10T07:20:00Z' : '2026-11-21T00:20:00Z';
  const fetchedAt = epss === 'fresh' ? FETCHED : old;
  return feedSignals({
    kev: { fetched_at: FETCHED, ok: true, records: kev.map((cveID) => ({ cveID })) },
    epssHigh: { fetched_at: fetchedAt, ok: epss === 'fresh', threshold: epssThreshold, records: epssRows.map(([cve, percentile]) => ({ cve, epss: 0.5, percentile })) },
    feedMode, targetSlot: requiredSlot(SCHEDULE, NOW), latestSlot: slotOf(SCHEDULE, NOW), now: NOW, thresholds, schedule: SCHEDULE,
    feedHealth: { run_slot: SLOT, sources: { kev: healthEntry(true, FETCHED), epss: healthEntry(epss === 'fresh', fetchedAt) } },
  });
}

export const detection = (aliases, extra = {}) => ({
  aliases, judgement: 'affected', lockfile: 'package-lock.json', package: 'pkg', ecosystem: 'npm', installed_version: '1.0.0',
  fixed_versions: ['1.0.1'], severity_hint: null, title: 'Example', osv_id: aliases[0], source_urls: [], ...extra,
});
export const advisory = (key, { cve = [], ghsa = [], severity = null } = {}) => ({
  key, aliases: { cve, ghsa, other: [] }, sources: [], severity: { level: severity }, known_exploited: { kev: false }, title: key, affected: [],
});

export const assemble = (detections, { signals, advisories = [], now = NOW, exposure = 'internet' } = {}) => assembleItems({
  detections, index: buildAdvisoryIndex(advisories), exposure, now, provenance: PROVENANCE, signals,
});

export const statusOf = (scanStatus, scannedAt = NOW) => ({
  project: 'demo', monitor_ref: 'main', inventory_status: 'fresh', scan_status: scanStatus, scan_errors: [], provenance: PROVENANCE, scanned_at: scannedAt, inventory_as_of: scannedAt,
});

// 前回の findings（Issue 起票済み）を作り、今回の検出を統合して reconcile する。戻り値で優先度・番号・Issue のラベルまで確かめる
export async function runTwoRounds({ previousItems, detections, scanStatus = 'complete', signals, advisories = [], ctx = null, exposure = 'internet' }) {
  const api = new FakeGitHub();
  const projects = [{ project: 'demo', owners: ['alice'] }];
  const first = { ...statusOf('complete', T0), items: previousItems };
  const firstResult = await reconcileIssues({ api, projects, findingsByProject: new Map([['demo', first]]), now: T0 });
  const numbered = previousItems.map((item) => ({ ...item, issue_number: item.issue_number ?? firstResult.issueNumbers.get('demo').get(item.advisory_key) ?? null }));
  const current = assemble(detections, { signals, advisories, exposure });
  const findings = mergeFindings({ previous: { ...first, items: numbered }, current, status: statusOf(scanStatus), signals, ctx });
  const result = await reconcileIssues({ api, projects, findingsByProject: new Map([['demo', findings]]), now: NOW });
  return { findings, api, result, numbered };
}

export const storedItem = (key, aliases, extra = {}) => ({
  advisory_key: key, aliases, title: key, fixed_versions: ['1.0.1'], source_urls: [], judgement: 'affected', priority: 'P2', evidence: 'e', kev: false,
  issue_number: null, first_detected_at: T0, last_confirmed_at: T0, last_confirmed_provenance: PROVENANCE,
  locations: [{ lockfile: 'package-lock.json', package: 'pkg', ecosystem: 'npm', installed_version: '1.0.0', last_confirmed_at: T0, last_confirmed_provenance: PROVENANCE }], ...extra,
});
export const ctxOf = (signals, feedMode = 'latest') => ({ epssState: signals.epssState, feedMode });
export const priorityLabels = (api) => [...api.issues.values()].filter((i) => i.state === 'open').map((i) => i.labels.find((l) => /^P[0-3]$/.test(l)));
