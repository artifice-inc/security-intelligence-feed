import { slotOf, isAcceptableSlot } from '../lib/schedule.mjs';
import { loadSchedule } from '../lib/config.mjs';
import { NEVER_FETCHED_AT } from '../feed/definition.mjs';
import { computePriority, isHigherPriority, priorityRank } from './priority.mjs';

const MS_PER_HOUR = 3_600_000;
const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low'];
const isValidTime = (text) => typeof text === 'string' && Number.isFinite(Date.parse(text));

const EARLIEST_SLOT = '0000-01-01T00:00Z'; // 条件H では下限を見ない

// 条件H：run_slot が実在し上限以下。下限は見ない
export const runSlotAcceptable = ({ feedHealth, latestSlot, schedule }) =>
  isAcceptableSlot(schedule, feedHealth?.run_slot, { lower: EARLIEST_SLOT, upper: latestSlot });

// 条件H：情報源の試行の枠が実在し run_slot 以下（収集側は run_slot より新しい試行を作れない）
export const healthConsistent = ({ entry, feedHealth, latestSlot, schedule }) =>
  runSlotAcceptable({ feedHealth, latestSlot, schedule })
  && isAcceptableSlot(schedule, entry?.last_attempt_slot, { lower: EARLIEST_SLOT, upper: feedHealth.run_slot });

// 条件S（下限=targetSlot、上限=latestSlot）と条件H を満たす試行の枠か
export const attemptSlotAcceptable = ({ entry, feedHealth, targetSlot, latestSlot, schedule = loadSchedule() }) =>
  healthConsistent({ entry, feedHealth, latestSlot, schedule })
  && isAcceptableSlot(schedule, entry.last_attempt_slot, { lower: targetSlot, upper: latestSlot });

// targetSlot は受け入れる最も古い予定枠（下限）、latestSlot は判定時刻の予定枠（上限）
export const sourceConfirmed = ({ name, feedMode, targetSlot, latestSlot, feedHealth, schedule = loadSchedule() }) => {
  const entry = feedHealth?.sources?.[name];
  return feedMode === 'latest' && Boolean(entry) && entry.last_attempt_ok === true
    && attemptSlotAcceptable({ entry, feedHealth, targetSlot, latestSlot, schedule });
};

// 一覧が「その枠の成功した試行の結果」か。読めない日時は例外にせず false
export function listConfirmed({ name, list, feedMode, targetSlot, latestSlot, feedHealth, schedule = loadSchedule() }) {
  if (!sourceConfirmed({ name, feedMode, targetSlot, latestSlot, feedHealth, schedule })) return false;
  if (!list || list.ok !== true || !isValidTime(list.fetched_at) || list.fetched_at === NEVER_FETCHED_AT) return false;
  const entry = feedHealth.sources[name];
  try {
    return slotOf(schedule, list.fetched_at) === entry.last_attempt_slot && list.fetched_at === entry.last_success_at;
  } catch {
    return false;
  }
}

export const kevConfirmed = (args) => listConfirmed({ name: 'kev', list: args.kev, ...args });

// 健全性と一覧の成否が矛盾しないか（同じ実行が両方を書くので、取得時刻と成否が一致するはず）
function consistentWithHealth(list, entry, { feedHealth, latestSlot, schedule }) {
  if (!healthConsistent({ entry, feedHealth, latestSlot, schedule })) return false;
  if (!entry || list.fetched_at !== entry.last_success_at) return false;
  if (list.ok !== true) return true;
  try {
    return entry.last_attempt_ok === true && entry.last_attempt_slot === slotOf(schedule, list.fetched_at);
  } catch {
    return false;
  }
}

export function epssState({ epssHigh, feedMode, targetSlot, latestSlot, feedHealth, now, thresholds, schedule = loadSchedule() }) {
  if (listConfirmed({ name: 'epss', list: epssHigh, feedMode, targetSlot, latestSlot, feedHealth, schedule }) && epssHigh.threshold <= thresholds.epss_percentile_p1) return 'fresh';
  if (!epssHigh || !isValidTime(epssHigh.fetched_at) || epssHigh.fetched_at === NEVER_FETCHED_AT) return 'expired';
  const ageMs = Date.parse(now) - Date.parse(epssHigh.fetched_at);
  if (ageMs > thresholds.stale_source_hours * MS_PER_HOUR) return 'expired';
  return consistentWithHealth(epssHigh, feedHealth?.sources?.epss, { feedHealth, latestSlot, schedule }) ? 'previous' : 'expired';
}

export function feedSignals({ kev, epssHigh, feedMode, targetSlot, latestSlot, feedHealth, now, thresholds, schedule = loadSchedule() }) {
  const kevIds = new Set((kev?.records ?? []).map((r) => r.cveID));
  const state = epssState({ epssHigh, feedMode, targetSlot, latestSlot, feedHealth, now, thresholds, schedule });
  const highIds = new Set((epssHigh?.records ?? []).filter((r) => r.percentile >= thresholds.epss_percentile_p1).map((r) => r.cve));
  return {
    isKev: (cves) => cves.some((cve) => kevIds.has(cve)),
    isEpssHigh(cves) {
      if (state === 'expired') return null;
      if (cves.some((cve) => highIds.has(cve))) return true;
      return state === 'fresh' ? false : null;
    },
    epssState: state,
    thresholds,
  };
}

export const maxSeverity = (levels) => levels.filter(Boolean).sort((a, b) => SEVERITY_ORDER.indexOf(String(a).toLowerCase()) - SEVERITY_ORDER.indexOf(String(b).toLowerCase()))[0] ?? null;
export const cvesOf = (ids) => ids.filter((id) => id.startsWith('CVE-'));

// previousItems の別名との和集合で KEV・EPSS を引き、前回の最高の優先度を下限にする（自動で下げない）
export function resolvePriority({ previousItems = [], current, signals, ctx, thresholds }) {
  const aliases = [...new Set([...current.aliases, ...previousItems.flatMap((p) => p.aliases)])].sort();
  const inputs = current.priority_inputs ?? {};
  const cves = cvesOf(aliases);
  const kev = signals.isKev(cves) || current.kev === true || previousItems.some((p) => p.kev === true);
  const epssHigh = signals.isEpssHigh(cves);
  const malicious = aliases.some((id) => id.startsWith('MAL-'));
  const priorityInputs = { judgement: current.judgement, kev, severity: inputs.severity ?? null, epss_high: epssHigh, exposure: inputs.exposure ?? null, malicious };
  const computed = computePriority({
    judgement: current.judgement, kev, severity: priorityInputs.severity, epssPercentile: epssHigh === true ? thresholds.epss_percentile_p1 : 0, exposure: priorityInputs.exposure, malicious,
  }, thresholds);
  const floor = previousItems.map((p) => p.priority).filter(Boolean).sort((a, b) => priorityRank(a) - priorityRank(b))[0];
  const keepFloor = floor && isHigherPriority(floor, computed);
  let note;
  if (keepFloor) note = `計算上は ${computed}。自動では下げない（前回の優先度を維持）`;
  else if (previousItems.length === 0 && ctx && ctx.epssState !== 'fresh') note = ctx.feedMode === 'degraded' ? 'KEV・EPSS 未確認' : 'EPSS 未確認';
  return { priority: keepFloor ? floor : computed, ...(note ? { priority_note: note } : {}), priority_inputs: priorityInputs, kev, aliases };
}
