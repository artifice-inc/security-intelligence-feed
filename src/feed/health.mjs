import { SOURCE_NAMES } from '../collect/index.mjs';
import { slotOf } from '../lib/schedule.mjs';

// 公開側の health.json。feed-health.schema.json の項目だけを明示的に組み立てる（projects・osv_db・自由文を持ち込まない）
export function buildFeedHealth({ previous, now, startedAt, status, schedule, sourceResults = {}, optionalResults = {}, packagistUpdatedSince }) {
  const runSlot = slotOf(schedule, startedAt);
  const slotOrNull = (iso) => (iso ? slotOf(schedule, iso) : null);

  // 前回の値を公開の形に直して引き継ぐ（試行の記録がないものは null）。旧形式（中央の health.json）の値も受ける
  const carry = (before) => (before?.last_attempt_at ? {
    last_attempt_at: before.last_attempt_at,
    last_success_at: before.last_success_at ?? null,
    last_attempt_slot: before.last_attempt_slot ?? slotOrNull(before.last_attempt_at),
    last_success_slot: before.last_success_slot ?? slotOrNull(before.last_success_at),
    last_attempt_ok: before.last_attempt_ok ?? !before.last_error,
    last_error: before.last_error ? { kind: before.last_error.kind, at: before.last_error.at } : null,
  } : null);

  const attempt = (before, result) => {
    const prior = carry(before);
    if (result.ok) {
      return { last_attempt_at: now, last_success_at: now, last_attempt_slot: runSlot, last_success_slot: runSlot, last_attempt_ok: true, last_error: null };
    }
    return {
      last_attempt_at: now, last_success_at: prior?.last_success_at ?? null, last_attempt_slot: runSlot,
      last_success_slot: prior?.last_success_slot ?? null, last_attempt_ok: false, last_error: { kind: result.error?.kind ?? 'unknown', at: now },
    };
  };

  const build = (names, before, results) => Object.fromEntries(names
    .map((name) => [name, results[name] ? attempt(before?.[name], results[name]) : carry(before?.[name])])
    .filter(([, entry]) => entry));

  const optionalNames = [...new Set([...Object.keys(previous?.optional_sources ?? {}), ...Object.keys(optionalResults)])];
  const optionalSources = build(optionalNames, previous?.optional_sources, optionalResults);
  return {
    run_slot: runSlot,
    last_run: { started_at: startedAt, finished_at: now, status },
    last_success_at: status === 'success' ? now : previous?.last_success_at ?? null,
    sources: build(SOURCE_NAMES, previous?.sources, sourceResults),
    ...(Object.keys(optionalSources).length > 0 ? { optional_sources: optionalSources } : {}),
    packagist_updated_since: packagistUpdatedSince ?? previous?.packagist_updated_since ?? null,
  };
}
