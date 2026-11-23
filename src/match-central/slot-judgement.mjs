import { SOURCE_NAMES } from '../collect/index.mjs';
import { slotOf, requiredSlot, isAcceptableSlot } from '../lib/schedule.mjs';
import { kevConfirmed, epssState, attemptSlotAcceptable } from '../match/priority-inputs.mjs';

const REASONS = {
  notLatest: 'フィードの最新を使えませんでした',
  noRecord: '公開側の健全性に記録がありません',
  otherSlot: '予定時刻と猶予の間に試行されていません',
  failed: '公開側の直近の取得に失敗しました',
  listMismatch: '一覧の取得日時が健全性の記録と合わない',
  epssThreshold: 'EPSS の一覧が閾値を網羅しない',
};

// targetSlot は受け入れる最も古い予定枠（下限）、latestSlot は判定時刻の予定枠（上限）
function reasonOf({ name, feedMode, targetSlot, latestSlot, feedHealth, kev, epssHigh, now, thresholds, schedule }) {
  if (feedMode !== 'latest') return REASONS.notLatest;
  const entry = feedHealth?.sources?.[name];
  if (!entry) return REASONS.noRecord;
  if (!attemptSlotAcceptable({ entry, feedHealth, targetSlot, latestSlot, schedule })) return REASONS.otherSlot;
  if (entry.last_attempt_ok !== true) return REASONS.failed;
  const base = { feedMode, targetSlot, latestSlot, feedHealth, schedule };
  if (name === 'kev' && !kevConfirmed({ kev, ...base })) return REASONS.listMismatch;
  if (name === 'epss' && epssState({ epssHigh, ...base, now, thresholds }) !== 'fresh') return epssHigh?.threshold > thresholds.epss_percentile_p1 ? REASONS.epssThreshold : REASONS.listMismatch;
  return null;
}

// 情報源ごとの成否（decideScanStatus に渡す形）と、全案件に足す scan_errors を決める。純粋関数
export function judgeSlots({ feedMode, feedHealth, kev, epssHigh, now, thresholds, schedule }) {
  const targetSlot = requiredSlot(schedule, now);
  const latestSlot = slotOf(schedule, now);
  const verdicts = {};
  for (const name of SOURCE_NAMES) {
    const reason = reasonOf({ name, feedMode, targetSlot, latestSlot, feedHealth, kev, epssHigh, now, thresholds, schedule });
    verdicts[name] = reason ? { ok: false, reason } : { ok: true };
  }
  const sourceResults = Object.fromEntries(Object.entries(verdicts).map(([name, v]) => [name, { ok: v.ok }]));
  const extraErrors = [];
  if (feedMode !== 'latest') extraErrors.push({ kind: 'feed', target: 'feed', message: feedMode === 'restored' ? '前回検証したフィードで照合しました（最新を使えません）' : 'フィードを使えないため縮退照合です' });
  else if (!isAcceptableSlot(schedule, feedHealth?.run_slot, { lower: targetSlot, upper: latestSlot })) extraErrors.push({ kind: 'feed', target: 'feed', message: '公開側の収集が予定時刻と猶予の間に実行されていません' });
  return { targetSlot, latestSlot, sourceResults, verdicts, extraErrors };
}
