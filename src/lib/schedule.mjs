import { addMinutes } from './time.mjs';

const MS_PER_DAY = 86_400_000;

// 指定タイムゾーンのその瞬間の UTC との差（分）
function zoneOffsetMinutes(utcMs, timeZone) {
  const parts = new Intl.DateTimeFormat('en-US', {
    timeZone, hourCycle: 'h23', year: 'numeric', month: '2-digit', day: '2-digit',
    hour: '2-digit', minute: '2-digit', second: '2-digit',
  }).formatToParts(new Date(utcMs));
  const get = (type) => Number(parts.find((p) => p.type === type).value);
  const asUtc = Date.UTC(get('year'), get('month') - 1, get('day'), get('hour'), get('minute'), get('second'));
  return Math.round((asUtc - Math.floor(utcMs / 1000) * 1000) / 60_000);
}

// タイムゾーンの壁時計時刻（Y-M-D h:m）を UTC のミリ秒へ変換する
function zonedToUtcMs(year, month, day, hour, minute, timeZone) {
  const guess = Date.UTC(year, month - 1, day, hour, minute);
  const first = guess - zoneOffsetMinutes(guess, timeZone) * 60_000;
  return guess - zoneOffsetMinutes(first, timeZone) * 60_000;
}

function parseTime(text) {
  const match = /^(\d{2}):(\d{2})$/.exec(text);
  if (!match) throw new Error(`時刻の形式が不正です: ${text}`);
  return { hour: Number(match[1]), minute: Number(match[2]) };
}

// now を含む前後各1日分の予定時刻（UTC の Date、昇順）
export function scheduledTimesAround(schedule, now) {
  const base = new Date(now);
  const result = [];
  for (let dayShift = -2; dayShift <= 2; dayShift += 1) {
    const day = new Date(base.getTime() + dayShift * MS_PER_DAY);
    const localParts = new Intl.DateTimeFormat('en-CA', {
      timeZone: schedule.timezone, year: 'numeric', month: '2-digit', day: '2-digit',
    }).formatToParts(day);
    const get = (type) => Number(localParts.find((p) => p.type === type).value);
    for (const text of schedule.times) {
      const { hour, minute } = parseTime(text);
      result.push(new Date(zonedToUtcMs(get('year'), get('month'), get('day'), hour, minute, schedule.timezone)));
    }
  }
  return result.sort((a, b) => a - b);
}

// 「猶予を過ぎた直近の予定時刻」。まだ猶予内の予定時刻は含めない
export function lastDueTime(schedule, now) {
  const due = scheduledTimesAround(schedule, now)
    .filter((t) => addMinutes(t, schedule.grace_minutes) <= new Date(now));
  return due.at(-1);
}

export function nextScheduledTime(schedule, now) {
  return scheduledTimesAround(schedule, now).find((t) => t > new Date(now));
}

// 最終成功が「猶予を過ぎた直近の予定時刻」より前なら止まっているとみなす
export function isCentralStale(lastSuccessAt, schedule, now) {
  const due = lastDueTime(schedule, now);
  if (!lastSuccessAt) return { stale: true, expected_after: due.toISOString() };
  return { stale: new Date(lastSuccessAt) < due, expected_after: due.toISOString() };
}

// 手動実行も直前の予定枠に属させる。予定枠は UTC の YYYY-MM-DDTHH:MMZ
export function slotOf(schedule, now) {
  const at = new Date(now);
  const slot = scheduledTimesAround(schedule, at).filter((t) => t <= at).at(-1);
  return slot.toISOString().slice(0, 16) + 'Z';
}

// ワークフローの cron（UTC）用。分が揃っていない予定は表現できないのでエラーにする。offsetMinutes は非公開側の遅らせ分
export function toUtcCron(schedule, referenceDate = new Date(), { offsetMinutes = 0 } = {}) {
  const slots = scheduledTimesAround(schedule, referenceDate)
    .filter((t) => t >= new Date(referenceDate) && t < new Date(new Date(referenceDate).getTime() + MS_PER_DAY))
    .map((t) => addMinutes(t, offsetMinutes));
  const minutes = new Set(slots.map((t) => t.getUTCMinutes()));
  if (minutes.size !== 1) throw new Error('予定時刻の分が揃っていないため cron に変換できません');
  const hours = [...new Set(slots.map((t) => t.getUTCHours()))].sort((a, b) => a - b);
  return { minute: [...minutes][0], hours };
}
