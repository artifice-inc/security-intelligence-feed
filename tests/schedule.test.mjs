import test from 'node:test';
import assert from 'node:assert/strict';
import { lastDueTime, nextScheduledTime, isCentralStale, toUtcCron, slotOf } from '../src/lib/schedule.mjs';
import { loadSchedule } from '../src/lib/config.mjs';

const schedule = loadSchedule(); // JST 07:17 / 16:17、猶予120分
const at = (iso) => new Date(iso);

test('猶予の境界±1分で直近の予定時刻が切り替わる', () => {
  // 07:17 JST = 22:17Z。猶予終了は 09:17 JST = 00:17Z
  assert.equal(lastDueTime(schedule, at('2026-10-25T00:16:00Z')).toISOString(), '2026-10-24T07:17:00.000Z');
  assert.equal(lastDueTime(schedule, at('2026-10-25T00:17:00Z')).toISOString(), '2026-10-24T22:17:00.000Z');
  assert.equal(lastDueTime(schedule, at('2026-10-25T00:18:00Z')).toISOString(), '2026-10-24T22:17:00.000Z');
});

test('夜間の15時間の間隔では正常な成功を stale にしない（試験10b）', () => {
  // 16:17 JST の回が 16:30 JST に成功。翌 07:17 JST+猶予の手前（09:00 JST）まで stale ではない
  const lastSuccess = '2026-10-24T07:30:00Z';
  assert.equal(isCentralStale(lastSuccess, schedule, at('2026-10-24T23:59:00Z')).stale, false);
});

test('予定時刻から猶予を過ぎても成功がなければ stale', () => {
  const lastSuccess = '2026-10-24T07:30:00Z';
  assert.equal(isCentralStale(lastSuccess, schedule, at('2026-10-25T00:30:00Z')).stale, true);
  assert.equal(isCentralStale(null, schedule, at('2026-10-25T00:30:00Z')).stale, true);
});

test('日をまたぐ場合の次の予定時刻', () => {
  assert.equal(nextScheduledTime(schedule, at('2026-10-24T08:00:00Z')).toISOString(), '2026-10-24T22:17:00.000Z');
  assert.equal(nextScheduledTime(schedule, at('2026-10-24T22:30:00Z')).toISOString(), '2026-10-25T07:17:00.000Z');
});

test('UTC の cron へ変換できる', () => {
  const cron = toUtcCron(schedule, at('2026-10-24T00:00:00Z'));
  assert.equal(cron.minute, 17);
  assert.deepEqual(cron.hours, [7, 22]);
});

test('slotOf: 予定時刻ちょうど・直前・直後・日付またぎ・予定の間の手動実行', () => {
  // 07:17 JST = 22:17Z、16:17 JST = 07:17Z
  assert.equal(slotOf(schedule, at('2026-10-24T07:17:00Z')), '2026-10-24T07:17Z');
  assert.equal(slotOf(schedule, at('2026-10-24T07:16:59Z')), '2026-10-23T22:17Z');
  assert.equal(slotOf(schedule, at('2026-10-24T07:18:00Z')), '2026-10-24T07:17Z');
  assert.equal(slotOf(schedule, at('2026-10-24T23:00:00Z')), '2026-10-24T22:17Z');
  assert.equal(slotOf(schedule, at('2026-10-25T00:30:00Z')), '2026-10-24T22:17Z');
  assert.equal(slotOf(schedule, at('2026-10-24T12:00:00Z')), '2026-10-24T07:17Z');
});

test('toUtcCron: offset を指定すると分と時が後ろへずれ、既定は変わらない', () => {
  const ref = at('2026-10-24T00:00:00Z');
  assert.deepEqual(toUtcCron(schedule, ref, { offsetMinutes: 30 }), { minute: 47, hours: [7, 22] });
  assert.deepEqual(toUtcCron(schedule, ref), { minute: 17, hours: [7, 22] });
  assert.equal(schedule.match_offset_minutes, 30);
});
