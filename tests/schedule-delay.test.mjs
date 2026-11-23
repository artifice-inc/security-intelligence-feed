import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { requiredSlot, isAcceptableSlot, lastDueTime, scheduledTimesAround, isCentralStale, slotOf } from '../src/lib/schedule.mjs';
import { judgeSlots } from '../src/match-central/slot-judgement.mjs';
import { epssState, kevConfirmed, feedSignals } from '../src/match/priority-inputs.mjs';
import { loadSchedule, loadThresholds } from '../src/lib/config.mjs';
import { makeFeedData, makeMatchHarness, NOW } from './helpers/match-harness.mjs';
import { setup } from './helpers/check-feed-setup.mjs';

const SCHEDULE = loadSchedule();
const THRESHOLDS = { stale_source_hours: 36, epss_percentile_p1: 0.95 };
const PREVIOUS_SLOT_FEED_AT = '2026-11-21T07:47:00Z'; // 枠 2026-11-21T07:17Z の収集（取得 07:20Z）
const MS_PER_MINUTE = 60_000;

function feedOf(options = {}) {
  const dir = makeFeedData(options);
  const read = (rel) => JSON.parse(readFileSync(path.join(dir, rel), 'utf8'));
  return { feedHealth: read('health.json'), kev: read('kev.json'), epssHigh: read('epss-high.json') };
}
const judge = (feed, now = NOW) => judgeSlots({ ...feed, feedMode: 'latest', now, thresholds: THRESHOLDS, schedule: SCHEDULE });
const failedNames = (result) => Object.entries(result.sourceResults).filter(([, v]) => !v.ok).map(([name]) => name);
const hasFeedError = (result) => result.extraErrors.some((e) => e.kind === 'feed');

test('requiredSlot: 07:17 JST（22:17Z）の枠は 19:17 JST（10:17Z）から下限になり、lastDueTime と一致し、日付をまたぐ', () => {
  assert.equal(requiredSlot(SCHEDULE, '2026-11-22T10:16:00Z'), '2026-11-21T07:17Z');
  assert.equal(requiredSlot(SCHEDULE, '2026-11-22T10:17:00Z'), '2026-11-21T22:17Z');
  assert.equal(requiredSlot(SCHEDULE, '2026-11-22T10:18:00Z'), '2026-11-21T22:17Z');
  assert.equal(requiredSlot(SCHEDULE, '2026-11-21T19:17:00Z'), '2026-11-21T07:17Z');
  for (const now of ['2026-11-22T10:16:00Z', '2026-11-22T10:17:00Z', '2026-12-31T23:59:00Z', '2027-01-01T00:30:00Z']) {
    assert.equal(requiredSlot(SCHEDULE, now), lastDueTime(SCHEDULE, now).toISOString().slice(0, 16) + 'Z');
  }
  assert.equal(requiredSlot(SCHEDULE, '2027-01-01T00:30:00Z'), '2026-12-31T07:17Z');
});

test('isAcceptableSlot: 下限・上限・間は true。範囲外・形の違い・null・存在しない日付・予定にない時刻は例外なしで false', () => {
  const now = '2026-11-21T10:16:00Z';
  const lower = requiredSlot(SCHEDULE, now);
  const upper = slotOf(SCHEDULE, now);
  assert.equal(lower, '2026-11-20T07:17Z');
  assert.equal(upper, '2026-11-21T07:17Z');
  const range = { lower, upper };
  for (const slot of ['2026-11-20T07:17Z', '2026-11-20T22:17Z', '2026-11-21T07:17Z']) assert.equal(isAcceptableSlot(SCHEDULE, slot, range), true, slot);
  // 10:17Z ちょうどで最も古い枠だけが外れる
  const later = { lower: requiredSlot(SCHEDULE, '2026-11-21T10:17:00Z'), upper: slotOf(SCHEDULE, '2026-11-21T10:17:00Z') };
  assert.equal(isAcceptableSlot(SCHEDULE, '2026-11-20T07:17Z', later), false);
  assert.equal(isAcceptableSlot(SCHEDULE, '2026-11-20T22:17Z', later), true);
  const bad = ['2026-11-20T07:16Z', '2026-11-21T22:17Z', '2026-11-21T07:17:00Z', '昨日', '', null, undefined, 7, '2026-11-20T22:18Z'];
  for (const slot of bad) assert.equal(isAcceptableSlot(SCHEDULE, slot, range), false, String(slot));
  // 範囲の比較だけなら通る下限・上限でも、存在しない日付は false
  assert.equal(isAcceptableSlot(SCHEDULE, '2026-02-30T22:17Z', { lower: '2026-02-01T00:00Z', upper: '2026-03-31T00:00Z' }), false);
  assert.equal(isAcceptableSlot(SCHEDULE, '2026-11-20T22:17Z', { lower: 'x', upper }), false);
  assert.equal(isAcceptableSlot(SCHEDULE, '2026-11-20T22:17Z', { lower, upper: undefined }), false);
  assert.equal(isAcceptableSlot(SCHEDULE, '2026-11-20T22:17Z'), false);
});

test('設定の整合（不変条件2）: 猶予＋予定の最大の間隔 ≤ stale_source_hours', () => {
  const times = scheduledTimesAround(SCHEDULE, '2026-11-21T00:00:00Z');
  const maxGapHours = Math.max(...times.slice(1).map((t, i) => (t - times[i]) / (60 * MS_PER_MINUTE)));
  assert.equal(maxGapHours, 15);
  assert.ok(SCHEDULE.grace_minutes / 60 + maxGapHours <= loadThresholds().stale_source_hours);
});

test('猶予の中の遅れ: run_slot・試行・KEV と EPSS がすべて前の枠の成功なら、中央は success で完了通知を送り、手元は complete: true', async () => {
  const result = judge(feedOf({ now: PREVIOUS_SLOT_FEED_AT }));
  assert.deepEqual(result.extraErrors, []);
  assert.deepEqual(failedNames(result), []);
  const h = makeMatchHarness();
  const out = await h.match({ feedOptions: { now: PREVIOUS_SLOT_FEED_AT } });
  assert.equal(out.status, 'success');
  assert.equal(h.state.heartbeats, 1);
  const local = setup({ feedOptions: { now: PREVIOUS_SLOT_FEED_AT } });
  const output = await local.run();
  assert.equal(output.local_scan.complete, true);
  assert.equal(output.central_health.stale, false);
});

test('run_slot と試行の枠の整合（条件H）: run_slot が前の枠で試行・一覧が新しい枠なら、中央は partial で通知なし、手元は complete: false', async () => {
  const options = { health: { run_slot: '2026-11-21T07:17Z' } };
  const result = judge(feedOf(options));
  assert.equal(failedNames(result).length > 0, true);
  assert.equal(kevConfirmed({ kev: feedOf(options).kev, feedMode: 'latest', targetSlot: result.targetSlot, latestSlot: result.latestSlot, feedHealth: feedOf(options).feedHealth, schedule: SCHEDULE }), false);
  const h = makeMatchHarness();
  const out = await h.match({ feedOptions: options });
  assert.equal(out.status, 'partial');
  assert.equal(h.state.heartbeats, 0);
  assert.equal((await setup({ feedOptions: options }).run()).local_scan.complete, false);
});

test('EPSS: run_slot が上限より後でも、run_slot が前の枠で一覧が新しい枠でも fresh にも previous にもならない（expired）', () => {
  const state = (feed) => epssState({ epssHigh: feed.epssHigh, feedMode: 'latest', targetSlot: requiredSlot(SCHEDULE, NOW), latestSlot: slotOf(SCHEDULE, NOW), feedHealth: feed.feedHealth, now: NOW, thresholds: THRESHOLDS, schedule: SCHEDULE });
  assert.equal(state(feedOf()), 'fresh');
  assert.equal(state(feedOf({ health: { run_slot: '2026-11-22T07:17Z' } })), 'expired', 'run_slot が上限より後');
  assert.equal(state(feedOf({ health: { run_slot: '2026-11-21T07:17Z' } })), 'expired', '試行が run_slot より新しい');
  // その一覧にだけ載る CVE でも優先度を上げない（isEpssHigh が一覧の行を使わない）
  const signals = (feed) => feedSignals({ kev: feed.kev, epssHigh: feed.epssHigh, feedMode: 'latest', targetSlot: requiredSlot(SCHEDULE, NOW), latestSlot: slotOf(SCHEDULE, NOW), feedHealth: feed.feedHealth, now: NOW, thresholds: THRESHOLDS, schedule: SCHEDULE });
  const rows = [['CVE-2026-9', 0.99]];
  assert.equal(signals(feedOf({ epssRows: rows })).isEpssHigh(['CVE-2026-9']), true, '対照：整合していれば上位');
  for (const run_slot of ['2026-11-22T07:17Z', '2026-11-21T07:17Z']) {
    assert.equal(signals(feedOf({ epssRows: rows, health: { run_slot } })).isEpssHigh(['CVE-2026-9']), null, run_slot);
  }
});

test('猶予の中でも失敗は失敗（不変条件4）: 前の枠の試行で php-ghsa が失敗 → 全体は partial', async () => {
  const feed = feedOf({ now: PREVIOUS_SLOT_FEED_AT, failing: ['php-ghsa'] });
  assert.deepEqual(failedNames(judge(feed)), ['php-ghsa']);
  const h = makeMatchHarness();
  assert.equal((await h.match({ feedOptions: { now: PREVIOUS_SLOT_FEED_AT, failing: ['php-ghsa'] } })).status, 'partial');
});

test('猶予を過ぎた: 2026-11-21T07:17Z の枠のフィードは 10:16Z まで受け入れ、10:17Z から partial・stale: true', async () => {
  const feed = feedOf({ now: PREVIOUS_SLOT_FEED_AT });
  const slotNow = (iso) => judge(feed, iso);
  assert.deepEqual(slotNow('2026-11-22T10:16:00Z').extraErrors, []);
  assert.deepEqual(failedNames(slotNow('2026-11-22T10:16:00Z')), []);
  const late = slotNow('2026-11-22T10:17:00Z');
  assert.equal(hasFeedError(late), true);
  assert.equal(failedNames(late).length > 0, true);
  for (const [iso, expected] of [['2026-11-22T10:16:00Z', false], ['2026-11-22T10:17:00Z', true]]) {
    const s = setup({ feedOptions: { now: PREVIOUS_SLOT_FEED_AT } });
    s.deps.now = new Date(iso);
    const output = await s.run();
    assert.equal(output.central_health.stale, expected, iso);
    assert.equal(output.local_scan.complete, !expected, iso);
  }
});

test('未来の枠: run_slot・試行の枠が上限より後 → 中央は partial、手元は complete: false', async () => {
  const future = { now: '2026-11-22T08:00:00Z' }; // 枠 2026-11-22T07:17Z は NOW（22:47Z）から見て未来
  const result = judge(feedOf(future));
  assert.equal(hasFeedError(result), true);
  assert.equal(failedNames(result).length > 0, true);
  const h = makeMatchHarness();
  assert.equal((await h.match({ feedOptions: future })).status, 'partial');
  assert.equal((await setup({ feedOptions: future }).run()).local_scan.complete, false);
});

test('取得中に新しい枠をまたいだ: 開始 22:16Z・収集の開始 22:17Z・取得直後 22:20Z → 中央で受け入れ、success', async () => {
  const h = makeMatchHarness();
  const out = await h.match({ now: '2026-11-21T22:16:00Z', feedOptions: { now: '2026-11-21T22:45:00Z' }, deps: { clock: () => new Date('2026-11-21T22:20:00Z') } });
  assert.equal(out.status, 'success');
  assert.equal(h.state.heartbeats, 1);
});

test('取得中に猶予の満了をまたいだ: 開始 10:16Z・取得直後 10:20Z → 中央は partial で通知なし、手元（10:20Z）も complete: false・stale: true', async () => {
  const h = makeMatchHarness();
  const out = await h.match({ now: '2026-11-22T10:16:00Z', feedOptions: { now: PREVIOUS_SLOT_FEED_AT }, deps: { clock: () => new Date('2026-11-22T10:20:00Z') } });
  assert.equal(out.status, 'partial');
  assert.equal(h.state.heartbeats, 0);
  const s = setup({ feedOptions: { now: PREVIOUS_SLOT_FEED_AT } });
  s.deps.now = new Date('2026-11-22T10:20:00Z');
  const output = await s.run();
  assert.equal(output.local_scan.complete, false);
  assert.equal(output.central_health.stale, true);
  assert.ok(output.scan_errors.some((e) => e.kind === 'feed'));
});

test('実行が1回抜けたとき（§5）: C が 19:17 JST（10:17Z）より前に成功なら partial にならず、後なら C の成功まで partial・stale', () => {
  const lastSuccessA = '2026-11-20T07:20:00Z'; // 枠 A（16:17 JST）。枠 B（07:17 JST）は抜けた
  const beforeGrace = '2026-11-21T10:16:00Z';
  const afterGrace = '2026-11-21T10:17:00Z';
  const feedA = feedOf({ now: '2026-11-20T07:47:00Z' });
  assert.equal(isCentralStale(lastSuccessA, SCHEDULE, beforeGrace).stale, false);
  assert.deepEqual(judge(feedA, beforeGrace).extraErrors, []);
  assert.equal(isCentralStale(lastSuccessA, SCHEDULE, afterGrace).stale, true);
  assert.equal(hasFeedError(judge(feedA, afterGrace)), true);
  // C（2026-11-21T07:17Z の枠）が成功すれば、また受け入れる
  const feedC = feedOf({ now: PREVIOUS_SLOT_FEED_AT });
  assert.deepEqual(judge(feedC, afterGrace).extraErrors, []);
  assert.equal(isCentralStale('2026-11-21T07:20:00Z', SCHEDULE, afterGrace).stale, false);
});

test('一覧と試行の枠の食い違い（不変条件5）: 試行の枠が 22:17Z で一覧の取得と last_success_at が 08:00Z → KEV は未確認、EPSS は fresh にならない', () => {
  const feed = feedOf();
  const earlier = '2026-11-21T08:00:00Z';
  for (const name of ['kev', 'epss']) feed.feedHealth.sources[name].last_success_at = earlier;
  feed.kev.fetched_at = earlier;
  feed.epssHigh.fetched_at = earlier;
  const result = judge(feed);
  assert.deepEqual(failedNames(result).sort(), ['epss', 'kev']);
  const state = epssState({ epssHigh: feed.epssHigh, feedMode: 'latest', targetSlot: result.targetSlot, latestSlot: result.latestSlot, feedHealth: feed.feedHealth, now: NOW, thresholds: THRESHOLDS, schedule: SCHEDULE });
  assert.notEqual(state, 'fresh');
});
