import test from 'node:test';
import assert from 'node:assert/strict';
import { listConfirmed, epssState, feedSignals } from '../src/match/priority-inputs.mjs';
import { makeSignals, assemble, detection, advisory, runTwoRounds, ctxOf, storedItem, SCHEDULE, THRESHOLDS, SLOT, FETCHED, NOW } from './helpers/priority-fixtures.mjs';

const health = (overrides = {}) => ({ sources: { epss: { last_attempt_slot: SLOT, last_success_at: FETCHED, last_attempt_ok: true, ...overrides } } });
const list = (overrides = {}) => ({ fetched_at: FETCHED, ok: true, threshold: 0.5, records: [], ...overrides });
const confirmed = (l, h = health(), feedMode = 'latest') => listConfirmed({ name: 'epss', list: l, feedMode, targetSlot: SLOT, feedHealth: h, schedule: SCHEDULE });

test('listConfirmed: その枠の成功した試行の一覧だけが true。日時が読めない・NEVER・別の枠・取得時刻の不一致・latest 以外は false（例外にしない）', () => {
  assert.equal(confirmed(list()), true);
  assert.equal(confirmed(list({ fetched_at: 'not-a-date' })), false);
  assert.equal(confirmed(list({ fetched_at: '1970-01-01T00:00:00Z' }), health({ last_success_at: '1970-01-01T00:00:00Z' })), false);
  assert.equal(confirmed(list({ fetched_at: '2026-11-20T07:20:00Z' }), health({ last_success_at: '2026-11-20T07:20:00Z' })), false);
  assert.equal(confirmed(list({ fetched_at: '2026-11-21T07:25:00Z' })), false, '同じ枠の別の試行');
  assert.equal(confirmed(list({ ok: false })), false);
  assert.equal(confirmed(list(), health({ last_attempt_ok: false })), false);
  assert.equal(confirmed(list(), health(), 'degraded'), false);
  assert.equal(confirmed(null), false);
});

test('epssState: fresh・previous・expired（期限切れ・ファイルなし・矛盾・NEVER）', () => {
  const state = (l, h = health()) => epssState({ epssHigh: l, feedMode: 'latest', targetSlot: SLOT, feedHealth: h, now: NOW, thresholds: THRESHOLDS, schedule: SCHEDULE });
  assert.equal(state(list()), 'fresh');
  assert.equal(state(list({ threshold: 0.99 })), 'previous', '一覧が消費側の閾値を網羅しない');
  const failed = list({ ok: false, fetched_at: '2026-11-21T00:20:00Z' });
  assert.equal(state(failed, health({ last_attempt_ok: false, last_success_at: failed.fetched_at })), 'previous');
  assert.equal(state(failed, health({ last_attempt_ok: false, last_success_at: '2026-11-20T00:00:00Z' })), 'expired', '健全性と矛盾');
  assert.equal(state(list({ ok: false, fetched_at: '2026-11-10T00:00:00Z' }), health({ last_attempt_ok: false, last_success_at: '2026-11-10T00:00:00Z' })), 'expired');
  assert.equal(state(null), 'expired');
  assert.equal(state(list({ ok: false, fetched_at: '1970-01-01T00:00:00Z' })), 'expired');
});

test('isEpssHigh は消費する側の閾値で判定する（公開側 0.90・非公開側 0.95、百分位 0.92 は fresh のとき上位でない）。expired は一覧の行も使わない', () => {
  const fresh = makeSignals({ epssRows: [['CVE-9', 0.92]], epssThreshold: 0.9 });
  assert.equal(fresh.epssState, 'fresh');
  assert.equal(fresh.isEpssHigh(['CVE-9']), false);
  const expired = makeSignals({ epssRows: [['CVE-9', 0.99]], epss: 'expired' });
  assert.equal(expired.epssState, 'expired');
  assert.equal(expired.isEpssHigh(['CVE-9']), null);
  const previous = makeSignals({ epssRows: [['CVE-9', 0.99]], epss: 'previous' });
  assert.equal(previous.isEpssHigh(['CVE-9']), true);
  assert.equal(previous.isEpssHigh(['CVE-8']), null);
  assert.equal(feedSignals({ kev: null, epssHigh: null, feedMode: 'latest', targetSlot: SLOT, feedHealth: null, now: NOW, thresholds: THRESHOLDS, schedule: SCHEDULE }).isKev(['CVE-1']), false);
});

test('CVE と GHSA で別々に検出した同じ脆弱性は1項目。GHSA だけを検出し CVE が索引にしかない KEV の脆弱性は P0', () => {
  const advisories = [advisory('CVE-1', { cve: ['CVE-1'], ghsa: ['GHSA-a'] })];
  const signals = makeSignals({ kev: ['CVE-1'] });
  const joined = assemble([detection(['CVE-1']), detection(['GHSA-a'], { package: 'other' })], { signals, advisories });
  assert.equal(joined.length, 1);
  assert.equal(joined[0].locations.length, 2);
  assert.equal(assemble([detection(['GHSA-a'])], { signals, advisories })[0].priority, 'P0');
});

test('affected は保存後に KEV に載れば P0、needs_review は P3 のまま', () => {
  const signals = makeSignals({ kev: ['CVE-1'] });
  assert.equal(assemble([detection(['CVE-1'])], { signals })[0].priority, 'P0');
  assert.equal(assemble([detection(['CVE-1'], { judgement: 'needs_review' })], { signals })[0].priority, 'P3');
});

test('悪性パッケージ: MAL- の ID を持つ新しい項目は P0。旧形式の前回の項目だけが MAL- を持つ場合も和集合で P0', async () => {
  const signals = makeSignals();
  const item = assemble([detection(['MAL-2026-1'])], { signals })[0];
  assert.equal(item.priority, 'P0');
  assert.equal(item.priority_inputs.malicious, true);
  const { findings } = await runTwoRounds({ previousItems: [storedItem('MAL-2026-1', ['MAL-2026-1', 'CVE-5'], { priority: 'P2' })], detections: [detection(['CVE-5'])], signals });
  assert.equal(findings.items[0].priority, 'P0');
  assert.equal(findings.items[0].priority_inputs.malicious, true);
});

test('EPSS: fresh は一覧で P1・なければ P2。previous は一覧で P1＋注記、なければ P2＋注記。expired は P2＋注記。degraded は注記が変わる', async () => {
  const run = async (epss, rows, feedMode = 'latest') => {
    const signals = makeSignals({ epss, epssRows: rows, feedMode });
    const { findings } = await runTwoRounds({ previousItems: [], detections: [detection(['CVE-7'])], signals, ctx: ctxOf(signals, feedMode) });
    return findings.items[0];
  };
  const high = [['CVE-7', 0.96]];
  assert.deepEqual([(await run('fresh', high)).priority, (await run('fresh', high)).priority_note], ['P1', undefined]);
  assert.equal((await run('fresh', [])).priority, 'P2');
  const previousHit = await run('previous', high);
  assert.deepEqual([previousHit.priority, previousHit.priority_note], ['P1', 'EPSS 未確認']);
  assert.deepEqual([(await run('previous', [])).priority, (await run('previous', [])).priority_note], ['P2', 'EPSS 未確認']);
  const expired = await run('expired', high);
  assert.deepEqual([expired.priority, expired.priority_note, expired.priority_inputs.epss_high], ['P2', 'EPSS 未確認', null]);
  assert.equal((await run('previous', [], 'degraded')).priority_note, 'KEV・EPSS 未確認');
});

test('今回の検出と索引には GHSA しかなく、前回の項目だけが CVE を持つ: KEV なら P0、EPSS fresh の上位なら P1（和集合で引く）', async () => {
  const advisories = [advisory('GHSA-a', { ghsa: ['GHSA-a'] })];
  const previousItems = [storedItem('CVE-2', ['CVE-2', 'GHSA-a'], { priority: 'P2', kev: false })];
  const kevRun = await runTwoRounds({ previousItems, detections: [detection(['GHSA-a'])], signals: makeSignals({ kev: ['CVE-2'] }), advisories });
  assert.equal(kevRun.findings.items[0].priority, 'P0');
  const epssRun = await runTwoRounds({ previousItems, detections: [detection(['GHSA-a'])], signals: makeSignals({ epssRows: [['CVE-2', 0.97]] }), advisories });
  assert.equal(epssRun.findings.items[0].priority, 'P1');
});
