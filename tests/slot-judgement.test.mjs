import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { judgeSlots } from '../src/match-central/slot-judgement.mjs';
import { SOURCE_NAMES } from '../src/collect/index.mjs';
import { loadSchedule } from '../src/lib/config.mjs';
import { makeFeedData, makeMatchHarness, NOW, PROJECT } from './helpers/match-harness.mjs';

const THRESHOLDS = { stale_source_hours: 36, epss_percentile_p1: 0.95 };
const SCHEDULE = loadSchedule();
const SLOT = '2026-11-21T22:17Z';
const OTHER_SLOT_AT = '2026-11-21T08:00:00Z'; // 前の枠（07:17Z）の取得

function feedOf(options = {}) {
  const dir = makeFeedData(options);
  const read = (rel) => JSON.parse(readFileSync(path.join(dir, rel), 'utf8'));
  return { feedHealth: read('health.json'), kev: read('kev.json'), epssHigh: read('epss-high.json') };
}
const judge = (feed, feedMode = 'latest') => judgeSlots({ ...feed, feedMode, now: NOW, thresholds: THRESHOLDS, schedule: SCHEDULE });
const failedNames = (result) => Object.entries(result.sourceResults).filter(([, v]) => !v.ok).map(([name]) => name);

test('全情報源が枠で成功: すべて ok で feed のエラーなし', () => {
  const result = judge(feedOf());
  assert.deepEqual(failedNames(result), []);
  assert.deepEqual(result.extraErrors, []);
  assert.equal(result.targetSlot, '2026-11-21T07:17Z', '下限は猶予内の前の枠');
  assert.equal(result.latestSlot, SLOT);
});

test('個別の失敗: php-ghsa だけ・epss だけが失敗として出る（health にない情報源も失敗）', () => {
  assert.deepEqual(failedNames(judge(feedOf({ failing: ['php-ghsa'] }))), ['php-ghsa']);
  assert.deepEqual(failedNames(judge(feedOf({ failing: ['epss'] }))), ['epss']);
  assert.deepEqual(failedNames(judge(feedOf({ omitSources: ['jvn'] }))), ['jvn']);
});

test('一覧と health の食い違い: kev の ok:false・日時の不一致・前の枠・読めない日時・初期フィードはいずれも成功にならず、例外も出ない', () => {
  const cases = {
    'kev の ok:false': (f) => { f.kev.ok = false; },
    'kev の日時が health と違う': (f) => { f.kev.fetched_at = '2026-11-21T22:30:00Z'; },
    'kev が前の枠の ok:true': (f) => { f.kev.fetched_at = OTHER_SLOT_AT; },
    'kev の日時が読めない': (f) => { f.kev.fetched_at = '昨日'; },
    'epss の ok:false': (f) => { f.epssHigh.ok = false; },
    'epss の日時が同じ枠の別の試行': (f) => { f.epssHigh.fetched_at = '2026-11-21T22:30:00Z'; },
    'epss の日時が読めない': (f) => { f.epssHigh.fetched_at = null; },
  };
  for (const [label, mutate] of Object.entries(cases)) {
    const feed = feedOf();
    mutate(feed);
    const failed = failedNames(judge(feed));
    assert.ok(failed.includes(label.startsWith('kev') ? 'kev' : 'epss'), label);
  }
  const initial = judge(feedOf({ omitSources: ['kev', 'epss'], neverLists: true }));
  assert.deepEqual(failedNames(initial).sort(), ['epss', 'kev']);
});

test('公開側の EPSS の閾値が非公開側より高い: epss は成功にならず、理由が出る', () => {
  const result = judge(feedOf({ epssThreshold: 0.97 }));
  assert.deepEqual(failedNames(result), ['epss']);
  assert.ok(result.verdicts.epss.reason.includes('閾値を網羅しない'));
  assert.deepEqual(failedNames(judge(feedOf({ epssThreshold: 0.9 }))), [], '公開側が低いのは網羅できる');
  const mismatch = feedOf();
  mismatch.epssHigh.fetched_at = '2026-11-21T22:30:00Z';
  assert.ok(judge(mismatch).verdicts.epss.reason.includes('健全性の記録と合わない'));
});

test('restored・degraded・run_slot が古い: 全情報源が失敗で、feed のエラーが全案件に足される', () => {
  const restored = judge(feedOf(), 'restored');
  assert.equal(failedNames(restored).length, SOURCE_NAMES.length);
  assert.equal(restored.extraErrors[0].kind, 'feed');
  const degraded = judge({ feedHealth: null, kev: null, epssHigh: null }, 'degraded');
  assert.equal(failedNames(degraded).length, SOURCE_NAMES.length);
  const old = judge(feedOf({ health: { run_slot: '2026-11-20T22:17Z' } }));
  assert.equal(old.extraErrors.length, 1);
});

async function withFindings() {
  const h = makeMatchHarness();
  h.state.vulns = [{ id: 'GHSA-aaaa-bbbb-cccc', aliases: ['CVE-2026-1'], severity: 'HIGH' }];
  assert.equal((await h.match()).status, 'success');
  return h;
}

test('epss が失敗した枠: 全案件 partial。項目は残り、fixed-in-repo も完了通知も出ない', async () => {
  const h = await withFindings();
  h.state.vulns = [];
  const out = await h.match({ feedOptions: { failing: ['epss'] } });
  assert.equal(out.status, 'partial');
  const findings = h.readOut(`findings/${PROJECT}.json`);
  assert.equal(findings.scan_status, 'partial');
  assert.equal(findings.items.length, 1);
  assert.ok(![...h.api.issues.values()].some((i) => i.labels.includes('fixed-in-repo')));
  assert.equal(h.state.heartbeats, 1);
});

test('jpcert だけが失敗した枠: 案件は complete、全体は partial、health Issue に載り、完了通知は送らない', async () => {
  const h = makeMatchHarness();
  const out = await h.match({ feedOptions: { failing: ['jpcert'] } });
  assert.equal(out.status, 'partial');
  assert.equal(h.readOut(`findings/${PROJECT}.json`).scan_status, 'complete');
  assert.equal(h.readOut('health.json').last_run.status, 'partial');
  assert.ok(h.healthIssues()[0].body.includes('jpcert'));
  assert.equal(h.state.heartbeats, 0);
});

test('digest の健全性欄: EPSS の閾値・一覧の日時の不一致の回は OK と出さず、理由が health Issue と一致する', async () => {
  const h = makeMatchHarness();
  await h.match({ feedOptions: { epssThreshold: 0.97 } });
  const row = h.readText('digest/latest.md').split('\n').find((l) => l.startsWith('| epss |'));
  assert.ok(row && !row.includes('OK') && row.includes('EPSS の一覧が閾値を網羅しない'), row);
  assert.ok(h.healthIssues()[0].body.includes('EPSS の一覧が閾値を網羅しない'));
});

test('KEV・EPSS が health では成功でも一覧が未取得（build-public の初期フィード）: 全案件 partial で前回の項目が残る', async () => {
  const h = await withFindings();
  const out = await h.match({ feedOptions: { neverLists: true, omitSources: ['kev', 'epss'] } });
  assert.equal(out.status, 'partial');
  assert.equal(h.readOut(`findings/${PROJECT}.json`).scan_status, 'partial');
  assert.equal(h.readOut(`findings/${PROJECT}.json`).items.length, 1);
  assert.equal(h.state.heartbeats, 1);
});
