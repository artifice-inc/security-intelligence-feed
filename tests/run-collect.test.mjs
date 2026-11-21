import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import path from 'node:path';
import { runCollect } from '../src/feed/run-collect.mjs';
import { validateFeed } from '../src/feed/validate-feed.mjs';
import { parseEpssCsv } from '../src/collect/epss.mjs';
import { defaultCollectors, failing } from './helpers/central-harness.mjs';
import { makeFeedRemote, cloneFeed, makeRoot, git } from './helpers/feed-git.mjs';
import { fixtureText } from './helpers/fake-http.mjs';

const T1 = '2026-11-21T22:20:00Z'; // 2026-11-22 07:20 JST。予定枠 2026-11-21T22:17Z
const T2 = '2026-11-21T22:40:00Z'; // 同じ予定枠の手動実行
const SLOT = '2026-11-21T22:17Z';
const KEV_RECORD = { cveID: 'CVE-2026-0009', vendorProject: 'Example', product: 'Example', dateAdded: '2026-11-20', knownRansomwareCampaignUse: 'Unknown' };
const BULLETIN = async () => ({ ok: true, records: [{ id: '2026-001-aws', title: 'Synthetic bulletin 1', rss_pub_date: '2026-11-20T00:00:00Z', cves: [] }] });

const readJson = (dir, rel) => JSON.parse(readFileSync(path.join(dir, 'data', rel), 'utf8'));

async function collect({ remote, now = T1, collectors = {}, optionalCollectors = { 'aws-bulletins': BULLETIN }, feedRoot = cloneFeed(remote), rootDir = makeRoot() }) {
  const outcome = await runCollect({
    rootDir, feedRoot, now, env: {},
    deps: { http: {}, collectors: { ...defaultCollectors(), ...collectors }, optionalCollectors },
  });
  return { outcome, feedRoot, rootDir, latest: cloneFeed(remote) };
}

test('成功の回: 検証を通り、kev・epss・health が更新されて feed に push される', async () => {
  const remote = makeFeedRemote();
  const { outcome, latest } = await collect({ remote, collectors: { kev: async () => ({ ok: true, records: [KEV_RECORD], meta: { catalogVersion: 'v9' } }) } });
  assert.equal(outcome.status, 'success');
  assert.deepEqual(outcome.reasons, []);
  assert.equal(outcome.pushed, true);
  assert.deepEqual(validateFeed(path.join(latest, 'data')), []);
  assert.deepEqual(readJson(latest, 'kev.json'), { fetched_at: T1, ok: true, catalog_version: 'v9', records: [KEV_RECORD] });
  assert.equal(readJson(latest, 'epss-high.json').threshold, 0.95);
  const health = readJson(latest, 'health.json');
  assert.equal(health.run_slot, SLOT);
  assert.equal(health.last_run.status, 'success');
  assert.equal(health.sources.epss.last_attempt_ok, true);
  assert.equal(readJson(latest, 'aws-bulletins.json').items.length, 1);
});

test('出力に findings・inventory・issues.json・digest がない', async () => {
  const { rootDir, latest } = await collect({ remote: makeFeedRemote() });
  for (const dir of [path.join(rootDir, '.work', 'feed-out', 'data'), path.join(latest, 'data')]) {
    const names = readdirSync(dir);
    for (const forbidden of ['findings', 'inventory', 'issues.json', 'digest']) assert.ok(!names.includes(forbidden), forbidden);
  }
});

// 失敗した情報源は前回の値を残し、last_attempt_ok: false、last_error に message を持たない
function assertFailedSource(health, name) {
  const source = health.sources[name];
  assert.equal(source.last_attempt_ok, false, name);
  assert.deepEqual(Object.keys(source.last_error).sort(), ['at', 'kind']);
  assert.equal(health.last_run.status, 'partial');
}

test('php-ghsa だけ失敗: partial。アドバイザリは前回のまま、health に失敗が残る', async () => {
  const remote = makeFeedRemote();
  const before = readdirSync(path.join(cloneFeed(remote), 'data', 'advisories'));
  const { outcome, latest } = await collect({ remote, collectors: { 'php-ghsa': failing() } });
  assert.equal(outcome.status, 'partial');
  assert.deepEqual(validateFeed(path.join(latest, 'data')), []);
  assertFailedSource(readJson(latest, 'health.json'), 'php-ghsa');
  assert.deepEqual(readdirSync(path.join(latest, 'data', 'advisories')), before);
});

test('KEV の失敗: 前回の records・fetched_at を残して ok:false', async () => {
  const remote = makeFeedRemote();
  const previous = readJson(cloneFeed(remote), 'kev.json');
  const { outcome, latest } = await collect({ remote, collectors: { kev: failing() } });
  assert.equal(outcome.status, 'partial');
  assert.deepEqual(validateFeed(path.join(latest, 'data')), []);
  assert.deepEqual(readJson(latest, 'kev.json'), { ...previous, ok: false });
  assertFailedSource(readJson(latest, 'health.json'), 'kev');
});

test('EPSS の失敗: 前回の records を残して ok:false', async () => {
  const remote = makeFeedRemote();
  const previous = readJson(cloneFeed(remote), 'epss-high.json');
  const { outcome, latest } = await collect({ remote, collectors: { epss: failing() } });
  assert.equal(outcome.status, 'partial');
  assert.deepEqual(validateFeed(path.join(latest, 'data')), []);
  assert.deepEqual(readJson(latest, 'epss-high.json'), { ...previous, ok: false });
  assertFailedSource(readJson(latest, 'health.json'), 'epss');
});

test('EPSS の成功: 閾値以上の行だけを threshold とともに書く', async () => {
  const { latest } = await collect({
    remote: makeFeedRemote(),
    collectors: { epss: async ({ minPercentile }) => ({ ok: true, ...parseEpssCsv(fixtureText('epss.csv'), new Set(), minPercentile), meta: { model_version: 'v1', score_date: '2026-11-20' } }) },
  });
  const file = readJson(latest, 'epss-high.json');
  assert.ok(file.ok && file.records.length > 0);
  assert.ok(file.records.every((r) => r.percentile >= 0.95 && Object.keys(r).sort().join() === 'cve,epss,percentile'));
});

test('AWS だけ失敗: 全体は success のまま（終了コード 0 になる状態）で、validateFeed を通る', async () => {
  const { outcome, latest } = await collect({ remote: makeFeedRemote(), optionalCollectors: { 'aws-bulletins': failing() } });
  assert.equal(outcome.status, 'success');
  assert.deepEqual(validateFeed(path.join(latest, 'data')), []);
  const health = readJson(latest, 'health.json');
  assert.equal(health.optional_sources['aws-bulletins'].last_attempt_ok, false);
  assert.deepEqual(Object.keys(health.optional_sources['aws-bulletins'].last_error).sort(), ['at', 'kind']);
  assert.equal(health.last_run.status, 'success');
});

test('同じ予定枠で成功の実行 → 失敗の実行: feed の最新に失敗が残る', async () => {
  const remote = makeFeedRemote();
  await collect({ remote, now: T1 });
  const second = await collect({ remote, now: T2, collectors: { 'php-ghsa': failing() } });
  const health = readJson(second.latest, 'health.json');
  assert.equal(health.run_slot, SLOT);
  assert.equal(health.sources['php-ghsa'].last_attempt_ok, false);
  assert.equal(health.sources['php-ghsa'].last_attempt_slot, SLOT);
  assert.equal(health.sources['php-ghsa'].last_success_slot, SLOT);
  assert.equal(health.sources.kev.last_attempt_ok, true);
});

test('push が fast-forward でなく拒否されたら failed（終了コード 1）', async () => {
  const remote = makeFeedRemote();
  const stale = cloneFeed(remote);
  await collect({ remote, now: T1 });
  const { outcome } = await collect({ remote, now: T2, feedRoot: stale });
  assert.equal(outcome.status, 'failed');
  assert.equal(outcome.pushed, false);
  assert.match(outcome.reasons.at(-1), /push/);
});

test('検証に外れたら push しない（failed）', async () => {
  const remote = makeFeedRemote();
  const head = git(remote, 'rev-parse', 'feed');
  const { outcome } = await collect({ remote, collectors: { kev: async () => ({ ok: true, records: [{ cveID: 'CVE-2026-0009' }] }) } });
  assert.equal(outcome.status, 'failed');
  assert.equal(outcome.pushed, false);
  assert.equal(git(remote, 'rev-parse', 'feed'), head);
});
