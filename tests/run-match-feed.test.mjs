import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, symlinkSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fetchFeed } from '../src/match-central/feed-source.mjs';
import { validateFeed } from '../src/feed/validate-feed.mjs';
import { inspectTree } from '../src/feed/inspect-tree.mjs';
import { makeValidFeed } from './helpers/feed-fixture.mjs';
import { makeFeedRepo, makeFeedData, makeMatchHarness, PROJECT } from './helpers/match-harness.mjs';

const NEEDLE = 'sample-app';
const VULN = { id: 'GHSA-aaaa-bbbb-cccc', aliases: ['CVE-2026-1'], severity: 'HIGH' };
const tmp = () => mkdtempSync(path.join(tmpdir(), 'feed-source-'));

test('最新が有効なら latest。案件名を含むフィードは使わず、前回検証した版から復元する。ログに語が出ない', async () => {
  const repo = makeFeedRepo();
  const good = repo.publish(makeFeedData());
  const first = await fetchFeed({ url: repo.url, needles: [NEEDLE], workDir: tmp() });
  assert.deepEqual([first.mode, first.sha, first.problems], ['latest', good, []]);
  repo.publish(makeFeedData(), { files: { 'README.md': `${NEEDLE} の覚え書き\n` } });
  const restored = await fetchFeed({ url: repo.url, lastValidatedSha: good, needles: [NEEDLE], workDir: tmp() });
  assert.deepEqual([restored.mode, restored.sha], ['restored', good]);
  assert.ok(restored.problems.some((p) => p.includes('案件情報')));
  assert.ok(!restored.problems.join('\n').toLowerCase().includes(NEEDLE));
  const degraded = await fetchFeed({ url: repo.url, needles: [NEEDLE], workDir: tmp() });
  assert.deepEqual([degraded.mode, degraded.dataDir], ['degraded', null]);
});

test('ファイル名に案件名を含むフィード: 使わず、表示のパスに語が出ない', async () => {
  const repo = makeFeedRepo();
  repo.publish(makeFeedData(), { files: { [`data/advisories/${NEEDLE}.json`]: '{}' } });
  const result = await fetchFeed({ url: repo.url, needles: [NEEDLE], workDir: tmp() });
  assert.equal(result.mode, 'degraded');
  assert.ok(!result.problems.join('\n').toLowerCase().includes(NEEDLE));
});

test('unsupported_format: 復元に進み、「コードの固定値の更新が必要」が載る', async () => {
  const repo = makeFeedRepo();
  const good = repo.publish(makeFeedData());
  repo.publish(makeFeedData({ formatVersion: 2 }));
  const result = await fetchFeed({ url: repo.url, lastValidatedSha: good, needles: [], workDir: tmp() });
  assert.equal(result.mode, 'restored');
  assert.ok(result.problems.some((p) => p.includes('コードの固定値の更新が必要')));
});

test('ルートが有効なフィードを指すシンボリックリンクなら、validateFeed・inspectTree は違反を返す', () => {
  const real = makeValidFeed();
  const link = path.join(tmp(), 'data');
  symlinkSync(real, link);
  assert.ok(validateFeed(link).length > 0);
  assert.ok(inspectTree({ dir: link, needles: [] }).length > 0);
  assert.deepEqual(validateFeed(real).filter((v) => v.message.includes('ルート')), []);
  assert.ok(validateFeed(path.join(tmp(), 'missing')).length > 0);
});

test('新しいランナー（.work が空）で最新の取り出しに失敗: feed-state の SHA から復元し partial。前回の項目は残り、health Issue に載る', async () => {
  const h = makeMatchHarness();
  h.state.vulns = [VULN];
  const first = await h.match();
  assert.equal(first.status, 'success', first.reasons.join('\n'));
  rmSync(path.join(h.central.root, '.work'), { recursive: true, force: true });
  h.feed.publish(makeFeedData(), { files: { 'README.md': `${NEEDLE}\n` } });
  const out = await h.match({ feedOptions: false });
  assert.equal(out.feedMode, 'restored');
  assert.equal(out.status, 'partial');
  const findings = h.readOut(`findings/${PROJECT}.json`);
  assert.equal(findings.scan_status, 'partial');
  assert.ok(findings.scan_errors.some((e) => e.kind === 'feed' && e.target === 'feed'));
  assert.equal(findings.items.length, 1);
  assert.equal(findings.provenance.feed_version, h.lastSha);
  assert.equal(h.readOut('feed-state.json').last_validated.sha, h.lastSha, '復元した回は last_validated を更新しない');
  assert.equal(h.state.heartbeats, 1, '1回目の success だけ');
  assert.ok(h.healthIssues()[0].body.includes('前回検証したフィード'));
});
