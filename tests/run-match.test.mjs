import test from 'node:test';
import assert from 'node:assert/strict';
import { readdirSync } from 'node:fs';
import path from 'node:path';
import { makeMatchHarness, PROJECT } from './helpers/match-harness.mjs';
import { validateOutDir } from '../src/publish/validate-out.mjs';

const VULN = { id: 'GHSA-aaaa-bbbb-cccc', aliases: ['CVE-2026-1'], severity: 'HIGH' };
const itemsOf = (h, project = PROJECT) => h.readOut(`findings/${project}.json`).items;

test('成功の回: complete・コミット・feed-state・provenance・共通の生成物なし', async () => {
  const h = makeMatchHarness();
  h.state.vulns = [VULN];
  const out = await h.match();
  assert.equal(out.status, 'success', out.reasons.join('\n'));
  assert.equal(out.feedMode, 'latest');
  assert.equal(out.committed, true);
  assert.equal(h.state.heartbeats, 1);
  const findings = h.readOut(`findings/${PROJECT}.json`);
  assert.equal(findings.scan_status, 'complete');
  assert.deepEqual([findings.provenance.script_version, findings.provenance.feed_version], ['code-sha', h.lastSha]);
  assert.equal(findings.items[0].priority, 'P1');
  assert.deepEqual(findings.items[0].priority_inputs.epss_high, false);
  const state = h.readOut('feed-state.json');
  assert.deepEqual([state.mode, state.last_validated.sha, state.last_validated.run_slot], ['match', h.lastSha, '2026-11-21T22:17Z']);
  for (const common of ['runtimes', 'os', 'jp-alerts.json', 'packagist-advisories.json', 'aws-bulletins.json']) assert.equal(h.has(common), false, common);
  assert.deepEqual(validateOutDir(path.join(h.central.root, 'data')), []);
  assert.deepEqual(readdirSync(path.join(h.central.root, 'data', 'advisories')).every((n) => !n.startsWith('CVE-2015')), true);
});

test('縮退照合: フィードなし・共通の生成物なしでも、OSV の検出が検証とコミットまで進み、feed の対象は feed エラーになる', async () => {
  const h = makeMatchHarness();
  h.state.vulns = [VULN];
  const out = await h.match({ feedOptions: false, feedUrl: 'file:///nonexistent-feed-remote' });
  assert.equal(out.status, 'partial');
  assert.equal(out.feedMode, 'degraded');
  assert.equal(out.committed, true);
  const findings = h.readOut(`findings/${PROJECT}.json`);
  assert.equal(findings.scan_status, 'partial');
  assert.ok(findings.scan_errors.some((e) => e.kind === 'feed' && e.target === 'runtime:nodejs'));
  assert.ok(findings.scan_errors.some((e) => e.kind === 'feed' && e.target === 'feed'));
  assert.equal(findings.provenance.feed_version, null);
  assert.equal(findings.items.length, 1);
  assert.equal(findings.items[0].priority_note, 'KEV・EPSS 未確認');
  assert.equal(h.state.heartbeats, 0);
  const digest = h.readText('digest/latest.md');
  assert.equal((digest.match(/- 取得できませんでした/g) ?? []).length, 3);
  assert.deepEqual(h.readOut('feed-state.json').last_validated, null);
  assert.ok(h.healthIssues()[0].body.includes('縮退照合'));
});

test('最新の検証を通ったフィードで新着がない回の digest は「なし」', async () => {
  const h = makeMatchHarness();
  await h.match();
  const digest = h.readText('digest/latest.md');
  assert.ok(!digest.includes('取得できませんでした'));
  assert.ok(digest.includes('### KEV') && digest.includes('- なし'));
});
