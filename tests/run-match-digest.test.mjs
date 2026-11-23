import test from 'node:test';
import assert from 'node:assert/strict';
import { makeMatchHarness, PROJECT, NOW } from './helpers/match-harness.mjs';
import { renderDigest } from '../src/publish/digest.mjs';
import { detectProject } from '../src/match/match-project.mjs';
import { keepMatchedOnly } from '../src/match/advisory-view.mjs';
import { inventoryOf } from './helpers/match-fixtures.mjs';
import { loadSchedule, loadThresholds } from '../src/lib/config.mjs';

const VULN = { id: 'GHSA-aaaa-bbbb-cccc', aliases: ['CVE-2026-1'], severity: 'HIGH' };
const digestLines = (h) => h.readText('digest/latest.md').split('\n');

test('国内の注意喚起: 同じフィードを2回使っても重複せず、1回飛ばした後にその間の新着を拾う', async () => {
  const h = makeMatchHarness();
  await h.match({ feedOptions: { jpIds: ['A'] } });
  assert.ok(digestLines(h).some((l) => l.includes('Alert A')));
  assert.deepEqual(h.readOut('feed-state.json').digest_jp.keys, ['jpcert|A']);
  await h.match({ feedOptions: { jpIds: ['A'] } });
  assert.ok(!digestLines(h).some((l) => l.includes('Alert A')), '2回目は新着ではない');
  await h.match({ feedOptions: { jpIds: ['A', 'B', 'C'] } });
  const lines = digestLines(h);
  assert.ok(lines.some((l) => l.includes('Alert B')) && lines.some((l) => l.includes('Alert C')));
  assert.ok(!lines.some((l) => l.includes('Alert A')));
});

test('公開側の収集が遅れた枠（run_slot が古い）: scan_errors に feed が入り、検証を通って partial のままコミットされる', async () => {
  const h = makeMatchHarness();
  h.state.vulns = [VULN];
  const out = await h.match({ feedOptions: { health: { run_slot: '2026-11-20T22:17Z' } } });
  assert.equal(out.status, 'partial');
  assert.equal(out.committed, true);
  const errors = h.readOut(`findings/${PROJECT}.json`).scan_errors;
  assert.ok(errors.some((e) => e.kind === 'feed' && e.target === 'feed'));
  assert.equal(h.readOut(`findings/${PROJECT}.json`).items.length, 1);
});

test('旧データの混在した記録がある回に OSV の DB を取得できなくても、書き出す記録は検証を通り、前回の優先度は下がらない', async () => {
  const h = makeMatchHarness();
  h.state.vulns = [VULN];
  await h.runCentralAt('2026-11-20T00:00:00Z');
  h.state.osvOk = { npm: false, Packagist: false, PyPI: false };
  const out = await h.match();
  assert.equal(out.status, 'partial');
  assert.equal(out.committed, true, out.reasons.join('\n'));
  assert.equal(h.readOut(`findings/${PROJECT}.json`).items[0].priority, 'P1');
});

test('renderDigest: feedUnavailable は3つの欄を「取得できませんでした」にし、既定（旧処理）は今のまま', () => {
  const base = {
    projects: [], findingsByProject: new Map(), snapshot: [], digestInfo: null, schedule: loadSchedule(), now: NOW, centralRepo: 'o/r',
    health: { last_success_at: NOW, sources: { kev: { last_success_at: NOW, last_error: null } } }, kevRecords: [], jpItems: [], thresholds: loadThresholds(),
  };
  assert.equal(renderDigest(base).includes('取得できませんでした'), false);
  assert.equal((renderDigest({ ...base, feedUnavailable: true }).match(/- 取得できませんでした/g) ?? []).length, 3);
  const verdicts = { kev: { ok: false, reason: 'テスト用の理由' } };
  const row = renderDigest({ ...base, sourceVerdicts: verdicts }).split('\n').find((l) => l.startsWith('| kev |'));
  assert.ok(!row.includes('OK') && row.includes('テスト用の理由'));
  assert.ok(renderDigest(base).split('\n').find((l) => l.startsWith('| kev |')).includes('OK'));
});

test('detectProject: feedAvailable:false はフィード依存の照合を止め、案件が使う対象だけを feed エラーにする', async () => {
  const inventory = inventoryOf({ lockfiles: [], files: [{ path: 'composer.lock', sha256: 'a'.repeat(64), kind: 'lockfile' }], runtimes: { php: { version: '8.3.1', constraint: null, source: 'composer.json' }, node: { version: '22.11.0', constraint: null, source: '.nvmrc' } } });
  const result = await detectProject({ inventory: { ...inventory, lockfiles: ['composer.lock'] }, workdir: null, exec: async () => ({ code: 0, stdout: '{}' }), scannerPath: 'x', dbDir: 'x', osvAvailable: {}, runtimeData: {}, packagistAdvisories: null, feedAvailable: false });
  const feedTargets = result.errors.filter((e) => e.kind === 'feed').map((e) => e.target).sort();
  assert.deepEqual(feedTargets, ['packagist', 'runtime:nodejs', 'runtime:php']);
  assert.equal(result.dependency_checks.packagist, 'unavailable');
});

test('keepMatchedOnly: sources が空の記録は残さない', () => {
  assert.deepEqual(keepMatchedOnly([{ key: 'a', sources: [] }, { key: 'b', sources: [{ name: 'osv' }] }, { key: 'c', sources: [{ name: 'osv' }, { name: 'php-ghsa' }] }]).map((a) => a.key), ['b']);
});
