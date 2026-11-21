import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdirSync, writeFileSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { makeHarness, T0, scannerStub, failing } from './helpers/central-harness.mjs';
import { securityCheck } from '../src/local/security-check.mjs';
import { assertValid } from '../src/lib/schema.mjs';
import { zipPathOf } from '../src/collect/osv-db.mjs';

const UNPINNED = 'requests>=2.0\nsecret-internal-pkg\n';
const LATER = new Date('2026-10-25T01:00:00Z');

test('中央: 固定されていない requirements だけの案件は partial。エラーに行番号があり行の中身はない。inventory の runtimes.python は版が未確定', async () => {
  const h = makeHarness({ projectFiles: { 'requirements.txt': UNPINNED } });
  await h.run();
  const findings = h.read('findings/demo.json');
  assert.equal(findings.scan_status, 'partial');
  const error = findings.scan_errors.find((e) => e.target === 'requirements.txt');
  assert.deepEqual(error, { kind: 'lockfile', target: 'requirements.txt', message: '版を == で固定していない行があるため照合できません（1行目、2行目）' });
  assert.ok(!JSON.stringify(findings).includes('secret-internal-pkg'));
  assert.ok(!JSON.stringify(h.read('inventory/demo.json')).includes('secret-internal-pkg'), 'inventory には行の中身を保存しない');
  const inventory = h.read('inventory/demo.json');
  assert.deepEqual(inventory.lockfiles, []);
  assert.deepEqual(inventory.files.map((f) => f.kind), ['requirements-unpinned']);
  assert.deepEqual(inventory.runtimes.python, { version: null, constraint: null, source: null });
  assertValid('inventory', inventory);
  assert.equal(h.deps.exec.calls.length, 0);
});

test('中央: PyPI の DB は毎回取得され、health.osv_db に出る。PyPI の取得失敗は PyPI を使わない案件を partial にしない', async () => {
  const h = makeHarness();
  const first = await h.run();
  assert.deepEqual(Object.keys(h.read('health.json').osv_db).sort(), ['Packagist', 'PyPI', 'npm']);
  assert.equal(first.status, 'success');
  const h2 = makeHarness();
  h2.state.osvOk = { npm: true, Packagist: true, PyPI: false };
  await h2.run();
  const findings = h2.read('findings/demo.json');
  assert.equal(findings.scan_status, 'complete', 'npm だけの案件は PyPI の DB に依存しない');
  assert.deepEqual(Object.keys(findings.provenance.osv_db), ['npm']);
});

test('不変条件1: npm の案件の inventory のキーと files・provenance の形が変わらない', async () => {
  const h = makeHarness();
  await h.run();
  const inventory = h.read('inventory/demo.json');
  assert.deepEqual(Object.keys(inventory).sort(), ['exposure', 'files', 'inventory_as_of', 'lockfiles', 'mode', 'monitor_ref', 'os', 'project', 'runtimes', 'source_commit']);
  assert.deepEqual(Object.keys(inventory.runtimes), ['node', 'php']);
  assert.deepEqual(inventory.files.map((f) => [f.path, f.kind]), [['.nvmrc', 'nvmrc'], ['package-lock.json', 'lockfile']]);
  assert.deepEqual(h.read('findings/demo.json').scan_errors, []);
  assert.deepEqual(Object.keys(h.read('findings/demo.json').provenance.osv_db), ['npm']);
});

test('ローカル: 固定されていない requirements の行は unavailable で、local_scan.complete は false、出力はスキーマを通る', async () => {
  const h = makeHarness({ projectFiles: { 'requirements.txt': UNPINNED } });
  await h.run();
  const osvDir = path.join(h.central.root, 'osv-db');
  for (const eco of ['npm', 'Packagist', 'PyPI']) { mkdirSync(path.dirname(zipPathOf(osvDir, eco)), { recursive: true }); writeFileSync(zipPathOf(osvDir, eco), 'placeholder'); }
  writeFileSync(path.join(osvDir, 'meta.json'), JSON.stringify(Object.fromEntries(['npm', 'Packagist', 'PyPI'].map((e) => [e, { fetched_at: T0, sha256: 'a'.repeat(64) }]))));
  const deps = { now: LATER, exec: scannerStub(h.state), scannerPath: 'osv-scanner', scannerVersion: async () => '2.7.0', fetchOsvDb: async () => { throw new Error('取得しない'); } };
  const output = await securityCheck({ cacheRoot: h.central.root, projectDir: h.project.root, projectName: 'demo', deps, scriptVersion: 'test-sha', exposure: 'internet' });
  assertValid('security-check-output', output);
  assert.deepEqual(output.summary.rows.filter((r) => r.kind === 'lockfile').map((r) => [r.target, r.state]), [['requirements.txt', 'unavailable']]);
  assert.equal(output.dependency_checks.osv, 'unavailable');
  assert.equal(output.dependency_check, 'unavailable');
  assert.equal(output.local_scan.complete, false);
  assert.ok(output.scan_errors.some((e) => e.message.includes('1行目')));
  assert.ok(!JSON.stringify(output).includes('secret-internal-pkg'));
  assert.equal(deps.exec.calls.length, 0);
});

const VULN = { id: 'GHSA-aaaa-bbbb-cccc', aliases: ['CVE-2026-1'], severity: 'HIGH' };
const stable = (h) => JSON.stringify({ findings: h.read('findings/demo.json'), inventory: h.read('inventory/demo.json'), issues: h.vulnIssues().map((i) => [i.title, i.labels, i.state]) });

test('中央: python.json が作られスキーマ検証を通り、health.sources に Python 用の3つの情報源が出る', async () => {
  const h = makeHarness();
  const outcome = await h.run();
  assert.equal(outcome.status, 'success');
  const python = h.read('runtimes/python.json');
  assertValid('runtimes', python);
  assert.deepEqual([python.runtime, python.pending, python.psf_synced_at], ['python', [], T0]);
  const sources = h.read('health.json').sources;
  for (const name of ['python-psf', 'python-releases', 'endoflife-python']) assert.equal(sources[name].last_error, null, name);
  assert.match(readFileSync(path.join(h.central.root, 'data/digest/latest.md'), 'utf8'), /\| endoflife-python \|/);
});

test('不変条件1: Python の情報源が失敗しても、Python のない案件の findings・inventory・Issue は成功した回と1バイトも変わらない（scan_status は complete のまま）', async () => {
  const baseline = makeHarness();
  baseline.state.vulns = [VULN];
  await baseline.run();
  for (const name of ['endoflife-python', 'python-psf', 'python-releases']) {
    const h = makeHarness();
    h.state.vulns = [VULN];
    h.state.collectors[name] = failing('network');
    const outcome = await h.run();
    assert.equal(h.read('findings/demo.json').scan_status, 'complete', name);
    assert.equal(h.read('findings/demo.json').scan_errors.length, 0, name);
    assert.equal(stable(h).replace(/[0-9a-f]{40}/g, 'C'), stable(baseline).replace(/[0-9a-f]{40}/g, 'C'), name);
    assert.equal(outcome.status, 'partial', '情報源の失敗は、今までどおり実行全体を partial にする');
    assert.ok(h.read('health.json').sources[name].last_error, name);
  }
});

test('Python の情報源が失敗した回は、前回の python.json の pending・psf_synced_at・advisories を残す', async () => {
  const h = makeHarness();
  h.state.collectors['python-psf'] = async () => ({ ok: true, records: [], missing: ['PSF-2026-404'] });
  await h.run(T0);
  const first = h.read('runtimes/python.json');
  assert.deepEqual(first.pending.map((p) => p.id), ['PSF-2026-404']);
  h.state.collectors['python-psf'] = failing('network');
  await h.run('2026-10-25T09:00:00Z');
  const second = h.read('runtimes/python.json');
  assert.deepEqual([second.pending, second.psf_synced_at, second.advisories], [first.pending, first.psf_synced_at, first.advisories]);
});
