import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, readFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fetchRepo, gitEnv } from '../src/inventory/fetch-repo.mjs';
import { exportInventory, evaluateExport } from '../src/inventory/export-inventory.mjs';
import { resolveInventory } from '../src/inventory/resolve.mjs';
import { assertValid } from '../src/lib/schema.mjs';
import { makeRepo, makeTree } from './helpers/tree.mjs';

const NOW = new Date('2026-10-25T00:00:00Z');
const tmp = () => mkdtempSync(path.join(tmpdir(), 'si-inv-'));

test('試験用リポジトリから pull し、inventory がスキーマを通る（lockfile の中身は保存しない）', async () => {
  const repo = makeRepo({ master: { 'composer.lock': '{"packages":[]}', 'package-lock.json': '{}', 'README.md': 'x', '.nvmrc': '22.11.0', 'src/big.txt': 'not fetched' } });
  const cfg = { project: 'demo', repo: 'o/demo', monitor_ref: 'master', owners: ['o'], exposure: 'internet' };
  const result = await resolveInventory({ cfg, workRoot: tmp(), now: NOW, cloneUrl: () => repo.url });
  assert.equal(result.inventory_status, 'fresh');
  assertValid('inventory', result.inventory);
  assert.equal(result.inventory.source_commit, repo.head());
  assert.deepEqual(result.inventory.lockfiles, ['composer.lock', 'package-lock.json']);
  assert.equal(result.inventory.runtimes.node.version, '22.11.0');
  assert.ok(!JSON.stringify(result.inventory).includes('packages'));
  assert.ok(!existsSync(path.join(result.workdir, 'README.md')), 'sparse checkout で対象外のファイルは取得しない');
});

test('stack.yml の monitor_ref が config と違えば、その ref で取り直す', async () => {
  const repo = makeRepo({
    main: { 'package-lock.json': '{"v":"main"}' },
    prod: { '.security/stack.yml': 'monitor_ref: prod\nruntimes:\n  node: "20.1.0"\n', 'package-lock.json': '{"v":"prod"}' },
  });
  const dir = path.join(tmp(), 'x');
  // 設定は main を指すが、main には stack.yml がないのでそのまま。prod を指定した場合のみ prod の宣言が読まれる
  const fetched = await fetchRepo({ url: repo.url, monitorRef: 'prod', dir });
  assert.equal(fetched.monitorRef, 'prod');
  assert.equal(JSON.parse(readFileSync(path.join(dir, 'package-lock.json'), 'utf8')).v, 'prod');
});

test('stack.yml が別の ref を宣言していれば追従する', async () => {
  const repo = makeRepo({
    main: { '.security/stack.yml': 'monitor_ref: prod\n', 'package-lock.json': '{"v":"main"}' },
    prod: { 'package-lock.json': '{"v":"prod"}', '.security/stack.yml': 'monitor_ref: prod\n' },
  });
  const dir = path.join(tmp(), 'y');
  const fetched = await fetchRepo({ url: repo.url, monitorRef: 'main', dir });
  assert.equal(fetched.monitorRef, 'prod');
  assert.equal(JSON.parse(readFileSync(path.join(dir, 'package-lock.json'), 'utf8')).v, 'prod');
});

test('トークンは環境変数の extraheader だけで渡す', () => {
  const env = gitEnv('SECRET-TOKEN-VALUE');
  assert.equal(env.GIT_CONFIG_KEY_0, 'http.extraheader');
  assert.match(env.GIT_CONFIG_VALUE_0, /^AUTHORIZATION: basic /);
  assert.ok(!env.GIT_CONFIG_VALUE_0.includes('SECRET-TOKEN-VALUE'));
});

test('D6: 取得に失敗した回は unavailable。前回のランタイムを使い、依存関係は照合しない', async () => {
  const cfg = { project: 'demo', repo: 'o/demo', monitor_ref: 'master', owners: ['o'], exposure: 'internet' };
  const previous = { project: 'demo', mode: 'pull', monitor_ref: 'master', source_commit: 'abc', inventory_as_of: '2026-10-24T00:00:00Z', files: [], lockfiles: ['composer.lock'], exposure: 'internet', runtimes: { php: { version: '8.2.30', constraint: null, source: 'Dockerfile' }, node: { version: null, constraint: null, source: null } } };
  const result = await resolveInventory({ cfg, previous, workRoot: tmp(), now: NOW, fetchImpl: async () => { throw new Error('clone failed'); } });
  assert.equal(result.inventory_status, 'unavailable');
  assert.equal(result.workdir, null);
  assert.equal(result.inventory.runtimes.php.version, '8.2.30');
  assert.equal(result.inventory.inventory_as_of, '2026-10-24T00:00:00Z');
  assert.equal(result.scan_errors[0].kind, 'inventory');
  assertValid('inventory', result.inventory);
});

const makeExport = (extra = {}) => {
  const project = makeTree({ 'composer.lock': '{"packages":[]}', 'Dockerfile': 'FROM php:8.2.30\n', ...extra });
  const out = path.join(tmp(), 'demo');
  const { manifest } = exportInventory({ projectDir: project, project: 'demo', outDir: out, now: NOW, sourceRef: 'main', sourceCommit: 'abc123', exposure: 'internet' });
  return { out, manifest };
};

test('export: manifest と files/ を作り、中央は pull と同じ検出で inventory を作る', async () => {
  const { out, manifest } = makeExport();
  assertValid('export-manifest', manifest);
  assert.ok(existsSync(path.join(out, 'files', 'composer.lock')));
  const cfg = { project: 'demo', source: 'export', monitor_ref: 'main', owners: ['o'], exposure: 'internet' };
  const result = await resolveInventory({ cfg, exportRoot: path.dirname(out), workRoot: tmp(), now: new Date('2026-11-10T00:00:00Z') });
  assert.equal(result.inventory_status, 'fresh');
  assert.equal(result.inventory.mode, 'export');
  assert.equal(result.inventory.runtimes.php.version, '8.2.30');
  assert.equal(result.inventory.inventory_as_of, manifest.exported_at);
  assert.deepEqual(result.scan_errors, []);
  assertValid('inventory', result.inventory);
});

test('試験2c/9: 30日を過ぎると stale_inventory（照合は続け、inventory_as_of は維持）', async () => {
  const { out, manifest } = makeExport();
  assert.equal(evaluateExport({ dir: out, now: new Date('2026-11-24T00:00:00Z') }).status, 'fresh');
  assert.equal(evaluateExport({ dir: out, now: new Date('2026-11-25T00:00:01Z') }).status, 'stale_inventory');
  const cfg = { project: 'demo', source: 'export', monitor_ref: 'main', owners: ['o'], exposure: 'internet' };
  const result = await resolveInventory({ cfg, exportRoot: path.dirname(out), workRoot: tmp(), now: new Date('2026-12-01T00:00:00Z') });
  assert.equal(result.inventory_status, 'stale_inventory');
  assert.ok(result.workdir);
  assert.equal(result.inventory.inventory_as_of, manifest.exported_at);
});

test('export: sha256 不一致・欠落・不正な manifest は unavailable', () => {
  const { out } = makeExport();
  writeFileSync(path.join(out, 'files', 'composer.lock'), '{"tampered":true}');
  assert.equal(evaluateExport({ dir: out, now: NOW }).status, 'unavailable');
  const { out: out2 } = makeExport();
  writeFileSync(path.join(out2, 'manifest.json'), '{"project":"demo"}');
  assert.equal(evaluateExport({ dir: out2, now: NOW }).status, 'unavailable');
  assert.equal(evaluateExport({ dir: path.join(tmp(), 'none'), now: NOW }).status, 'unavailable');
});

test('export: 中央の再検出が runtimes_detected と食い違えば scan_errors に記録する', async () => {
  const { out } = makeExport();
  const manifestPath = path.join(out, 'manifest.json');
  const manifest = JSON.parse(readFileSync(manifestPath, 'utf8'));
  manifest.runtimes_detected.php.version = '7.4.0';
  writeFileSync(manifestPath, JSON.stringify(manifest));
  const cfg = { project: 'demo', source: 'export', monitor_ref: 'main', owners: ['o'], exposure: 'internet' };
  const result = await resolveInventory({ cfg, exportRoot: path.dirname(out), workRoot: tmp(), now: NOW });
  assert.equal(result.inventory_status, 'fresh');
  assert.ok(result.scan_errors.some((e) => /runtimes_detected/.test(e.message)));
});
