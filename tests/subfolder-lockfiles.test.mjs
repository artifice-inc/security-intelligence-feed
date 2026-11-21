import test from 'node:test';
import assert from 'node:assert/strict';
import { makeHarness } from './helpers/central-harness.mjs';
import { makeTree } from './helpers/tree.mjs';
import { detectStack, hasNoMaterial } from '../src/inventory/detect-stack.mjs';
import { matchProject } from '../src/match/match-project.mjs';
import { NOW, PROVENANCE, inventoryOf, stubExec } from './helpers/match-fixtures.mjs';

const projectsWith = (extra = {}) => ({
  project_owner: 'o',
  projects: [{ project: 'demo', repo: 'o/demo', monitor_ref: 'master', owners: ['alice'], exposure: 'internet', ...extra }],
});

test('a: lockfile も検出用のファイルもない案件は partial（inventory エラー）で health Issue に載り、「影響なし」にならない', async () => {
  const h = makeHarness({ projectFiles: { 'README.md': 'x' } });
  const outcome = await h.run();
  assert.equal(outcome.status, 'partial');
  const findings = h.read('findings/demo.json');
  assert.equal(findings.scan_status, 'partial');
  assert.ok(findings.scan_errors.some((e) => e.kind === 'inventory' && e.message.includes('projects.yaml の lockfiles を確認してください')));
  assert.ok([...h.api.issues.values()].some((i) => i.labels.includes('health') && i.body.includes('demo')), 'health Issue に載る');
});

test('a2: 材料がない案件の照合は dependency_checks が unavailable（ローカルの security-check と共用）', async () => {
  const inventory = inventoryOf({ files: [], lockfiles: [] });
  assert.equal(hasNoMaterial(inventory), true);
  const result = await matchProject({
    inventory, workdir: makeTree({ 'README.md': 'x' }), exec: stubExec(0, '{}'), scannerPath: 'x', dbDir: '/db', osvAvailable: { npm: true, Packagist: true },
    runtimeData: {}, packagistAdvisories: null, advisoryIndex: new Map(), provenance: PROVENANCE, now: NOW,
  });
  assert.deepEqual(result.dependency_checks, { osv: 'unavailable', packagist: 'unavailable' });
  assert.ok(result.errors.some((e) => e.kind === 'inventory'));
});

test('b: サブフォルダの composer.lock と composer.json を取得し、lockfile を照合・PHP を対象にして RUNTIME-UNKNOWN-php（P3）を作る', async () => {
  const h = makeHarness({
    projectFiles: { 'svr/app/composer.lock': '{"packages":[]}', 'svr/app/composer.json': '{"require":{"php":">=8.1"}}', 'README.md': 'x' },
    projects: projectsWith({ lockfiles: ['svr/app/composer.lock'] }),
  });
  const outcome = await h.run();
  const inventory = h.read('inventory/demo.json');
  assert.deepEqual(inventory.lockfiles, ['svr/app/composer.lock']);
  assert.ok(inventory.files.some((f) => f.path === 'svr/app/composer.json' && f.kind === 'composer-json'));
  assert.deepEqual(inventory.runtimes.php, { version: null, constraint: '>=8.1', source: 'svr/app/composer.json' });
  assert.ok(h.deps.exec.calls.some((args) => args.some((a) => a.endsWith('svr/app/composer.lock'))), 'lockfile が照合に渡される');
  const unknown = h.read('findings/demo.json').items.find((i) => i.advisory_key === 'RUNTIME-UNKNOWN-php');
  assert.equal(unknown.priority, 'P3');
  assert.equal(unknown.judgement, 'needs_review');
  assert.ok(['success', 'partial'].includes(outcome.status));
});

test('b2: detectStack は直下のマニフェストを優先し、なければ lockfile のフォルダのものを使う', () => {
  const root = makeTree({
    'composer.json': '{"require":{"php":">=8.3"}}', 'sub/composer.lock': '{}', 'sub/composer.json': '{"require":{"php":">=7.4"}}', 'sub/package.json': '{"engines":{"node":">=18"}}',
  });
  const result = detectStack(root, { lockfileOverride: ['sub/composer.lock'] });
  assert.equal(result.runtimes.php.source, 'composer.json');
  assert.equal(result.runtimes.node.source, 'sub/package.json');
  assert.ok(result.files.some((f) => f.path === 'sub/package.json' && f.kind === 'package-json'));
});

test('c: projects.yaml の lockfiles に登録したファイルがリポジトリになければ partial（kind: lockfile）', async () => {
  const h = makeHarness({
    projectFiles: { 'svr/app/composer.lock': '{"packages":[]}', 'svr/app/composer.json': '{}' },
    projects: projectsWith({ lockfiles: ['svr/app/composer.lock', 'lp/package-lock.json'] }),
  });
  const outcome = await h.run();
  assert.equal(outcome.status, 'partial');
  const findings = h.read('findings/demo.json');
  assert.equal(findings.scan_status, 'partial');
  assert.ok(findings.scan_errors.some((e) => e.kind === 'lockfile' && e.target === 'lp/package-lock.json'));
});
