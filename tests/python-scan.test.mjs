import test from 'node:test';
import assert from 'node:assert/strict';
import { writeFileSync, existsSync, readFileSync, readdirSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { detectProject } from '../src/match/match-project.mjs';
import { prepareRequirementsInputs } from '../src/match/requirements-input.mjs';
import { buildSummary, buildLocalScan } from '../src/local/check-summary.mjs';
import { decideScanStatus } from '../src/match/scan-status.mjs';
import { detectStack } from '../src/inventory/detect-stack.mjs';
import { makeTree } from './helpers/tree.mjs';
import { stubExec } from './helpers/match-fixtures.mjs';

const OSV_ALL = { npm: true, Packagist: true, PyPI: true };
const RUNTIME_DATA = { php: null, nodejs: null };
const siRequirementDirs = () => readdirSync(os.tmpdir()).filter((n) => n.startsWith('si-req-')).sort();

// detectStack の結果から、inventory に相当するものを作る
function inventoryFor(root, overrides = {}) {
  const d = detectStack(root);
  return { project: 'demo', mode: 'pull', monitor_ref: 'main', source_commit: 'c', inventory_as_of: '2026-11-19T00:00:00Z', files: d.files, runtimes: d.runtimes, exposure: 'internal', lockfiles: d.lockfiles, ...overrides };
}
const detect = (root, inventory, exec, extra = {}) => detectProject({ inventory, workdir: root, exec, scannerPath: 'osv', dbDir: '/db', osvAvailable: OSV_ALL, runtimeData: RUNTIME_DATA, packagistAdvisories: null, ...extra });
const pypiOutput = (scanPath, vulns = []) => JSON.stringify({ results: [{ source: { path: scanPath, type: 'lockfile' }, packages: [{ package: { name: 'requests', version: '2.31.0', ecosystem: 'PyPI' }, vulnerabilities: vulns }] }] });
// 依存パッケージ（lockfile）の照合のエラーだけ。python の手がかり（requirements）から作られる CPython の版・データのエラーは P-C の領分
const lockfileErrors = (result) => result.errors.filter((e) => e.kind === 'lockfile' || e.kind === 'scanner');
const scanPathOf = (args) => args.find((a) => a.startsWith('--lockfile=')).slice('--lockfile='.length);

test('prod.txt を stack.yml で指定: 引数は requirements.txt:<一時ディレクトリ>/requirements.txt、検出の lockfile は元のパス、終了後は一時ディレクトリが消える', async () => {
  const root = makeTree({ 'requirements/prod.txt': 'requests==2.31.0\n', '.security/stack.yml': 'lockfiles:\n  - requirements/prod.txt\n' });
  const inventory = inventoryFor(root);
  const before = siRequirementDirs();
  let seenScanPath;
  const exec = async (cmd, args) => {
    const arg = args.find((a) => a.startsWith('--lockfile='));
    assert.match(arg, /^--lockfile=requirements\.txt:/);
    seenScanPath = arg.slice('--lockfile=requirements.txt:'.length);
    assert.equal(path.basename(seenScanPath), 'requirements.txt');
    assert.ok(seenScanPath.startsWith(os.tmpdir()) || seenScanPath.startsWith(path.resolve(os.tmpdir())), '元のパスではなく一時ファイルを渡す');
    assert.equal(readFileSync(seenScanPath, 'utf8'), 'requests==2.31.0\n');
    const vuln = { id: 'GHSA-aaaa-bbbb-cccc', aliases: ['CVE-2026-1'], summary: 's', affected: [{ package: { ecosystem: 'PyPI', name: 'requests' }, ranges: [{ type: 'ECOSYSTEM', events: [{ introduced: '0' }, { fixed: '2.32.0' }] }] }] };
    return { code: 1, stdout: pypiOutput(seenScanPath, [vuln]) };
  };
  const result = await detect(root, inventory, exec);
  assert.equal(result.dependency_checks.osv, 'ok');
  assert.deepEqual(lockfileErrors(result), [], 'requirements の照合自体にエラーはない（python の版が未確定のエラーは別）');
  const packages = result.detections.filter((d) => d.ecosystem === 'PyPI');
  assert.equal(packages.length, 1);
  assert.equal(packages[0].lockfile, 'requirements/prod.txt');
  assert.deepEqual(packages[0].fixed_versions, ['2.32.0']);
  assert.ok(!existsSync(path.dirname(seenScanPath)));
  assert.deepEqual(siRequirementDirs(), before);
});

test('スキャナが失敗しても一時ディレクトリを残さない', async () => {
  const root = makeTree({ 'requirements.txt': 'requests==2.31.0\n' });
  const before = siRequirementDirs();
  const failed = await detect(root, inventoryFor(root), stubExec(127, ''));
  assert.equal(failed.dependency_checks.osv, 'unavailable');
  const thrown = detect(root, inventoryFor(root), async () => { throw new Error('exec 失敗'); });
  await assert.rejects(thrown, /exec 失敗/);
  assert.deepEqual(siRequirementDirs(), before);
});

test('検査とスキャンの間に requirements.txt が固定でなくなったら、スキャンせず内容が変わったエラー（sha256 の比較が先）', async () => {
  const root = makeTree({ 'requirements.txt': 'requests==2.31.0\n' });
  const inventory = inventoryFor(root);
  writeFileSync(path.join(root, 'requirements.txt'), 'requests>=2.0\n');
  const exec = stubExec(0, '{"results":[]}');
  const result = await detect(root, inventory, exec);
  assert.equal(exec.calls.length, 0, 'スキャナを実行しない');
  assert.equal(result.dependency_checks.osv, 'unavailable');
  assert.deepEqual(lockfileErrors(result).map((e) => [e.kind, e.target, e.message]), [['lockfile', 'requirements.txt', 'インベントリの作成後に内容が変わったため照合できません']]);
});

test('別の固定版に書き換えられても（== のまま）スキャンされない。中央は partial、ローカルは照合不完全', async () => {
  const root = makeTree({ 'requirements.txt': 'requests==2.31.0\n' });
  const inventory = inventoryFor(root);
  writeFileSync(path.join(root, 'requirements.txt'), 'requests==2.32.0\n');
  const exec = stubExec(0, '{"results":[]}');
  const result = await detect(root, inventory, exec);
  assert.equal(exec.calls.length, 0);
  assert.equal(result.errors[0].message, 'インベントリの作成後に内容が変わったため照合できません');
  const central = decideScanStatus({ inventory, inventoryStatus: 'fresh', sourceResults: { kev: { ok: true }, epss: { ok: true }, endoflife: { ok: true } }, osvDb: { PyPI: true }, packagistFullSyncAt: null, scanErrors: result.errors });
  assert.equal(central.scan_status, 'partial');
  const summary = buildSummary({ inventory, osvAvailable: OSV_ALL, checks: result.dependency_checks, scanErrors: result.errors, items: [], runtimeData: RUNTIME_DATA });
  assert.equal(summary.rows[0].state, 'unavailable');
  assert.equal(buildLocalScan({ summary, scanErrors: result.errors, pullOk: true, localOsvDb: {}, central: null, inventory }).complete, false);
});

test('スキャナの実行中に元ファイルを書き換えても、スキャンされるのは検査した内容（一時ファイル）', async () => {
  const root = makeTree({ 'requirements.txt': 'requests==2.31.0\n' });
  const inventory = inventoryFor(root);
  let scanned;
  const exec = async (cmd, args) => {
    writeFileSync(path.join(root, 'requirements.txt'), 'requests==9.9.9\n');
    scanned = readFileSync(scanPathOf(args).replace('requirements.txt:', ''), 'utf8');
    return { code: 0, stdout: pypiOutput(scanPathOf(args).replace('requirements.txt:', '')) };
  };
  const result = await detect(root, inventory, exec);
  assert.equal(scanned, 'requests==2.31.0\n');
  assert.equal(result.dependency_checks.osv, 'ok');
});

test('固定されていない requirements だけの案件: スキャナに渡さず、行番号つきのエラー（行の中身は載せない）', async () => {
  const root = makeTree({ 'requirements.txt': 'requests>=2.0\nflask==3.0.0\nsecret-pkg\n' });
  const inventory = inventoryFor(root);
  assert.deepEqual(inventory.lockfiles, []);
  const exec = stubExec(0, '{"results":[]}');
  const result = await detect(root, inventory, exec);
  assert.equal(exec.calls.length, 0);
  assert.equal(result.dependency_checks.osv, 'unavailable');
  assert.equal(lockfileErrors(result).length, 1);
  assert.deepEqual(lockfileErrors(result)[0], { kind: 'lockfile', target: 'requirements.txt', message: '版を == で固定していない行があるため照合できません（1行目、3行目）' });
  assert.ok(!JSON.stringify(result).includes('requests>=2.0') && !JSON.stringify(result).includes('secret-pkg'));
  assert.ok(!JSON.stringify(result.detections).includes('requests'));
  // 中央: partial（エラーあり）。材料なしのエラーは出ない
  const status = decideScanStatus({ inventory, inventoryStatus: 'fresh', sourceResults: { kev: { ok: true }, epss: { ok: true }, endoflife: { ok: true } }, osvDb: {}, packagistFullSyncAt: null, scanErrors: result.errors });
  assert.equal(status.scan_status, 'partial');
  // ローカル: 行が unavailable で complete にならない
  const summary = buildSummary({ inventory, osvAvailable: OSV_ALL, checks: result.dependency_checks, scanErrors: result.errors, items: [], runtimeData: RUNTIME_DATA });
  assert.deepEqual(summary.rows.filter((r) => r.kind === 'lockfile').map((r) => [r.target, r.kind, r.state]), [['requirements.txt', 'lockfile', 'unavailable']]);
  const local = buildLocalScan({ summary, scanErrors: result.errors, pullOk: true, localOsvDb: {}, central: { provenance: {} }, inventory });
  assert.equal(local.complete, false);
});

test('固定済みの requirements と固定でないものが混在: 固定済みはスキャンされ、固定でないものだけ照合不能', async () => {
  const root = makeTree({ 'requirements.txt': 'requests==2.31.0\n', 'requirements/dev.txt': 'pytest\n', '.security/stack.yml': 'lockfiles:\n  - requirements.txt\n  - requirements/dev.txt\n' });
  const inventory = inventoryFor(root);
  assert.deepEqual(inventory.lockfiles, ['requirements.txt']);
  const exec = async (cmd, args) => ({ code: 0, stdout: pypiOutput(scanPathOf(args).replace('requirements.txt:', '')) });
  const result = await detect(root, inventory, exec);
  assert.deepEqual(lockfileErrors(result).map((e) => e.target), ['requirements/dev.txt']);
  assert.equal(result.dependency_checks.osv, 'unavailable');
  const summary = buildSummary({ inventory, osvAvailable: OSV_ALL, checks: result.dependency_checks, scanErrors: result.errors, items: [], runtimeData: RUNTIME_DATA });
  assert.deepEqual(summary.rows.filter((r) => r.kind === 'lockfile').map((r) => [r.target, r.state]), [['requirements.txt', 'unavailable'], ['requirements/dev.txt', 'unavailable']], 'checks.osv が unavailable の間は ok にしない');
});

test('表にない名前（Gemfile.lock）: スキャナに渡さず、エラー1件で partial。黙って ok にならない', async () => {
  const root = makeTree({ 'Gemfile.lock': 'x', '.security/stack.yml': 'lockfiles:\n  - Gemfile.lock\n' });
  const inventory = inventoryFor(root);
  const exec = stubExec(0, '{"results":[]}');
  const result = await detect(root, inventory, exec);
  assert.equal(exec.calls.length, 0);
  assert.deepEqual(result.errors, [{ kind: 'lockfile', target: 'Gemfile.lock', message: 'この lockfile の形式には対応していません' }]);
  assert.equal(result.dependency_checks.osv, 'unavailable');
  const status = decideScanStatus({ inventory, inventoryStatus: 'fresh', sourceResults: { kev: { ok: true }, epss: { ok: true }, endoflife: { ok: true } }, osvDb: {}, packagistFullSyncAt: null, scanErrors: result.errors });
  assert.equal(status.scan_status, 'partial');
});

test('npm と PyPI の lockfile が混在: npm は元のパス、poetry.lock も元のパスを読む（requirements だけが一時ファイル）', async () => {
  const root = makeTree({ 'package-lock.json': '{}', 'poetry.lock': 'x', 'requirements.txt': 'requests==2.31.0\n' });
  const inventory = inventoryFor(root);
  const exec = stubExec(0, JSON.stringify({ results: [] }));
  await detect(root, inventory, exec);
  const args = exec.calls[0].args.filter((a) => a.startsWith('--lockfile='));
  assert.equal(args[0], `--lockfile=${path.join(root, 'package-lock.json')}`);
  assert.equal(args[1], `--lockfile=${path.join(root, 'poetry.lock')}`);
  assert.match(args[2], /^--lockfile=requirements\.txt:.*requirements\.txt$/);
});

test('PyPI の DB が使えなければ、PyPI の lockfile をスキャンせず unavailable（npm の DB があっても）', async () => {
  const root = makeTree({ 'poetry.lock': 'x' });
  const exec = stubExec(0, '{"results":[]}');
  const result = await detect(root, inventoryFor(root), exec, { osvAvailable: { npm: true, Packagist: true, PyPI: false } });
  assert.equal(exec.calls.length, 0);
  assert.equal(result.dependency_checks.osv, 'unavailable');
});

test('2つ目のファイルで一時ファイルの書き込みが失敗しても、作成済みの一時ディレクトリが残らない', () => {
  const root = makeTree({ 'requirements.txt': 'a==1.0\n', 'requirements/prod.txt': 'b==2.0\n', '.security/stack.yml': 'lockfiles:\n  - requirements.txt\n  - requirements/prod.txt\n' });
  const inventory = inventoryFor(root);
  const before = siRequirementDirs();
  let count = 0;
  const writeFile = (file, data) => { count += 1; if (count === 2) throw new Error('disk full'); writeFileSync(file, data); };
  assert.throws(() => prepareRequirementsInputs({ workdir: root, files: inventory.lockfiles, inventory, io: { writeFile } }), /disk full/);
  assert.equal(count, 2);
  assert.deepEqual(siRequirementDirs(), before);
});
