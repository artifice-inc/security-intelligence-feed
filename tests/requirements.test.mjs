import test from 'node:test';
import assert from 'node:assert/strict';
import { checkRequirementsPinned, findUrlCredentials } from '../src/inventory/requirements.mjs';
import { detectStack, hasNoMaterial, ecosystemOfLockfile, isRequirementsFile, DEFAULT_LOCKFILES } from '../src/inventory/detect-stack.mjs';
import { requiredOsvEcosystems } from '../src/match/scan-status.mjs';
import { computePriority } from '../src/match/priority.mjs';
import { assembleItems } from '../src/match/assemble.mjs';
import { makeTree } from './helpers/tree.mjs';
import { NOW, PROVENANCE } from './helpers/match-fixtures.mjs';

const HASH = 'sha256:' + 'a'.repeat(64);

test('requirements: 固定されている形は ok', () => {
  const pinned = [
    'a==1.0', 'A_b.c[x,y]==1.0.0', 'a===1.0', `a==1.0 --hash=${HASH}`, '# コメント', '', '   ',
    'a==1.0 ; python_version < "3.11"', 'b==2.0  # 末尾のコメント', '--index-url https://user:pass@example/simple',
    '-i https://example/simple', '--extra-index-url=https://example/simple', '--require-hashes', '--no-binary :all:', 'c==1.0!post1+local.1',
  ];
  for (const line of pinned) assert.deepEqual(checkRequirementsPinned(line), { ok: true, lines: [] }, line);
  assert.deepEqual(checkRequirementsPinned(`a==1.0 \\\n    --hash=${HASH} \\\n    --hash=${HASH}\nb==2.0\n`), { ok: true, lines: [] });
  assert.deepEqual(checkRequirementsPinned('a==1.0\r\nb==2.0\r\n'), { ok: true, lines: [] });
});

test('requirements: 固定されていない形は行番号だけを返す（折り返しは最初の行）', () => {
  const bad = ['a>=1.0', 'a', 'a==1.*', 'a~=1.0', 'a @ https://example.test/a.whl', 'git+https://example.test/a.git', '-r base.txt', '--requirement base.txt',
    '-c c.txt', '--constraint c.txt', '-e .', '--editable .', '--unknown-option', 'a==', '==1.0', 'a==1.0 b==2.0', 'a!=1.0'];
  for (const line of bad) assert.deepEqual(checkRequirementsPinned(line), { ok: false, lines: [1] }, line);
  const text = ['a==1.0', '', '# c', 'b>=2 \\', '   --hash=' + HASH, 'c==3', '-r x.txt'].join('\n');
  assert.deepEqual(checkRequirementsPinned(text), { ok: false, lines: [4, 7] });
  // 折り返しの最後に固定でない行が来ても、最初の行の番号になる
  assert.deepEqual(checkRequirementsPinned('a==1.0\nb \\\n>=2\n'), { ok: false, lines: [2] });
});

test('requirements: 行番号は最大20件で、行の中身を返さない', () => {
  const many = Array.from({ length: 30 }, (_, i) => `pkg${i}>=1`).join('\n');
  const result = checkRequirementsPinned(many);
  assert.equal(result.lines.length, 20);
  assert.deepEqual(Object.keys(result), ['ok', 'lines']);
  assert.ok(result.lines.every((n, i) => n === i + 1));
});

test('findUrlCredentials: 認証情報つきの URL の行番号だけを返し、環境変数の参照と https 以外は対象外', () => {
  const text = [
    '--index-url https://user:pass@x/simple', // 1
    'ok==1', // 2
    '--extra-index-url https://token@x/simple', // 3
    'git+https://token@github.com/o/r.git#egg=r', // 4
    '--index-url https://${PIP_USER}:${PIP_PASS}@x/simple', // 5 対象外
    'git+ssh://git@github.com/o/r.git', // 6 対象外
    '--index-url https://x/simple', // 7 対象外
    '# https://u:p@commented.example/simple', // 8 コメントの中も含めて検出
    'a @ https://x/y@z', // 9 パスの @ は userinfo ではない
    '--index-url https://${PIP_USER}:secret@x/simple', // 10 一部だけ参照は検出
    '--index-url HTTPS://U:P@x/simple', // 11
  ].join('\n');
  assert.deepEqual(findUrlCredentials(text), [1, 3, 4, 8, 10, 11]);
  assert.deepEqual(findUrlCredentials(''), []);
});

test('lockfile の対応表: 既知の名前だけが対応し、表にない名前は null（npm 扱いにしない）', () => {
  const expected = { 'package-lock.json': 'npm', 'pnpm-lock.yaml': 'npm', 'yarn.lock': 'npm', 'composer.lock': 'Packagist', 'poetry.lock': 'PyPI', 'uv.lock': 'PyPI', 'Pipfile.lock': 'PyPI', 'pdm.lock': 'PyPI' };
  for (const [name, eco] of Object.entries(expected)) assert.equal(ecosystemOfLockfile(`sub/dir/${name}`), eco, name);
  for (const name of ['requirements.txt', 'requirements/prod.txt', 'a/b/dev.txt']) assert.equal(ecosystemOfLockfile(name), 'PyPI', name);
  for (const name of ['Gemfile.lock', 'Cargo.lock', 'go.sum', 'requirements.txt.bak']) assert.equal(ecosystemOfLockfile(name), null, name);
  assert.ok(isRequirementsFile('x/prod.txt') && !isRequirementsFile('x/prod.lock'));
  assert.ok(DEFAULT_LOCKFILES.includes('requirements.txt') && DEFAULT_LOCKFILES.includes('poetry.lock'));
});

test('detectStack: 固定されていない requirements は lockfiles に入れず、files に requirements-unpinned で残す', () => {
  const root = makeTree({ 'requirements.txt': 'requests>=2.0\n', 'README.md': 'x' });
  const detected = detectStack(root);
  assert.deepEqual(detected.lockfiles, []);
  assert.deepEqual(detected.files.map((f) => [f.path, f.kind]), [['requirements.txt', 'requirements-unpinned']]);
  assert.deepEqual(detected.problems, [], 'エラーは detectProject が出す（problems には積まない）');
  assert.equal(hasNoMaterial({ lockfiles: detected.lockfiles, files: detected.files }), false);
  assert.deepEqual(detected.runtimes.python, { version: null, constraint: null, source: null }, 'Python の手がかりがあるので python のキーができる（版は未確定）');
});

test('detectStack: 固定された requirements と、名前に requirements を含まない prod.txt を stack.yml で指定できる', () => {
  const root = makeTree({
    'requirements.txt': 'requests==2.31.0\n', 'requirements/prod.txt': 'flask==3.0.0\n',
    '.security/stack.yml': 'lockfiles:\n  - requirements/prod.txt\n  - requirements.txt\n  - Gemfile.lock\n',
    'Gemfile.lock': 'x', 'pyproject.toml': '[project]\n', 'Pipfile': 'x', '.python-version': '3.12.7\n',
  });
  const detected = detectStack(root);
  assert.deepEqual(detected.lockfiles, ['Gemfile.lock', 'requirements.txt', 'requirements/prod.txt']);
  const kinds = Object.fromEntries(detected.files.map((f) => [f.path, f.kind]));
  assert.equal(kinds['requirements/prod.txt'], 'lockfile');
  assert.equal(kinds['pyproject.toml'], 'pyproject');
  assert.equal(kinds.Pipfile, 'pipfile');
  assert.equal(kinds['.python-version'], 'python-version');
  assert.deepEqual(requiredOsvEcosystems({ lockfiles: ['requirements/prod.txt', 'Gemfile.lock'] }), ['PyPI'], '表にない名前は OSV の DB を要求しない');
});

test('detectStack: poetry.lock など4つの lockfile を既定で検出する', () => {
  const root = makeTree({ 'poetry.lock': 'x', 'uv.lock': 'x', 'Pipfile.lock': '{}', 'pdm.lock': 'x' });
  assert.deepEqual(detectStack(root).lockfiles, ['Pipfile.lock', 'pdm.lock', 'poetry.lock', 'uv.lock']);
});

test('requiredOsvEcosystems: 順序は ECOSYSTEMS の順（npm と composer の案件で変わらない）', () => {
  assert.deepEqual(requiredOsvEcosystems({ lockfiles: ['composer.lock', 'package-lock.json'] }), ['npm', 'Packagist']);
  assert.deepEqual(requiredOsvEcosystems({ lockfiles: ['poetry.lock', 'composer.lock', 'yarn.lock'] }), ['npm', 'Packagist', 'PyPI']);
  assert.deepEqual(requiredOsvEcosystems({ lockfiles: ['poetry.lock'] }), ['PyPI']);
  assert.deepEqual(requiredOsvEcosystems({ lockfiles: ['composer.lock'] }), ['Packagist']);
  assert.deepEqual(requiredOsvEcosystems({ lockfiles: [] }), []);
});

// ---- MAL（悪性パッケージ）は常に P0 ------------------------------------------------------

const malDetection = (overrides = {}) => ({
  lockfile: 'poetry.lock', package: 'evil', ecosystem: 'PyPI', installed_version: '1.0.0', judgement: 'affected',
  osv_id: 'MAL-2026-1', aliases: ['MAL-2026-1'], title: 'malware', fixed_versions: [], ...overrides,
});
const assemble = (detections, exposure = null, advisories = new Map()) => assembleItems({ detections, index: advisories, exposure, now: NOW, provenance: PROVENANCE });

test('MAL: affected は exposure・重大度・EPSS を問わず P0', () => {
  for (const exposure of [null, 'internal', 'internet']) {
    assert.equal(assemble([malDetection({ severity_hint: 'low' })], exposure)[0].priority, 'P0', String(exposure));
  }
  assert.equal(computePriority({ judgement: 'affected', kev: false, severity: null, epssPercentile: 0, exposure: null, malicious: true }), 'P0');
});

test('MAL: CVE とつながった item も P0。needs_review の MAL は P3。MAL でなければ今までどおり', () => {
  const linked = assemble([malDetection({ aliases: ['MAL-2026-1', 'CVE-2026-5'] })], 'internal');
  assert.equal(linked[0].priority, 'P0');
  assert.equal(assemble([malDetection({ judgement: 'needs_review' })], 'internet')[0].priority, 'P3');
  assert.equal(assemble([malDetection({ osv_id: 'GHSA-x', aliases: ['GHSA-x'] })], 'internal')[0].priority, 'P2');
  assert.equal(computePriority({ judgement: 'needs_review', kev: true, malicious: true }), 'P3');
  assert.equal(computePriority({ judgement: 'affected', kev: false, severity: 'high', exposure: 'internet' }), 'P1');
});

test('MAL: npm の lockfile でも同じ扱い', () => {
  assert.equal(assemble([malDetection({ lockfile: 'package-lock.json', ecosystem: 'npm' })], 'internal')[0].priority, 'P0');
});
