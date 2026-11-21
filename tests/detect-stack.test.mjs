import test from 'node:test';
import assert from 'node:assert/strict';
import { detectStack, isSafeRelativePath } from '../src/inventory/detect-stack.mjs';
import { makeTree } from './helpers/tree.mjs';
import { buildInventory } from '../src/inventory/build-inventory.mjs';

test('stack.yml の申告が最優先で、版が確定する', () => {
  const root = makeTree({
    '.security/stack.yml': 'runtimes:\n  php: "8.3.14"\n  node: "22.11.0"\nexposure: internal\n',
    '.nvmrc': 'v20.0.0\n', 'Dockerfile': 'FROM php:8.1.2-fpm\n', 'composer.lock': '{}', 'package-lock.json': '{}',
  });
  const result = detectStack(root);
  assert.deepEqual(result.runtimes.php, { version: '8.3.14', constraint: null, source: '.security/stack.yml' });
  assert.deepEqual(result.runtimes.node, { version: '22.11.0', constraint: null, source: '.security/stack.yml' });
  assert.equal(result.stack.exposure, 'internal');
  assert.deepEqual(result.lockfiles, ['composer.lock', 'package-lock.json']);
  assert.ok(result.files.every((f) => /^[0-9a-f]{64}$/.test(f.sha256)));
});

test('申告がなければ .nvmrc → Dockerfile → engines の順', () => {
  const root = makeTree({ '.nvmrc': 'v22.11.0\n', 'package.json': '{"engines":{"node":">=18"}}', 'Dockerfile': 'FROM node:20.1.0-alpine\nFROM php:8.2-apache\n' });
  const result = detectStack(root);
  assert.equal(result.runtimes.node.version, '22.11.0');
  assert.equal(result.runtimes.node.source, '.nvmrc');
  assert.deepEqual(result.runtimes.php, { version: null, constraint: '8.2', source: 'Dockerfile' });
});

test('制約しか分からない場合は version が null（engines は完全一致でも制約扱い）', () => {
  const root = makeTree({ 'package.json': '{"engines":{"node":"22.11.0"}}', 'composer.json': '{"require":{"php":">=8.1"}}' });
  const result = detectStack(root);
  assert.deepEqual(result.runtimes.node, { version: null, constraint: '22.11.0', source: 'package.json' });
  assert.deepEqual(result.runtimes.php, { version: null, constraint: '>=8.1', source: 'composer.json' });
});

test('composer.json の config.platform.php は版として扱う。何もなければ全て null', () => {
  const root = makeTree({ 'composer.json': '{"config":{"platform":{"php":"8.3.14"}}}' });
  assert.equal(detectStack(root).runtimes.php.version, '8.3.14');
  assert.deepEqual(detectStack(makeTree({ 'README.md': 'x' })).runtimes.node, { version: null, constraint: null, source: null });
});

test('stack.yml の lockfiles で置き換える。作業ツリー外を指すパスは拒否する', () => {
  const root = makeTree({
    '.security/stack.yml': 'lockfiles:\n  - apps/web/package-lock.json\n  - ../../etc/passwd\n  - missing/composer.lock\n',
    'apps/web/package-lock.json': '{}', 'package-lock.json': '{}',
  });
  const result = detectStack(root);
  assert.deepEqual(result.lockfiles, ['apps/web/package-lock.json']);
  assert.equal(result.problems.filter((p) => p.kind === 'lockfile').length, 2);
  assert.equal(isSafeRelativePath('/abs'), false);
  assert.equal(isSafeRelativePath('a/../b'), false);
  assert.equal(isSafeRelativePath('a/b.json'), true);
});

test('不正な stack.yml は無視して自動検出で補い、問題として返す', () => {
  const root = makeTree({ '.security/stack.yml': 'exposure: nowhere\n', '.nvmrc': '22.1.0' });
  const result = detectStack(root);
  assert.equal(result.runtimes.node.version, '22.1.0');
  assert.equal(result.problems[0].kind, 'inventory');
});

test('stack.yml の os を読み、inventory に載せる。スキーマ外の値では stack.yml 全体が無視される', () => {
  const linux = makeTree({ '.security/stack.yml': 'os: linux\nexposure: internal\n', 'package-lock.json': '{}' });
  assert.equal(detectStack(linux).stack.os, 'linux');
  assert.equal(buildInventory({ root: linux, project: 'p', mode: 'pull', monitorRef: 'm', sourceCommit: null, inventoryAsOf: null, exposure: null }).inventory.os, 'linux');
  const none = makeTree({ '.security/stack.yml': 'exposure: internal\n', 'package-lock.json': '{}' });
  assert.equal(detectStack(none).stack.os, null);
  const bad = makeTree({ '.security/stack.yml': 'os: beos\nexposure: internal\n', 'package-lock.json': '{}' });
  const result = detectStack(bad);
  assert.equal(result.stack, null);
  assert.equal(result.problems[0].kind, 'inventory');
});
