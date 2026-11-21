import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, readFileSync, readdirSync, existsSync, mkdirSync, renameSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { exportInventory, evaluateExport } from '../src/inventory/export-inventory.mjs';
import { sha256Hex } from '../src/lib/hash.mjs';
import { makeTree } from './helpers/tree.mjs';

const NOW = new Date('2026-11-19T00:00:00Z');
const base = () => mkdtempSync(path.join(tmpdir(), 'si-exp-'));
const run = (projectDir, outDir, io) => exportInventory({ projectDir, project: 'demo', outDir, now: NOW, sourceRef: 'main', sourceCommit: 'abc', io });
const leftovers = (dir) => readdirSync(dir).filter((n) => n !== 'demo');

// 前回の出力を作っておく（失敗しても消えないことの確認用）
function withPrevious() {
  const out = path.join(base(), 'demo');
  run(makeTree({ 'package-lock.json': '{"previous":true}', '.nvmrc': '20.1.0' }), out);
  return { out, parent: path.dirname(out), previous: readFileSync(path.join(out, 'manifest.json'), 'utf8') };
}

test('認証情報つきの URL がある requirements は export を拒否する。前回の出力は消えず、出力先も一時ディレクトリも作られない', () => {
  const { out, parent, previous } = withPrevious();
  const project = makeTree({ 'requirements.txt': 'a==1.0\n--index-url https://user:pass@example.test/simple\n' });
  assert.throws(() => run(project, out), (error) => /認証情報を含む URL があるため export できません: requirements\.txt（2行目）/.test(error.message) && !/user|pass/.test(error.message.replace('認証情報', '')));
  assert.equal(readFileSync(path.join(out, 'manifest.json'), 'utf8'), previous);
  assert.ok(existsSync(path.join(out, 'files', 'package-lock.json')));
  assert.deepEqual(leftovers(parent), []);
  const fresh = path.join(base(), 'new');
  assert.throws(() => run(project, fresh), /認証情報/);
  assert.ok(!existsSync(fresh));
  assert.deepEqual(leftovers(path.dirname(fresh)), []);
});

test('Pipfile・pyproject.toml・poetry.lock の URL にも同じ検査をかける。環境変数の参照だけなら通る', () => {
  for (const name of ['Pipfile', 'pyproject.toml']) {
    const project = makeTree({ 'poetry.lock': '{}', [name]: 'url = "https://token@git.example.test/simple"\n' });
    assert.throws(() => run(project, path.join(base(), 'demo')), new RegExp(name.replace('.', '\\.')));
  }
  const ok = makeTree({ Pipfile: 'url = "https://${USER}:${TOKEN}@git.example.test/simple"\n', 'poetry.lock': '{}' });
  assert.doesNotThrow(() => run(ok, path.join(base(), 'demo')));
});

test('書き込みの失敗（3つ目のファイル）: 前回の出力がそのまま残り、一時ディレクトリが残らない', () => {
  const { out, parent, previous } = withPrevious();
  const project = makeTree({ 'package-lock.json': '{}', '.nvmrc': '22.0.0', 'package.json': '{}', Dockerfile: 'FROM node:22\n' });
  let count = 0;
  const writeFile = (file, data) => { count += 1; if (count === 3) throw new Error('disk full'); writeFileSync(file, data); };
  assert.throws(() => run(project, out, { writeFile }), /disk full/);
  assert.equal(readFileSync(path.join(out, 'manifest.json'), 'utf8'), previous);
  assert.deepEqual(readdirSync(path.join(out, 'files')).sort(), ['.nvmrc', 'package-lock.json']);
  assert.deepEqual(leftovers(parent), []);
});

test('2つ目の rename の失敗: 前回の出力が outDir に戻り、一時ディレクトリが残らない', () => {
  const { out, parent, previous } = withPrevious();
  const project = makeTree({ 'package-lock.json': '{}' });
  let count = 0;
  const rename = (from, to) => { count += 1; if (count === 2) throw new Error('rename failed'); renameSync(from, to); };
  assert.throws(() => run(project, out, { rename }), /rename failed/);
  assert.equal(readFileSync(path.join(out, 'manifest.json'), 'utf8'), previous);
  assert.deepEqual(leftovers(parent), []);
});

test('検出のあと・読み取りの前にファイルが変わったら、sha256 の不一致で例外になり何も書かれない', () => {
  const { out, parent, previous } = withPrevious();
  const project = makeTree({ 'requirements.txt': 'a==1.0\n' });
  const readFile = (file) => (file.endsWith('requirements.txt') ? Buffer.from('a==2.0\n') : readFileSync(file));
  assert.throws(() => run(project, out, { readFile }), /検出のあとでファイルが変わりました: requirements\.txt/);
  assert.equal(readFileSync(path.join(out, 'manifest.json'), 'utf8'), previous);
  assert.deepEqual(leftovers(parent), []);
});

test('読み取りの時点で認証情報つきに変わった場合も、検査した内容と書き出す内容が同じなので書き出さない', () => {
  const project = makeTree({ 'requirements.txt': 'a==1.0\n' });
  const out = path.join(base(), 'demo');
  const poisoned = Buffer.from('a==1.0\n--index-url https://u:p@x/simple\n');
  assert.throws(() => run(project, out, { readFile: () => poisoned }), /検出のあとでファイルが変わりました/);
  assert.ok(!existsSync(out));
});

test('正常な回: 書き出したファイルの sha256 が manifest の値と一致し、evaluateExport が fresh、.bak が残らない', () => {
  const { out, parent } = withPrevious();
  const project = makeTree({ 'requirements.txt': 'requests==2.31.0\n', 'package-lock.json': '{}' });
  const { manifest, leftovers: left } = run(project, out);
  assert.deepEqual(left, []);
  for (const file of manifest.files) assert.equal(sha256Hex(readFileSync(path.join(out, 'files', file.path))), file.sha256);
  assert.equal(evaluateExport({ dir: out, now: NOW }).status, 'fresh');
  assert.deepEqual(leftovers(parent), []);
  assert.ok(!existsSync(path.join(out, 'files', '.nvmrc')), '前回の出力の中身は新しい出力に混ざらない');
});

test('前回の途中終了で残った .bak-* は、次の実行の結果で警告のために返る', () => {
  const out = path.join(base(), 'demo');
  mkdirSync(`${out}.bak-99999`, { recursive: true });
  const { leftovers: left } = run(makeTree({ 'package-lock.json': '{}' }), out);
  assert.deepEqual(left, ['demo.bak-99999']);
});

test('手がかりのない既存の案件の export: runtimes_detected に python のキーが増えない', () => {
  const out = path.join(base(), 'demo');
  const { manifest } = run(makeTree({ 'package-lock.json': '{}', Dockerfile: 'FROM node:22.11.0\n' }), out);
  assert.deepEqual(Object.keys(manifest.runtimes_detected).sort(), ['node', 'php']);
});
