import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync, symlinkSync, readdirSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { validateFeed } from '../src/feed/validate-feed.mjs';
import { inspectTree, needlesFromPrivateConfig, SECRET_PATTERNS } from '../src/feed/inspect-tree.mjs';
import { makeValidFeed, writeJson } from './helpers/feed-fixture.mjs';
import { ROOT_DIR } from '../src/lib/config.mjs';

const readJson = (dir, rel) => JSON.parse(readFileSync(path.join(dir, rel), 'utf8'));
const hasViolation = (violations, file) => violations.some((v) => v.file === file);

test('validateFeed: 正しい一式は違反0件、空のディレクトリは違反', () => {
  assert.deepEqual(validateFeed(makeValidFeed()), []);
  assert.ok(validateFeed(mkdtempSync(path.join(tmpdir(), 'feed-empty-'))).length > 0);
});

test('validateFeed: 必須ファイルの欠落とアドバイザリ0件', () => {
  const dir = makeValidFeed();
  rmSync(path.join(dir, 'kev.json'));
  rmSync(path.join(dir, 'advisories'), { recursive: true });
  const violations = validateFeed(dir);
  assert.ok(hasViolation(violations, 'kev.json'));
  assert.ok(hasViolation(violations, 'advisories/'));
});

test('validateFeed: シンボリックリンク・許可外のパス・隠しファイル・..', () => {
  const dir = makeValidFeed();
  symlinkSync(path.join(dir, 'kev.json'), path.join(dir, 'link.json'));
  writeJson(dir, 'extra.json', {});
  writeJson(dir, 'advisories/.hidden.json', {});
  writeJson(dir, 'advisories/a..b.json', {});
  const violations = validateFeed(dir);
  for (const file of ['link.json', 'extra.json', 'advisories/.hidden.json', 'advisories/a..b.json']) assert.ok(hasViolation(violations, file), file);
});

test('validateFeed: スキーマ違反・照合由来の情報源・読めない版', () => {
  const dir = makeValidFeed();
  writeJson(dir, 'kev.json', { ok: true });
  const advisory = readJson(dir, 'advisories/CVE-2015-6764.json');
  advisory.sources.push({ ...advisory.sources[0], name: 'osv-scanner' });
  writeJson(dir, 'advisories/CVE-2015-6764.json', advisory);
  writeJson(dir, 'feed-format.json', { format_version: 2 });
  const violations = validateFeed(dir);
  assert.ok(hasViolation(violations, 'kev.json'));
  assert.ok(hasViolation(violations, 'advisories/CVE-2015-6764.json'));
  assert.equal(violations.find((v) => v.file === 'feed-format.json').kind, 'unsupported_format');
});

test('validateFeed: health.json の projects・last_run の余計な項目・last_error.message は違反', () => {
  for (const mutate of [(h) => { h.projects = {}; }, (h) => { h.last_run.reason = 'free text'; }, (h) => { h.sources.kev.last_error = { kind: 'network', at: 'x', message: 'free text' }; }]) {
    const dir = makeValidFeed();
    const health = readJson(dir, 'health.json');
    mutate(health);
    writeJson(dir, 'health.json', health);
    assert.ok(hasViolation(validateFeed(dir), 'health.json'));
  }
});

const SAMPLE_WORD = 'example-app';
const fakeToken = () => 'ghp_' + 'a'.repeat(36);

test('inspectTree: 内容の一致では語そのものを返さない', () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'tree-'));
  writeFileSync(path.join(dir, 'a.txt'), `この文に Example-App が含まれる ${fakeToken()}`);
  const result = inspectTree({ dir, needles: [SAMPLE_WORD] });
  assert.deepEqual(result.map((r) => r.needleIndex ?? r.patternName).sort(), [0, 'github_token'].sort());
  assert.ok(!JSON.stringify(result).toLowerCase().includes(SAMPLE_WORD));
});

test('inspectTree: ファイル名に語を含む場合は伏せ字のパスを返す', () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'tree-'));
  mkdirSync(path.join(dir, 'sub'));
  writeFileSync(path.join(dir, 'sub', `${SAMPLE_WORD}.json`), '{}');
  const result = inspectTree({ dir, needles: [SAMPLE_WORD] });
  assert.deepEqual(result, [{ file: 'sub/***.json', needleIndex: 0 }]);
});

test('inspectTree: シンボリックリンクは違反で、リンク先を読まない', () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'tree-'));
  const outside = mkdtempSync(path.join(tmpdir(), 'outside-'));
  writeFileSync(path.join(outside, 'secret.txt'), SAMPLE_WORD);
  symlinkSync(outside, path.join(dir, 'link'));
  const result = inspectTree({ dir, needles: [SAMPLE_WORD] });
  assert.deepEqual(result, [{ file: 'link', patternName: 'symlink' }]);
});

test('inspectTree: .git は飛ばす', () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'tree-'));
  mkdirSync(path.join(dir, '.git'));
  writeFileSync(path.join(dir, '.git', 'config'), SAMPLE_WORD);
  assert.deepEqual(inspectTree({ dir, needles: [SAMPLE_WORD] }), []);
});

test('inspectTree: このリポジトリの src/ に SECRET_PATTERNS の違反が0件', () => {
  assert.deepEqual(inspectTree({ dir: path.join(ROOT_DIR, 'src'), needles: [], secretPatterns: SECRET_PATTERNS }), []);
});

test('needlesFromPrivateConfig: 案件名・リポジトリの両側・所有者・連絡先を重複なく返す', () => {
  const needles = needlesFromPrivateConfig({
    projectsConfig: { project_owner: 'example-org', projects: [{ project: 'example-app', repo: 'example-org/example-app' }] },
    central: { contact_email: 'ops@example.test' },
  });
  assert.deepEqual(needles.sort(), ['example-app', 'example-org', 'ops@example.test']);
});
