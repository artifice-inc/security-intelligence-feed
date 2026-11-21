import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdirSync, writeFileSync, readFileSync, mkdtempSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { guardCommit, GuardError } from '../src/publish/guard-commit.mjs';
import { makeFeedRemote, cloneFeed, git } from './helpers/feed-git.mjs';

function outDirWith(files) {
  const dir = mkdtempSync(path.join(tmpdir(), 'guard-out-'));
  for (const [rel, text] of Object.entries(files)) {
    mkdirSync(path.dirname(path.join(dir, rel)), { recursive: true });
    writeFileSync(path.join(dir, rel), text);
  }
  return dir;
}

test('branch 指定: remote の feed ブランチの data/ だけが更新され、ほかのファイルは変わらない', async () => {
  const remote = makeFeedRemote();
  const repoDir = cloneFeed(remote);
  const before = git(remote, 'ls-tree', '-r', 'feed', '--name-only').split('\n').filter(Boolean);
  const outDataDir = outDirWith({ 'new.json': '{"a":1}\n', 'sub/deep.json': '{}\n' });
  const result = await guardCommit({ repoDir, outDataDir, message: 'test', branch: 'feed' });
  assert.deepEqual(result, { committed: true, pushed: true });
  const after = git(remote, 'ls-tree', '-r', 'feed', '--name-only').split('\n').filter(Boolean);
  assert.deepEqual(after.filter((f) => !f.startsWith('data/')), before.filter((f) => !f.startsWith('data/')));
  assert.deepEqual(after.filter((f) => f.startsWith('data/')).sort(), ['data/new.json', 'data/sub/deep.json']);
  assert.equal(git(remote, 'show', 'feed:README.md'), 'feed branch\n');
  // コミットが追加されたのは data/ だけ（.git はもちろん、ほかのファイルも含まない）
  assert.deepEqual(git(remote, 'diff', '--name-only', 'feed~1', 'feed').split('\n').filter(Boolean).filter((f) => !f.startsWith('data/')), []);
});

test('branch 指定: 差分がなければコミットも push もしない', async () => {
  const remote = makeFeedRemote();
  const repoDir = cloneFeed(remote);
  const outDataDir = outDirWith({ 'a.json': '{}\n' });
  await guardCommit({ repoDir, outDataDir, message: 'one', branch: 'feed' });
  const head = git(remote, 'rev-parse', 'feed');
  assert.deepEqual(await guardCommit({ repoDir, outDataDir, message: 'two', branch: 'feed' }), { committed: false, pushed: false });
  assert.equal(git(remote, 'rev-parse', 'feed'), head);
});

test('data/ 以外に変更があれば中止する', async () => {
  const repoDir = cloneFeed(makeFeedRemote());
  writeFileSync(path.join(repoDir, 'README.md'), 'changed\n');
  await assert.rejects(() => guardCommit({ repoDir, outDataDir: outDirWith({ 'a.json': '{}\n' }), message: 'x', branch: 'feed' }), GuardError);
});

test('branch の既定（省略）では今のまま git push（実行中のブランチ）になる', async () => {
  const remote = makeFeedRemote();
  const repoDir = cloneFeed(remote);
  const result = await guardCommit({ repoDir, outDataDir: outDirWith({ 'a.json': '{}\n' }), message: 'default' });
  assert.deepEqual(result, { committed: true, pushed: true });
  assert.equal(git(remote, 'show', 'feed:data/a.json'), '{}\n');
  assert.ok(existsSync(path.join(repoDir, '.git')));
  assert.equal(readFileSync(path.join(repoDir, 'README.md'), 'utf8'), 'feed branch\n');
});
