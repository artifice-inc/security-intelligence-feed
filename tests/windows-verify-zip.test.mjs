import test from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, readFileSync, existsSync, mkdirSync, copyFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { verifyZip, fetchOsvDb, zipPathOf } from '../src/collect/osv-db.mjs';

const work = mkdtempSync(path.join(tmpdir(), 'si-winzip-'));
const goodZip = path.join(work, 'good.zip');
writeFileSync(path.join(work, 'a.json'), JSON.stringify({ id: 'A' }));
execFileSync('zip', ['-q', '-j', goodZip, path.join(work, 'a.json')]);
const goodBytes = readFileSync(goodZip);
const fileOf = (name, bytes) => { const file = path.join(work, name); writeFileSync(file, bytes); return file; };
const ENV = { SystemRoot: 'C:\\Windows' };

// tar.exe の代わり。起動した引数を記録し、指定の終了コードか error イベントで終わる
const fakeSpawn = ({ code = 0, error = null, stderr = '' } = {}) => {
  const calls = [];
  const spawnFn = (command, args, options) => {
    calls.push({ command, args, options });
    const child = new EventEmitter();
    child.stderr = new EventEmitter();
    setImmediate(() => { if (error) { child.emit('error', error); return; } if (stderr) child.stderr.emit('data', stderr); child.emit('close', code); });
    return child;
  };
  return { calls, spawnFn };
};
const verifyWin = (file, spawner = fakeSpawn()) => verifyZip(file, { platform: 'win32', env: ENV, spawnFn: spawner.spawnFn });

test('verifyZip(win32): 正しい ZIP は tar.exe を絶対パスで -xOf 起動する', async () => {
  const spawner = fakeSpawn();
  await verifyWin(goodZip, spawner);
  assert.equal(spawner.calls.length, 1);
  assert.equal(spawner.calls[0].command, 'C:\\Windows\\System32\\tar.exe');
  assert.deepEqual(spawner.calls[0].args, ['-xOf', goodZip]);
  assert.deepEqual(spawner.calls[0].options.stdio, ['ignore', 'ignore', 'pipe']);
});

test('verifyZip(win32): ZIP でない・途中で切れた・末尾に収まらないものは tar.exe を起動する前に拒否', async () => {
  const tarFile = path.join(work, 'x.tar');
  execFileSync('tar', ['-cf', tarFile, '-C', work, 'a.json']);
  const cases = { tar: tarFile, 切れた: fileOf('cut.zip', goodBytes.subarray(0, goodBytes.length - 10)), 末尾に余り: fileOf('extra.zip', Buffer.concat([goodBytes, Buffer.from('garbage')])), 空: fileOf('empty.zip', Buffer.alloc(0)) };
  for (const [name, file] of Object.entries(cases)) {
    const spawner = fakeSpawn();
    await assert.rejects(() => verifyWin(file, spawner), /ZIP ではないか、途中で切れています/, name);
    assert.equal(spawner.calls.length, 0, name);
  }
});

test('verifyZip(win32): コメント付きの ZIP は末尾に収まれば通る', async () => {
  const withComment = Buffer.from(goodBytes);
  const comment = Buffer.from('comment');
  withComment.writeUInt16LE(comment.length, withComment.length - 2);
  await verifyWin(fileOf('comment.zip', Buffer.concat([withComment, comment])));
});

test('verifyZip(win32): tar.exe が0以外（CRC 不一致を模す）・起動の失敗・SystemRoot なしは失敗', async () => {
  await assert.rejects(() => verifyWin(goodZip, fakeSpawn({ code: 1, stderr: 'bad crc' })), /終了コード1.*bad crc/);
  await assert.rejects(() => verifyWin(goodZip, fakeSpawn({ error: new Error('ENOENT') })), /ENOENT/);
  await assert.rejects(() => verifyZip(goodZip, { platform: 'win32', env: {}, spawnFn: fakeSpawn().spawnFn }), /SystemRoot/);
});

test('fetchOsvDb(win32 の検証を注入): 検証に失敗したら既存の all.zip と meta は変わらない', async () => {
  const dest = path.join(work, 'db');
  const http = (source) => ({ download: async (url, to) => copyFileSync(source, to) });
  await fetchOsvDb({ ecosystems: ['npm'], dest, http: http(goodZip), now: new Date('2026-10-25T00:00:00Z') });
  const zipBefore = readFileSync(zipPathOf(dest, 'npm'));
  const metaBefore = readFileSync(path.join(dest, 'meta.json'), 'utf8');
  const broken = fileOf('broken.zip', goodBytes.subarray(0, 30));
  const { outcomes } = await fetchOsvDb({ ecosystems: ['npm'], dest, http: http(broken), now: new Date('2026-10-26T00:00:00Z'), verify: (file) => verifyWin(file) });
  assert.equal(outcomes.npm.ok, false);
  assert.deepEqual(readFileSync(zipPathOf(dest, 'npm')), zipBefore);
  assert.equal(readFileSync(path.join(dest, 'meta.json'), 'utf8'), metaBefore);
  assert.equal(existsSync(`${zipPathOf(dest, 'npm')}.download`), false);
});
