import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, readFileSync, copyFileSync, existsSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fetchOsvDb, zipPathOf, dbFreshness, readOsvRecord, osvHttp } from '../src/collect/osv-db.mjs';

const work = mkdtempSync(path.join(tmpdir(), 'si-osv-'));
const goodZip = path.join(work, 'good.zip');
writeFileSync(path.join(work, 'GHSA-aaaa-bbbb-cccc.json'), JSON.stringify({ id: 'GHSA-aaaa-bbbb-cccc' }));
execFileSync('zip', ['-q', '-j', goodZip, path.join(work, 'GHSA-aaaa-bbbb-cccc.json')]);

// download の呼び出し先 URL を記録し、指定の内容をファイルへ書くフェイク
const fakeDownloader = (content) => {
  const urls = [];
  return { urls, download: async (url, dest) => { urls.push(url); if (content instanceof Error) throw content; if (Buffer.isBuffer(content)) writeFileSync(dest, content); else copyFileSync(content, dest); } };
};

test('試験1b: 通信先は固定 URL だけで、lockfile は渡されない', async () => {
  const dest = path.join(work, 'db1');
  const http = fakeDownloader(goodZip);
  const { meta, outcomes } = await fetchOsvDb({ ecosystems: ['npm', 'Packagist'], dest, http, now: new Date('2026-10-25T00:00:00Z') });
  assert.deepEqual(http.urls, [
    'https://osv-vulnerabilities.storage.googleapis.com/npm/all.zip',
    'https://osv-vulnerabilities.storage.googleapis.com/Packagist/all.zip',
  ]);
  assert.ok(outcomes.npm.ok);
  assert.match(meta.npm.sha256, /^[0-9a-f]{64}$/);
  assert.ok(existsSync(zipPathOf(dest, 'npm')));
  assert.equal(fetchOsvDb.length, 1); // 引数は1つのオプションオブジェクトだけ（ecosystems, dest）
});

test('許可ホストは OSV の配布元だけ', async () => {
  await assert.rejects(() => osvHttp().getText('https://github.com/x'), { kind: 'forbidden_host' });
});

test('壊れた zip では既存の DB を残す', async () => {
  const dest = path.join(work, 'db2');
  await fetchOsvDb({ ecosystems: ['npm'], dest, http: fakeDownloader(goodZip) });
  const before = readFileSync(zipPathOf(dest, 'npm'));
  const { outcomes, meta } = await fetchOsvDb({ ecosystems: ['npm'], dest, http: fakeDownloader(Buffer.from('not a zip')) });
  assert.equal(outcomes.npm.ok, false);
  assert.deepEqual(readFileSync(zipPathOf(dest, 'npm')), before);
  assert.ok(meta.npm.sha256, '前回の meta が残る');
  assert.ok(!existsSync(`${zipPathOf(dest, 'npm')}.download`));
});

test('ダウンロード失敗でも既存の DB を残す', async () => {
  const dest = path.join(work, 'db3');
  await fetchOsvDb({ ecosystems: ['npm'], dest, http: fakeDownloader(goodZip) });
  const { outcomes } = await fetchOsvDb({ ecosystems: ['npm'], dest, http: fakeDownloader(Object.assign(new Error('x'), { kind: 'network' })) });
  assert.equal(outcomes.npm.ok, false);
  assert.ok(existsSync(zipPathOf(dest, 'npm')));
});

test('鮮度: 12時間で更新、72時間までは警告付き、それ以降は照合不能', () => {
  const at = (h) => new Date(Date.parse('2026-10-25T00:00:00Z') + h * 3_600_000);
  const entry = { fetched_at: '2026-10-25T00:00:00Z' };
  assert.deepEqual(dbFreshness(entry, at(11)), { state: 'fresh', needs_refresh: false });
  assert.deepEqual(dbFreshness(entry, at(13)), { state: 'stale_warn', needs_refresh: true });
  assert.equal(dbFreshness(entry, at(73)).state, 'unavailable');
  assert.equal(dbFreshness(undefined, at(1)).state, 'unavailable');
});

test('zip から OSV レコードを取り出す。不正な ID は拒否', async () => {
  assert.deepEqual(await readOsvRecord(goodZip, 'GHSA-aaaa-bbbb-cccc'), { id: 'GHSA-aaaa-bbbb-cccc' });
  assert.equal(await readOsvRecord(goodZip, 'GHSA-none'), null);
  await assert.rejects(() => readOsvRecord(goodZip, '*'));
});
