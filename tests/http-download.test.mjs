import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, writeFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { createHttp } from '../src/lib/http.mjs';
import { fetchOsvDb, zipPathOf } from '../src/collect/osv-db.mjs';

// 本体の受信に bodyDelayMs かかり、signal が中断されたら本体の読み取りがエラーになる fetch
const slowFetch = (bodyDelayMs, payload = 'data') => async (url, { signal }) => ({
  ok: true, status: 200, headers: { get: () => null },
  body: new ReadableStream({
    start(controller) {
      const timer = setTimeout(() => { controller.enqueue(new TextEncoder().encode(payload)); controller.close(); }, bodyDelayMs);
      signal.addEventListener('abort', () => { clearTimeout(timer); controller.error(signal.reason); });
    },
  }),
  text: async () => { await new Promise((resolve) => setTimeout(resolve, bodyDelayMs)); signal.throwIfAborted(); return payload; },
});
const options = { allowedHosts: ['example.test'], userAgent: 'test', sleep: async () => {}, timeoutMs: 50, downloadTimeoutMs: 800 };
const URL_OF = 'https://example.test/all.zip';
const tmp = () => mkdtempSync(path.join(tmpdir(), 'si-dl-'));

test('DB の取得は http_timeout_ms より長くかかっても、専用の上限内なら成功する', async () => {
  const file = path.join(tmp(), 'x.zip');
  await createHttp({ ...options, fetchImpl: slowFetch(200) }).download(URL_OF, file);
  assert.equal(readFileSync(file, 'utf8'), 'data');
});

test('通常の API 呼び出しは従来どおり http_timeout_ms で打ち切られる', async () => {
  const http = createHttp({ ...options, fetchImpl: slowFetch(200), retries: 1 });
  await assert.rejects(() => http.getText(URL_OF), /timeout/i);
});

test('専用の上限を超えたら失敗し、タイムアウトは再試行しない。既存の DB は残る', async () => {
  const dest = tmp();
  const target = zipPathOf(dest, 'npm');
  await fetchOsvDb({ ecosystems: [], dest }); // meta.json の準備
  const calls = [];
  const fetchImpl = (...args) => { calls.push(args[0]); return slowFetch(400)(...args); };
  const http = createHttp({ ...options, fetchImpl, downloadTimeoutMs: 100 });
  // 既存の DB を置いてから、時間切れの取得を行う
  const { mkdirSync } = await import('node:fs');
  mkdirSync(path.dirname(target), { recursive: true });
  writeFileSync(target, 'old-db');
  const { outcomes } = await fetchOsvDb({ ecosystems: ['npm'], dest, http: { download: (url, temp) => http.download(URL_OF, temp) } });
  assert.equal(outcomes.npm.ok, false);
  assert.equal(calls.length, 1, 'タイムアウト後に再試行しない');
  assert.equal(readFileSync(target, 'utf8'), 'old-db');
  assert.ok(!existsSync(`${target}.download`));
});
