import test from 'node:test';
import assert from 'node:assert/strict';
import { createHttp, COLLECT_HOSTS, OSV_HOSTS } from '../src/lib/http.mjs';
import { loadCentral } from '../src/lib/config.mjs';

const okResponse = (body = 'ok', init = {}) => new Response(body, { status: 200, ...init });

test('許可リスト外のホストは例外になり、fetch は呼ばれない', async () => {
  let called = 0;
  const http = createHttp({ allowedHosts: COLLECT_HOSTS, fetchImpl: async () => { called += 1; return okResponse(); } });
  await assert.rejects(() => http.getText('https://example.com/x'), { kind: 'forbidden_host' });
  assert.equal(called, 0);
});

test('OSV 専用インスタンスは他の情報源ホストを拒否する', async () => {
  const http = createHttp({ allowedHosts: OSV_HOSTS, fetchImpl: async () => okResponse() });
  await assert.rejects(() => http.getText('https://www.cisa.gov/x'), { kind: 'forbidden_host' });
});

test('リダイレクト先が許可外なら例外になる', async () => {
  const fetchImpl = async () => new Response(null, { status: 302, headers: { location: 'https://evil.example/' } });
  const http = createHttp({ allowedHosts: COLLECT_HOSTS, fetchImpl });
  await assert.rejects(() => http.getText('https://www.cisa.gov/x'), { kind: 'forbidden_host' });
});

test('相対リダイレクトは同じホスト内で追従する', async () => {
  const urls = [];
  const fetchImpl = async (url) => {
    urls.push(url);
    return urls.length === 1 ? new Response(null, { status: 302, headers: { location: 'next.csv' } }) : okResponse('data');
  };
  const http = createHttp({ allowedHosts: COLLECT_HOSTS, fetchImpl });
  assert.equal(await http.getText('https://epss.empiricalsecurity.com/a.csv'), 'data');
  assert.equal(urls[1], 'https://epss.empiricalsecurity.com/next.csv');
});

test('5xx は3回まで再試行し、User-Agent を付ける', async () => {
  const seen = [];
  let n = 0;
  const fetchImpl = async (url, init) => { seen.push(init.headers['User-Agent']); n += 1; return n < 3 ? new Response('', { status: 503 }) : okResponse('fine'); };
  const http = createHttp({ allowedHosts: COLLECT_HOSTS, fetchImpl, sleep: async () => {} });
  assert.equal(await http.getText('https://www.cisa.gov/x'), 'fine');
  assert.equal(n, 3);
  assert.ok(seen.every((ua) => ua === loadCentral().user_agent));
});

test('4xx は再試行しない', async () => {
  let n = 0;
  const http = createHttp({ allowedHosts: COLLECT_HOSTS, fetchImpl: async () => { n += 1; return new Response('', { status: 404 }); }, sleep: async () => {} });
  await assert.rejects(() => http.getText('https://www.cisa.gov/x'), { http_status: 404 });
  assert.equal(n, 1);
});

test('ネットワーク障害は再試行後に network エラー', async () => {
  const http = createHttp({ allowedHosts: COLLECT_HOSTS, fetchImpl: async () => { throw new Error('boom'); }, sleep: async () => {} });
  await assert.rejects(() => http.getText('https://www.cisa.gov/x'), { kind: 'network' });
});
