import test from 'node:test';
import assert from 'node:assert/strict';
import { createHttp, COLLECT_HOSTS } from '../src/lib/http.mjs';
import { githubHeaders } from '../src/collect/result.mjs';
import * as phpGhsa from '../src/collect/php-ghsa.mjs';

const ENV = { GITHUB_TOKEN: 'dummy-value-for-test' };
const redirectTo = (location) => new Response(null, { status: 302, headers: { location } });
const authOf = (init) => init.headers.Authorization;

// URL → 応答の列。呼ばれた URL と Authorization を記録する
function recordingFetch(routes) {
  const calls = [];
  const fetchImpl = async (url, init) => {
    calls.push({ url, auth: authOf(init) });
    const route = routes[url];
    if (!route) throw new Error(`未登録: ${url}`);
    return typeof route === 'function' ? route() : route.clone();
  };
  return { calls, fetchImpl };
}

test('githubHeaders: オリジンが https://api.github.com のときだけ認証を付ける', () => {
  assert.ok(githubHeaders(ENV, 'https://api.github.com/repos/x').Authorization);
  for (const url of ['https://api.github.com:8443/x', 'http://api.github.com/x', 'https://raw.githubusercontent.com/x', null]) {
    assert.equal(githubHeaders(ENV, url).Authorization, undefined, String(url));
  }
  assert.equal(githubHeaders({}, 'https://api.github.com/x').Authorization, undefined);
});

test('リダイレクト: 別ホストへの転送には Authorization を付けない（元の要求には付く）', async () => {
  const { calls, fetchImpl } = recordingFetch({
    'https://api.github.com/a': redirectTo('https://raw.githubusercontent.com/b'),
    'https://raw.githubusercontent.com/b': new Response('ok'),
  });
  const http = createHttp({ allowedHosts: COLLECT_HOSTS, fetchImpl });
  await http.getText('https://api.github.com/a', { headers: githubHeaders(ENV, 'https://api.github.com/a') });
  assert.ok(calls[0].auth);
  assert.equal(calls[1].auth, undefined);
});

test('リダイレクト: 同じホストの別ポートには Authorization を付けない', async () => {
  const { calls, fetchImpl } = recordingFetch({
    'https://api.github.com/a': redirectTo('https://api.github.com:8443/b'),
    'https://api.github.com:8443/b': new Response('ok'),
  });
  const http = createHttp({ allowedHosts: COLLECT_HOSTS, fetchImpl });
  await http.getText('https://api.github.com/a', { headers: githubHeaders(ENV, 'https://api.github.com/a') });
  assert.ok(calls[0].auth);
  assert.equal(calls[1].auth, undefined);
});

test('リダイレクト: http: への転送は送信されない（認証も付かない）', async () => {
  const { calls, fetchImpl } = recordingFetch({ 'https://api.github.com/a': redirectTo('http://api.github.com/b') });
  const http = createHttp({ allowedHosts: COLLECT_HOSTS, fetchImpl });
  await assert.rejects(() => http.getText('https://api.github.com/a', { headers: githubHeaders(ENV, 'https://api.github.com/a') }), { kind: 'forbidden_host' });
  assert.equal(calls.length, 1);
});

test('リダイレクト: 同じオリジンの転送では Authorization が付く', async () => {
  const { calls, fetchImpl } = recordingFetch({
    'https://api.github.com/a': redirectTo('/b'),
    'https://api.github.com/b': new Response('ok'),
  });
  const http = createHttp({ allowedHosts: COLLECT_HOSTS, fetchImpl });
  await http.getText('https://api.github.com/a', { headers: githubHeaders(ENV, 'https://api.github.com/a') });
  assert.ok(calls[1].auth);
});

const pageWithNext = (next) => new Response('[]', { status: 200, headers: { link: `<${next}>; rel="next"` } });

test('php-ghsa のページ送り: 別ホスト・別ポートの次ページには付かず、同じオリジンには付く', async () => {
  for (const [next, expectAuth] of [
    ['https://www.php.net/next', false], ['https://api.github.com:8443/next', false], ['https://api.github.com/next', true],
  ]) {
    const { calls, fetchImpl } = recordingFetch({ [phpGhsa.FIRST_URL]: pageWithNext(next), [next]: new Response('[]') });
    const http = createHttp({ allowedHosts: COLLECT_HOSTS, fetchImpl });
    const result = await phpGhsa.collect({ http, env: ENV });
    assert.equal(result.ok, true, next);
    assert.ok(calls[0].auth);
    assert.equal(Boolean(calls[1].auth), expectAuth, next);
  }
});

test('php-ghsa のページ送り: http: の次ページは拒否され、認証は送られない', async () => {
  const { calls, fetchImpl } = recordingFetch({ [phpGhsa.FIRST_URL]: pageWithNext('http://api.github.com/next') });
  const http = createHttp({ allowedHosts: COLLECT_HOSTS, fetchImpl });
  const result = await phpGhsa.collect({ http, env: ENV });
  assert.equal(result.ok, false);
  assert.equal(calls.length, 1);
});
