import test from 'node:test';
import assert from 'node:assert/strict';
import { gzipSync } from 'node:zlib';
import { fakeHttp, fixture, fixtureText } from './helpers/fake-http.mjs';
import * as kev from '../src/collect/kev.mjs';
import * as epss from '../src/collect/epss.mjs';
import * as nodeCore from '../src/collect/node-core.mjs';
import * as nodeDist from '../src/collect/node-dist.mjs';
import * as phpGhsa from '../src/collect/php-ghsa.mjs';
import * as phpReleases from '../src/collect/php-releases.mjs';
import * as endoflife from '../src/collect/endoflife.mjs';
import * as packagist from '../src/collect/packagist.mjs';
import { collectors, parseFeed } from '../src/collect/jp-rss.mjs';

const NETWORK_DOWN = Object.assign(new Error('down'), { kind: 'network', http_status: null });

test('kev: 実レスポンスを解析し catalogVersion を記録する', async () => {
  const result = await kev.collect({ http: fakeHttp({ [kev.KEV_URL]: fixture('kev.json') }) });
  assert.equal(result.ok, true);
  assert.match(result.records[0].cveID, /^CVE-/);
  assert.ok(result.meta.catalogVersion);
  assert.equal(kev.isRuntimeRelated({ vendorProject: 'PHP Group', product: 'PHP' }), true);
  assert.equal(kev.isRuntimeRelated({ vendorProject: 'Arista', product: 'VeloCloud' }), false);
});

test('kev: 不正な形式なら ok:false', async () => {
  const result = await kev.collect({ http: fakeHttp({ [kev.KEV_URL]: '{"vulnerabilities":{}}' }) });
  assert.equal(result.ok, false);
  assert.equal(result.error.kind, 'parse');
});

test('kev: 通信失敗も ok:false で理由を返す', async () => {
  const result = await kev.collect({ http: fakeHttp({ [kev.KEV_URL]: NETWORK_DOWN }) });
  assert.equal(result.ok, false);
  assert.equal(result.error.kind, 'network');
});

test('epss: 欲しい CVE だけを残し、モデルの版と日付を記録する', async () => {
  const http = fakeHttp({ [epss.EPSS_URL]: gzipSync(fixture('epss.csv')) });
  const result = await epss.collect({ http, wantedCves: new Set(['CVE-1999-0001', 'CVE-1999-0002']) });
  assert.equal(result.ok, true);
  assert.deepEqual(result.records.map((r) => r.cve), ['CVE-1999-0001', 'CVE-1999-0002']);
  assert.equal(result.records[0].epss, 0.04753);
  assert.match(result.meta.model_version, /^v\d{4}/);
  assert.match(result.meta.score_date, /^2026-/);
});

test('epss: ヘッダが違えば ok:false', async () => {
  const result = await epss.collect({ http: fakeHttp({ [epss.EPSS_URL]: gzipSync('#x:y\nfoo,bar\n') }) });
  assert.equal(result.ok, false);
});

test('node-core: 一覧から個別ファイルを取得し、sha が同じものは再取得しない', async () => {
  const list = JSON.parse(fixtureText('node-core-list.json'));
  const first = list.find((f) => f.name === '1.json');
  const last = list.find((f) => f.name === '204.json');
  const routes = {
    [nodeCore.LIST_URL]: list,
    [first.download_url]: fixture('node-core-1.json'),
    [last.download_url]: fixture('node-core-204.json'),
  };
  const previousShas = Object.fromEntries(list.filter((f) => f.name !== '204.json' && f.name !== '1.json').map((f) => [f.name.replace('.json', ''), f.sha]));
  const http = fakeHttp(routes);
  const result = await nodeCore.collect({ http, previousShas });
  assert.equal(result.ok, true);
  assert.deepEqual(result.records.map((r) => r.id).sort(), ['1', '204']);
  assert.equal(result.unchanged.length, list.filter((f) => /^\d+\.json$/.test(f.name)).length - 2);
  assert.equal(result.records.find((r) => r.id === '204').cve[0], 'CVE-2026-111497');
  assert.ok(!http.requested.some((u) => u.includes('index.json')));
});

test('node-core: 個別ファイルの形式が不正なら ok:false', async () => {
  const list = [{ name: '1.json', type: 'file', sha: 'a', download_url: 'https://raw.githubusercontent.com/nodejs/security-wg/main/vuln/core/1.json' }];
  const result = await nodeCore.collect({ http: fakeHttp({ [nodeCore.LIST_URL]: list, [list[0].download_url]: '{"cve":"x"}' }) });
  assert.equal(result.ok, false);
});

test('node-dist: 解析と不正形式', async () => {
  const ok = await nodeDist.collect({ http: fakeHttp({ [nodeDist.DIST_URL]: fixture('node-dist.json') }) });
  assert.equal(ok.ok, true);
  assert.equal(ok.records[0].security, true);
  const bad = await nodeDist.collect({ http: fakeHttp({ [nodeDist.DIST_URL]: '{}' }) });
  assert.equal(bad.ok, false);
});

// 2026-10-30 に一覧の先頭へ v27.0.0-alpha.0.0.0 が載り、取得全体が失敗し続けた
test('node-dist: 試験版は捨てて続け、正式版が1件もなければ失敗', async () => {
  const mixed = [{ version: 'v27.0.0-alpha.0.0.0', date: '2026-10-29' }, { version: 'v26.13.0', date: '2026-10-28', lts: false, security: true }];
  const ok = await nodeDist.collect({ http: fakeHttp({ [nodeDist.DIST_URL]: JSON.stringify(mixed) }) });
  assert.equal(ok.ok, true);
  assert.deepEqual(ok.records.map((r) => r.version), ['v26.13.0']);
  const onlyPre = await nodeDist.collect({ http: fakeHttp({ [nodeDist.DIST_URL]: JSON.stringify([mixed[0]]) }) });
  assert.equal(onlyPre.ok, false);
});

test('php-ghsa: 範囲を解析し、ページ送りを追う', async () => {
  const all = JSON.parse(fixtureText('php-ghsa.json'));
  const second = 'https://api.github.com/repositories/1/security-advisories?page=2';
  const http = fakeHttp({
    [phpGhsa.FIRST_URL]: { body: all.slice(0, 3), link: `<${second}>; rel="next"` },
    [second]: { body: all.slice(3), link: null },
  });
  const result = await phpGhsa.collect({ http });
  assert.equal(result.ok, true);
  assert.equal(result.records.length, all.length);
  const first = result.records[0];
  assert.equal(first.ghsa_id, 'GHSA-7875-c8px-7q5f');
  assert.deepEqual(first.vulnerabilities[0].parsed, [{ type: 'PHP_BRANCH', branch: '8.2', fixed: '8.2.34' }]);
});

test('php-ghsa: 解析できない範囲は parsed:null（needs_review へ）', () => {
  const record = phpGhsa.toRecord({
    ghsa_id: 'GHSA-aaaa-bbbb-cccc', cve_id: null,
    vulnerabilities: [{ package: { name: 'x' }, vulnerable_version_range: '>= 8.0, < 8.1.2', patched_versions: '8.1.2' }],
  });
  assert.equal(record.vulnerabilities[0].parsed, null);
});

test('php-releases: リリースとブランチ状態', async () => {
  const http = fakeHttp({ [phpReleases.RELEASES_URL]: fixture('php-releases.json'), [phpReleases.STATES_URL]: fixture('php-states.json') });
  const result = await phpReleases.collect({ http });
  assert.equal(result.ok, true);
  assert.ok(result.records.some((r) => r.type === 'release' && r.version === '8.5.12' && r.security_tag));
  assert.ok(result.records.some((r) => r.type === 'branch' && r.branch === '8.3' && r.state === 'security'));
});

test('endoflife: php と nodejs の両方を取得する', async () => {
  const http = fakeHttp({ 'https://endoflife.date/api/v1/products/php': fixture('eol-php.json'), 'https://endoflife.date/api/v1/products/nodejs': fixture('eol-nodejs.json') });
  const result = await endoflife.collect({ http });
  assert.equal(result.ok, true);
  assert.ok(result.records.some((r) => r.product === 'nodejs' && r.name === '25' && r.isEol));
});

test('jp-rss: 3本を独立に解析し、CVE を抽出する', async () => {
  const feeds = { jpcert: 'jpcert.rdf', ipa: 'ipa.rdf', jvn: 'jvn.rdf' };
  for (const collector of collectors) {
    const http = fakeHttp({ [{ jpcert: 'https://www.jpcert.or.jp/rss/jpcert.rdf', ipa: 'https://www.ipa.go.jp/security/alert-rss.rdf', jvn: 'https://jvn.jp/rss/jvn.rdf' }[collector.name]]: fixture(feeds[collector.name]) });
    const result = await collector.collect({ http });
    assert.equal(result.ok, true, collector.name);
    assert.ok(result.records.some((r) => r.cves.includes('CVE-2026-109618')), collector.name);
    assert.ok(result.records.every((r) => r.source === collector.name));
  }
});

test('jp-rss: CVE がないものは needs_review、XML でなければ例外', () => {
  const rows = parseFeed('ipa', fixtureText('ipa.rdf'));
  assert.ok(rows.some((r) => r.cves.length === 0 && r.verification_status === 'needs_review'));
  assert.throws(() => parseFeed('ipa', '<html></html>'));
});

test('packagist: updatedSince だけを送り、packages[] は送らない', async () => {
  const http = fakeHttp({ 'https://packagist.org/api/security-advisories/': fixture('packagist.json') });
  const result = await packagist.collect({ http, updatedSince: 1790000000 });
  assert.equal(result.ok, true);
  assert.deepEqual(http.requested, ['https://packagist.org/api/security-advisories/?updatedSince=1790000000']);
  assert.ok(!http.requested[0].includes('packages'));
  const ghsa = result.records.filter(packagist.hasGhsa).length;
  assert.ok(ghsa > 0 && ghsa < result.records.length);
});

test('packagist: 差分が空（advisories が空配列）でも ok', async () => {
  const result = await packagist.collect({ http: fakeHttp({ 'https://packagist.org/api/security-advisories/': '{"advisories":[]}' }) });
  assert.equal(result.ok, true);
  assert.equal(result.records.length, 0);
});
