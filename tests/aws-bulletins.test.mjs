import test from 'node:test';
import assert from 'node:assert/strict';
import { parseFeed, collect } from '../src/collect/aws-bulletins.mjs';
import { normalizeAwsBulletins, changedItems } from '../src/normalize/aws-bulletins.mjs';
import { createHttp, COLLECT_HOSTS } from '../src/lib/http.mjs';
import { validate } from '../src/lib/schema.mjs';
import { fixtureText } from './helpers/fake-http.mjs';

const GOOD = fixtureText('aws-bulletins.xml');
const feed = (channelBody, root = 'rss version="2.0"') => `<?xml version="1.0"?><${root}><channel><title>t</title><link>l</link><description>d</description>${channelBody}</channel></rss>`;
const itemXml = (link, title = 'T', pubDate = 'Thu, 19 Nov 2026 22:48:05 +0000') => `<item><link>${link}</link><title>${title}</title><pubDate>${pubDate}</pubDate></item>`;
const LINK = (id) => `https://aws.amazon.com/security/security-bulletins/rss/${id}/`;

test('parse: 正常な2件（ID は小文字、CVE は重複除去して並べる、掲載日時は UTC）', () => {
  const records = parseFeed(GOOD);
  assert.deepEqual(records.map((r) => r.id), ['2026-192-aws', '2026-191-aws']);
  assert.deepEqual(records[0].cves, ['CVE-2026-0001', 'CVE-2026-0002']);
  assert.equal(records[0].rss_pub_date, '2026-11-19T22:48:05Z');
  assert.deepEqual(Object.keys(records[0]).sort(), ['cves', 'id', 'rss_pub_date', 'title']);
});

test('parse: link の形が違う・pubDate が不正・ID の重複・title が空は失敗', () => {
  assert.throws(() => parseFeed(feed(itemXml('https://aws.amazon.com/other/'))), { kind: 'parse' });
  assert.throws(() => parseFeed(feed(itemXml('https://evil.example/security/security-bulletins/rss/2026-001-aws/'))), { kind: 'parse' });
  assert.throws(() => parseFeed(feed(itemXml(LINK('2026-001-aws'), 'T', 'not a date'))), { kind: 'parse' });
  assert.throws(() => parseFeed(feed(itemXml(LINK('2026-001-aws')) + itemXml(LINK('2026-001-AWS')))), { kind: 'parse' });
  assert.throws(() => parseFeed(feed(itemXml(LINK('2026-001-aws'), ''))), { kind: 'parse' });
});

test('parse: 構造の有効な0件は成功（空の配列）', () => {
  assert.deepEqual(parseFeed(feed('')), []);
});

test('parse: 構造が壊れた XML は失敗する', () => {
  assert.throws(() => parseFeed(GOOD.replace('</rss>', '')), { kind: 'parse' }); // </rss> の欠け
  assert.throws(() => parseFeed('<?xml version="1.0"?><rss version="2.0"></rss>'), { kind: 'parse' }); // channel なし
  assert.throws(() => parseFeed('<rss version="2.0"><channel>text</channel></rss>'), { kind: 'parse' }); // channel が文字列
  assert.throws(() => parseFeed('<rss version="2.0">' + '<channel><title>t</title><link>l</link><description>d</description></channel>'.repeat(2) + '</rss>'), { kind: 'parse' }); // channel が2つ
  for (const missing of ['title', 'link', 'description']) {
    const channel = ['title', 'link', 'description'].filter((k) => k !== missing).map((k) => `<${k}>x</${k}>`).join('');
    assert.throws(() => parseFeed(`<rss version="2.0"><channel>${channel}</channel></rss>`), { kind: 'parse' }, missing);
  }
  assert.throws(() => parseFeed('<rss><channel><title>'), { kind: 'parse' }); // 壊れた XML
  assert.throws(() => parseFeed('<rss version="2.0"><channel><title>t</title><link>l</link><description>d</description><item>x</item></channel></rss>'), { kind: 'parse' }); // item が文字列
});

const NOW = '2026-11-21T07:17:00Z';
const rec = (id, title = 'T', rss_pub_date = '2026-11-19T00:00:00Z') => ({ id, title, rss_pub_date, cves: [] });

test('normalize: 初回はスキーマに通り、url は ID から組み立てる', () => {
  const next = normalizeAwsBulletins({ previous: null, records: parseFeed(GOOD), now: NOW });
  assert.equal(validate('aws-bulletins', next).ok, true);
  assert.equal(next.items[0].url, 'https://aws.amazon.com/security/security-bulletins/2026-192-aws/');
  assert.equal(next.items[0].last_changed_at, null);
  assert.equal(next.items[0].first_seen_at, NOW);
});

test('normalize: 2回目で変化がなければ updated_at を変えない', () => {
  const first = normalizeAwsBulletins({ previous: null, records: parseFeed(GOOD), now: NOW });
  const second = normalizeAwsBulletins({ previous: first, records: parseFeed(GOOD), now: '2026-11-22T00:00:00Z' });
  assert.deepEqual(second, first);
});

test('normalize: title の変更で last_changed_at が付き、first_seen_at は変わらない', () => {
  const first = normalizeAwsBulletins({ previous: null, records: [rec('2026-001-aws')], now: NOW });
  const next = normalizeAwsBulletins({ previous: first, records: [rec('2026-001-aws', 'T2')], now: '2026-11-22T00:00:00Z' });
  assert.equal(next.items[0].last_changed_at, '2026-11-22T00:00:00Z');
  assert.equal(next.items[0].first_seen_at, NOW);
  assert.equal(next.updated_at, '2026-11-22T00:00:00Z');
  const { added, updated } = changedItems(next, '2026-11-22T00:00:00Z', 7);
  assert.equal(added.length, 1); // 7日以内は新着のまま。更新は新着でないものだけ
  assert.equal(updated.length, 0);
  assert.equal(changedItems(next, '2026-12-30T00:00:00Z', 7).added.length, 0);
});

test('normalize: 更新は新着期間を過ぎたものだけが「更新」になる', () => {
  const first = normalizeAwsBulletins({ previous: null, records: [rec('2026-001-aws')], now: '2026-11-01T00:00:00Z' });
  const next = normalizeAwsBulletins({ previous: first, records: [rec('2026-001-aws', 'T2')], now: '2026-11-21T00:00:00Z' });
  const { added, updated } = changedItems(next, '2026-11-21T00:00:00Z', 7);
  assert.equal(added.length, 0);
  assert.equal(updated.length, 1);
});

test('normalize: RSS から消えた項目は残る', () => {
  const first = normalizeAwsBulletins({ previous: null, records: [rec('2026-001-aws'), rec('2026-002-aws')], now: NOW });
  const next = normalizeAwsBulletins({ previous: first, records: [rec('2026-002-aws')], now: NOW });
  assert.equal(next.items.length, 2);
});

test('normalize: 300件の上限は古い方から落とし、並びは掲載日時と ID の降順', () => {
  const records = Array.from({ length: 305 }, (_, i) => rec(`2026-${String(i + 1).padStart(3, '0')}-aws`, 'T', '2026-11-19T00:00:00Z'));
  const next = normalizeAwsBulletins({ previous: null, records, now: NOW });
  assert.equal(next.items.length, 300);
  assert.equal(next.items[0].id, '2026-305-aws'); // 同時刻は ID の降順
  assert.equal(next.items.at(-1).id, '2026-006-aws');
  const mixed = normalizeAwsBulletins({ previous: null, records: [rec('2026-001-aws', 'T', '2026-11-20T00:00:00Z'), rec('2026-002-aws')], now: NOW });
  assert.equal(mixed.items[0].id, '2026-001-aws');
});

// --- 時間の上限と外側からの中断（実際の collect と createHttp を通す） ---
const makeHttp = (fetchImpl) => createHttp({ allowedHosts: COLLECT_HOSTS, fetchImpl, sleep: () => new Promise((r) => setTimeout(r, 5)), timeoutMs: 10_000, retries: 3, userAgent: 'test' });
const DEADLINE_MS = 80;

test('collect: 応答を返さない fetch は期限内に timeout で返る', async () => {
  const http = makeHttp((url, { signal }) => new Promise((_, reject) => signal.addEventListener('abort', () => reject(signal.reason))));
  const started = Date.now();
  const result = await collect({ http, deadlineMs: DEADLINE_MS });
  assert.equal(result.ok, false);
  assert.equal(result.error.kind, 'timeout');
  assert.ok(Date.now() - started < DEADLINE_MS * 5);
});

test('collect: 302 と 503 の再試行が重なっても期限内に打ち切る', async () => {
  let calls = 0;
  const fetchImpl = async (url, { signal }) => {
    calls += 1;
    await new Promise((r) => setTimeout(r, 30));
    if (signal.aborted) throw signal.reason;
    return calls % 2 === 1 ? new Response(null, { status: 302, headers: { location: LINK('2026-001-aws') } }) : new Response('x', { status: 503 });
  };
  const started = Date.now();
  const result = await collect({ http: makeHttp(fetchImpl), deadlineMs: DEADLINE_MS });
  assert.equal(result.error.kind, 'timeout');
  assert.ok(Date.now() - started < DEADLINE_MS * 5);
});

test('collect: signal を無視する fetch でも期限内に返る', async () => {
  const http = makeHttp(() => new Promise(() => {}));
  const started = Date.now();
  const result = await collect({ http, deadlineMs: DEADLINE_MS });
  assert.equal(result.error.kind, 'timeout');
  assert.ok(Date.now() - started < DEADLINE_MS * 5);
});

test('collect: 正常な RSS は ok で返る', async () => {
  const result = await collect({ http: makeHttp(async () => new Response(GOOD, { status: 200 })), deadlineMs: 1000 });
  assert.equal(result.ok, true);
  assert.equal(result.records.length, 2);
});

test('collect: 本文の受信中に外側から中断すると、期限より前に unfinished で返り、signal が中断済みになる', async () => {
  let received;
  const fetchImpl = async (url, { signal }) => {
    received = signal;
    let timer;
    const body = new ReadableStream({
      start(controller) {
        signal.addEventListener('abort', () => { clearInterval(timer); controller.error(signal.reason); });
        timer = setInterval(() => controller.enqueue(new TextEncoder().encode('<rss>')), 5);
      },
    });
    return new Response(body, { status: 200 });
  };
  const outer = new AbortController();
  const pending = collect({ http: makeHttp(fetchImpl), deadlineMs: 5000, signal: outer.signal });
  setTimeout(() => outer.abort(), 50);
  const started = Date.now();
  const result = await pending;
  assert.equal(result.ok, false);
  assert.equal(result.error.kind, 'unfinished');
  assert.ok(Date.now() - started < 1000);
  assert.equal(received.aborted, true);
});
