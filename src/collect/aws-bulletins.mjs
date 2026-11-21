import { XMLParser, XMLValidator } from 'fast-xml-parser';
import { loadThresholds } from '../lib/config.mjs';
import { toIso } from '../lib/time.mjs';
import { okResult, failResult, expect } from './result.mjs';

export const FEED_URL = 'https://aws.amazon.com/security/security-bulletins/rss/feed/';

const LINK_PATTERN = /^https:\/\/aws\.amazon\.com\/security\/security-bulletins\/rss\/(\d{4}-\d{3,}-aws)\/?$/i;
const CVE_PATTERN = /CVE-\d{4}-\d{4,}/g;
const REQUIRED_CHANNEL_KEYS = ['title', 'link', 'description'];
const parser = new XMLParser({ ignoreAttributes: false, attributeNamePrefix: '@_', processEntities: true });

const isPlainObject = (value) => value !== null && typeof value === 'object' && !Array.isArray(value);
const text = (value) => String(value?.['#text'] ?? value ?? '').trim();

// 本文（description）・guid などは読まない。ID・タイトル・掲載日時・CVE だけを取る
export function parseFeed(xml) {
  // XMLParser は閉じタグの欠けた XML でも項目を返すので、先に構文を確かめる
  const valid = XMLValidator.validate(xml);
  expect(valid === true, `aws-bulletins: XML の構文が不正です: ${valid?.err?.msg ?? ''}`);
  const doc = parser.parse(xml);
  expect(isPlainObject(doc.rss), 'aws-bulletins: rss が1個の要素ではありません');
  const { channel } = doc.rss;
  expect(isPlainObject(channel), 'aws-bulletins: channel が1個の要素ではありません');
  expect(REQUIRED_CHANNEL_KEYS.every((key) => channel[key] !== undefined), 'aws-bulletins: channel の必須要素（title・link・description）が欠けています');
  if (channel.item === undefined) return []; // 新着のない期間は正常な0件
  const items = [channel.item].flat();
  expect(items.every(isPlainObject), 'aws-bulletins: item の形が不正です');
  const seen = new Set();
  return items.map((item) => {
    const matched = LINK_PATTERN.exec(text(item.link));
    expect(matched, 'aws-bulletins: link の形が想定と違います');
    const id = matched[1].toLowerCase();
    expect(!seen.has(id), `aws-bulletins: ID が重複しています: ${id}`);
    seen.add(id);
    const title = text(item.title);
    expect(title, `aws-bulletins: title が空です: ${id}`);
    const published = new Date(text(item.pubDate));
    expect(!Number.isNaN(published.getTime()), `aws-bulletins: pubDate が不正です: ${id}`);
    return { id, title, rss_pub_date: toIso(published), cves: [...new Set(title.match(CVE_PATTERN) ?? [])].sort() };
  });
}

// deadlineMs で取得全体（リダイレクト・再試行・本文の受信を含む）を打ち切る。signal は外側（照合後の締め切り）からの中断
export async function collect({ http, deadlineMs = loadThresholds().aws_bulletins_deadline_ms, signal: outerSignal } = {}) {
  const deadline = new AbortController();
  const timers = [];
  const signal = AbortSignal.any([deadline.signal, ...(outerSignal ? [outerSignal] : [])]);
  const interruption = new Promise((resolve) => {
    timers.push(setTimeout(() => { deadline.abort(); resolve(failResult({ kind: 'timeout', message: `取得が ${deadlineMs}ms の期限を超えました` })); }, deadlineMs));
    outerSignal?.addEventListener('abort', () => resolve(failResult({ kind: 'unfinished', message: '外側の締め切りで中断されました' })), { once: true });
  });
  const work = (async () => {
    try {
      return okResult(parseFeed(await http.getText(FEED_URL, { signal })));
    } catch (error) {
      if (outerSignal?.aborted) return failResult({ kind: 'unfinished', message: '外側の締め切りで中断されました' });
      if (deadline.signal.aborted) return failResult({ kind: 'timeout', message: `取得が ${deadlineMs}ms の期限を超えました` });
      return failResult(error);
    }
  })();
  try {
    return await Promise.race([work, interruption]);
  } finally {
    timers.forEach(clearTimeout);
  }
}
