import { XMLParser } from 'fast-xml-parser';
import { guarded, okResult, expect } from './result.mjs';

export const FEEDS = {
  jpcert: 'https://www.jpcert.or.jp/rss/jpcert.rdf',
  ipa: 'https://www.ipa.go.jp/security/alert-rss.rdf',
  jvn: 'https://jvn.jp/rss/jvn.rdf',
};

const CVE_PATTERN = /CVE-\d{4}-\d{4,}/g;
const parser = new XMLParser({ ignoreAttributes: false, attributeNamePrefix: '@_', processEntities: true });

const asArray = (value) => (value === undefined ? [] : [value].flat());
const text = (value) => String(value?.['#text'] ?? value ?? '').trim();

// 本文 HTML は取得しない。タイトルとリンク文字列だけから CVE を抽出する
export function parseFeed(source, xml) {
  const doc = parser.parse(xml);
  const root = doc['rdf:RDF'] ?? doc.rss;
  expect(root, `${source}: RDF/RSS として解析できません`);
  const items = asArray(root.item ?? root.channel?.item);
  expect(items.length > 0, `${source}: item が1件もありません`);
  return items.map((item) => {
    const link = text(item.link) || item['@_rdf:about'];
    const title = text(item.title);
    expect(title && link, `${source}: title または link がありません`);
    const cves = [...new Set(`${title} ${link}`.match(CVE_PATTERN) ?? [])].sort();
    const identifier = text(item['dc:identifier']) || link.split('/').filter(Boolean).pop();
    return {
      source, id: identifier.replace('#', ''), title, link, date: text(item['dc:date']) || null,
      cves, verification_status: cves.length > 0 ? 'text_extracted' : 'needs_review',
    };
  });
}

const makeCollector = (source) => ({ http }) => guarded(async () => {
  const xml = await http.getText(FEEDS[source]);
  return okResult(parseFeed(source, xml));
});

// 3本はそれぞれ独立した情報源として扱う
export const collectors = Object.keys(FEEDS).map((name) => ({ name, collect: makeCollector(name) }));
