import test from 'node:test';
import assert from 'node:assert/strict';
import { combineAdvisoryViews, keepMatchedOnly } from '../src/match/advisory-view.mjs';
import { buildAdvisoryIndex } from '../src/match/assemble.mjs';

const adv = (key, { cve = [], ghsa = [], sources = [], title = key, kev = false, severity = 'medium', superseded = null } = {}) => ({
  key, aliases: { cve, ghsa, other: [] }, status: 'active', superseded_by: superseded, title, severity: { level: severity }, summary: `s-${key}`,
  known_exploited: { kev, date_added: kev ? '2026-11-01' : null }, epss: { score: null, percentile: null, date: null }, sources, affected: [],
});
const src = (name, id, withdrawn = null) => ({ name, id, url: `https://example.test/${id}`, withdrawn_at: withdrawn });

test('combineAdvisoryViews: 片側にしかない記録はそのまま返り、superseded は除かれる', () => {
  const result = combineAdvisoryViews({
    publicAdvisories: [adv('CVE-1', { cve: ['CVE-1'], sources: [src('php-ghsa', 'a')] }), adv('CVE-OLD', { cve: ['CVE-OLD'], superseded: 'CVE-1' })],
    privateAdvisories: [adv('GHSA-p', { ghsa: ['GHSA-p'], sources: [src('osv', 'p')] })],
  });
  assert.deepEqual(result.map((a) => a.key).sort(), ['CVE-1', 'GHSA-p']);
});

test('combineAdvisoryViews: 別名だけが重なる両側の記録は1つになり、公開側の値が優先、KEV は OR、情報源は重複を除く', () => {
  const [merged, ...rest] = combineAdvisoryViews({
    publicAdvisories: [adv('CVE-1', { cve: ['CVE-1'], ghsa: ['GHSA-x'], title: '公開側', severity: 'high', sources: [src('php-ghsa', 'a')] })],
    privateAdvisories: [adv('GHSA-x', { ghsa: ['GHSA-x'], title: '非公開側', kev: true, sources: [src('osv', 'x'), src('php-ghsa', 'a')] })],
  });
  assert.equal(rest.length, 0);
  assert.equal(merged.key, 'CVE-1');
  assert.deepEqual(merged.aliases, { cve: ['CVE-1'], ghsa: ['GHSA-x'], other: [] });
  assert.equal(merged.title, '公開側');
  assert.equal(merged.severity.level, 'high');
  assert.equal(merged.known_exploited.kev, true);
  assert.equal(merged.sources.length, 2);
  assert.equal(buildAdvisoryIndex([merged]).get('GHSA-x'), merged);
});

test('combineAdvisoryViews: 公開由来の値がフィードで更新された翌回は、新しい値が使われる（保存しない合成）', () => {
  const privateAdvisories = [adv('GHSA-x', { ghsa: ['GHSA-x'], sources: [src('osv', 'x')] })];
  const at = (title) => combineAdvisoryViews({ publicAdvisories: [adv('CVE-1', { cve: ['CVE-1'], ghsa: ['GHSA-x'], title })], privateAdvisories })[0].title;
  assert.equal(at('旧'), '旧');
  assert.equal(at('新'), '新');
});

test('combineAdvisoryViews: 取り下げは成分のすべての情報源が取り下げ済みのときだけ', () => {
  const pub = (withdrawn) => adv('CVE-1', { cve: ['CVE-1'], ghsa: ['GHSA-x'], sources: [src('php-ghsa', 'a', withdrawn)] });
  const priv = (withdrawn) => adv('GHSA-x', { ghsa: ['GHSA-x'], sources: [src('osv', 'x', withdrawn)] });
  const status = (p, q) => combineAdvisoryViews({ publicAdvisories: [pub(p)], privateAdvisories: [priv(q)] })[0].status;
  assert.equal(status('2026-11-01T00:00:00Z', null), 'active');
  assert.equal(status('2026-11-01T00:00:00Z', '2026-11-02T00:00:00Z'), 'withdrawn');
});

test('keepMatchedOnly: 照合由来だけが残り、公開由来だけ・混在の記録は捨てる。捨てた脆弱性が今回検出されても記録なしで項目は作れる', () => {
  const kept = keepMatchedOnly([
    adv('CVE-PUB', { sources: [src('php-ghsa', 'a')] }), adv('CVE-MATCH', { sources: [src('osv', 'b'), src('packagist', 'c')] }), adv('CVE-MIX', { sources: [src('osv', 'd'), src('node-core', 'e')] }),
  ]);
  assert.deepEqual(kept.map((a) => a.key), ['CVE-MATCH']);
  assert.equal(buildAdvisoryIndex(kept).get('CVE-MIX'), undefined);
});
