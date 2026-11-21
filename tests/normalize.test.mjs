import test from 'node:test';
import assert from 'node:assert/strict';
import { mergeAdvisories } from '../src/normalize/advisories.mjs';
import { fromOsv, fromPhpGhsa, fromNodeCore, previousNodeCoreShas } from '../src/normalize/sources.mjs';
import { enrichAdvisories } from '../src/normalize/enrich.mjs';
import { normalizeJpAlerts } from '../src/normalize/jp-alerts.mjs';
import { buildPhpRuntime, buildNodeRuntime } from '../src/normalize/runtimes.mjs';
import { planPackagistFetch, applyPackagist, emptyPackagist } from '../src/normalize/packagist.mjs';
import { assertValid } from '../src/lib/schema.mjs';
import { osvRecord } from './helpers/osv-records.mjs';

const T1 = new Date('2026-10-25T00:00:00Z');
const T2 = new Date('2026-10-25T08:00:00Z');
const apply = (previous, records, now) => {
  const changed = mergeAdvisories({ previous, records, now });
  const byKey = new Map(previous.map((a) => [a.key, a]));
  for (const [k, v] of changed) byKey.set(k, v);
  return { all: [...byKey.values()], changed };
};

test('新規のアドバイザリはスキーマを通り、GHSA を正規キーにする', () => {
  const { all } = apply([], [fromOsv(osvRecord(), { now: T1 })], T1);
  assert.equal(all.length, 1);
  assertValid('advisory', all[0]);
  assert.equal(all[0].key, 'GHSA-aaaa-bbbb-cccc');
  assert.equal(all[0].severity.level, 'high');
  assert.deepEqual(all[0].affected[0].from_sources, ['osv:GHSA-aaaa-bbbb-cccc']);
});

test('同じ入力で2回実行すると2回目の差分は0（T3 完了条件）', () => {
  const records = [fromOsv(osvRecord({ aliases: ['CVE-2026-1'] }), { now: T1 })];
  const first = apply([], records, T1);
  const again = mergeAdvisories({ previous: first.all, records: [fromOsv(osvRecord({ aliases: ['CVE-2026-1'] }), { now: T2 })], now: T2 });
  assert.equal(again.size, 0);
});

test('試験5: 正規キーが GHSA から CVE に変わる。旧ファイルは残り superseded_by が付く', () => {
  const first = apply([], [fromOsv(osvRecord(), { now: T1 })], T1);
  const second = apply(first.all, [fromOsv(osvRecord({ aliases: ['CVE-2026-1'], modified: '2026-10-02T00:00:00Z' }), { now: T2 })], T2);
  const cve = second.all.find((a) => a.key === 'CVE-2026-1');
  const ghsa = second.all.find((a) => a.key === 'GHSA-aaaa-bbbb-cccc');
  assert.ok(cve && ghsa);
  assert.equal(ghsa.superseded_by, 'CVE-2026-1');
  assert.deepEqual(cve.aliases.ghsa, ['GHSA-aaaa-bbbb-cccc']);
  assert.equal(cve.first_seen_at, '2026-10-25T00:00:00Z');
  assert.equal(second.all.filter((a) => !a.superseded_by).length, 1);
  // 付け替えた後の2回目は差分なし
  const third = mergeAdvisories({ previous: second.all, records: [fromOsv(osvRecord({ aliases: ['CVE-2026-1'], modified: '2026-10-02T00:00:00Z' }), { now: T2 })], now: T2 });
  assert.equal(third.size, 0);
});

test('別名で別々の情報源が1件に統合される（OSV と php-ghsa）', () => {
  const osv = fromOsv(osvRecord({ id: 'GHSA-x', aliases: ['CVE-5'] }), { now: T1 });
  const other = fromPhpGhsa({ ghsa_id: 'GHSA-x', cve_id: 'CVE-5', published_at: null, updated_at: null, withdrawn_at: null, severity: 'high', summary: 's', html_url: 'u', vulnerabilities: [{ package: 'ext-standard', vulnerable_version_range: '<8.2.35', patched_versions: '8.2.35', parsed: [{ type: 'PHP_BRANCH', branch: '8.2', fixed: '8.2.35' }] }] }, { now: T1 });
  const { all } = apply([], [osv, other], T1);
  assert.equal(all.length, 1);
  assert.equal(all[0].sources.length, 2);
});

test('試験4: 一部の情報源だけが取り下げられると、残る情報源で影響範囲が作り直される', () => {
  const a = fromOsv(osvRecord({ id: 'GHSA-x', aliases: ['CVE-5'], affected: [{ package: { ecosystem: 'npm', name: 'pkg-a' }, ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '1.0.0' }] }] }] }), { now: T1 });
  const b = fromOsv(osvRecord({ id: 'GHSA-y', aliases: ['CVE-5'], affected: [{ package: { ecosystem: 'npm', name: 'pkg-b' }, ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '2.0.0' }] }] }] }), { now: T1 });
  const first = apply([], [a, b], T1);
  assert.equal(first.all[0].affected.length, 2);
  const withdrawn = fromOsv(osvRecord({ id: 'GHSA-y', aliases: ['CVE-5'], withdrawn: '2026-10-03T00:00:00Z', modified: '2026-10-03T00:00:00Z' }), { now: T2 });
  const second = apply(first.all, [withdrawn], T2);
  const adv = second.all[0];
  assert.equal(adv.status, 'active');
  assert.deepEqual(adv.affected.map((x) => x.package.name), ['pkg-a']);
  assert.equal(adv.sources.find((s) => s.id === 'GHSA-y').withdrawn_at, '2026-10-03T00:00:00Z');
  assert.equal(adv.history.at(-1).significant, true);
});

test('有効な情報源がすべて取り下げられたら status が withdrawn になる', () => {
  const first = apply([], [fromOsv(osvRecord(), { now: T1 })], T1);
  const second = apply(first.all, [fromOsv(osvRecord({ withdrawn: '2026-10-03T00:00:00Z', modified: '2026-10-03T00:00:00Z' }), { now: T2 })], T2);
  assert.equal(second.all[0].status, 'withdrawn');
  assert.deepEqual(second.all[0].affected, []);
});

test('影響範囲が変わると significant な履歴が付く。モディファイだけなら付かない', () => {
  const first = apply([], [fromOsv(osvRecord(), { now: T1 })], T1);
  const changedRange = osvRecord({ modified: '2026-10-04T00:00:00Z', affected: [{ package: { ecosystem: 'npm', name: 'example-package' }, ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '1.2.4' }] }] }] });
  const second = apply(first.all, [fromOsv(changedRange, { now: T2 })], T2);
  assert.deepEqual(second.all[0].history.at(-1), { at: '2026-10-25T08:00:00Z', changes: ['affected'], significant: true });
  const textOnly = apply(second.all, [fromOsv({ ...changedRange, details: 'more text', modified: '2026-10-05T00:00:00Z' }, { now: T2 })], T2);
  assert.equal(textOnly.all[0].history.at(-1).significant, false);
});

test('KEV と EPSS と国内注意喚起が付与され、失敗した回（null）は前回のまま', () => {
  const { all } = apply([], [fromOsv(osvRecord({ aliases: ['CVE-2026-1'] }), { now: T1 })], T1);
  const jp = [{ source: 'jpcert', id: 'at1', title: 't', link: 'l', cves: ['CVE-2026-1'] }];
  const kev = [{ cveID: 'CVE-2026-1', dateAdded: '2026-10-20' }];
  const epss = [{ cve: 'CVE-2026-1', epss: 0.5, percentile: 0.97, score_date: '2026-10-24T12:00:00Z' }];
  const enriched = enrichAdvisories({ advisories: all, kevRecords: kev, epssRecords: epss, jpItems: jp, now: T2 });
  const next = enriched.get('CVE-2026-1');
  assert.deepEqual(next.known_exploited, { kev: true, date_added: '2026-10-20' });
  assert.equal(next.epss.percentile, 0.97);
  assert.equal(next.jp_alerts.length, 1);
  assert.equal(next.history.at(-1).changes[0], 'kev');
  assertValid('advisory', next);
  const keep = enrichAdvisories({ advisories: [next], kevRecords: null, epssRecords: null, jpItems: jp, now: T2 });
  assert.equal(keep.size, 0);
});

test('node-core: NODE_SEMVER の範囲と修正版、blob sha が前回値として復元できる', () => {
  const record = fromNodeCore({ id: '204', sha: 'abc', cve: ['CVE-2026-111497'], vulnerable: '22.x || 24.x', patched: '^22.23.4 || ^24.22.1', severity: 'high', ref: 'https://x', description: 'd' }, { now: T1 });
  const { all } = apply([], [record], T1);
  assert.equal(all[0].key, 'CVE-2026-111497');
  assert.equal(all[0].category, 'runtime');
  assert.deepEqual(all[0].affected[0].ranges[0].fixed_versions, ['22.23.4', '24.22.1']);
  assert.deepEqual(previousNodeCoreShas(all), { 204: 'abc' });
});

test('runtimes: PHP / Node の branches と advisories を作り、取り下げ済みは除く', () => {
  const ghsa = (id, withdrawn) => fromPhpGhsa({ ghsa_id: id, cve_id: null, published_at: null, updated_at: null, withdrawn_at: withdrawn, severity: 'high', summary: 's', html_url: 'u', vulnerabilities: [{ package: 'php', vulnerable_version_range: '<8.2.35', patched_versions: '8.2.35', parsed: [{ type: 'PHP_BRANCH', branch: '8.2', fixed: '8.2.35' }] }] }, { now: T1 });
  const { all } = apply([], [ghsa('GHSA-p1', null), ghsa('GHSA-p2', '2026-10-01T00:00:00Z')], T1);
  const php = buildPhpRuntime({
    previous: null, now: T1, advisories: all,
    phpReleases: [{ type: 'branch', branch: '8.2', state: 'security', security_support_end: '2026-12-31', active_support_end: null }, { type: 'branch', branch: '8.0', state: 'eol', security_support_end: '2023-11-26', active_support_end: null }],
    endoflife: [{ product: 'php', name: '8.2', isEol: false, latest: '8.2.34' }],
  });
  assertValid('runtimes', php);
  assert.deepEqual(php.advisories.map((a) => a.key), ['GHSA-p1']);
  assert.equal(php.branches.find((b) => b.branch === '8.0').is_eol, true);
  assert.equal(php.branches.find((b) => b.branch === '8.2').latest_version, '8.2.34');
  const node = buildNodeRuntime({ previous: null, now: T1, advisories: [], nodeDist: [{ version: 'v24.22.1' }], endoflife: [{ product: 'nodejs', name: '24', isEol: false, isLts: true, eolFrom: '2028-04-30', latest: null }] });
  assertValid('runtimes', node);
  assert.equal(node.branches[0].latest_version, '24.22.1');
  // 同じ入力なら updated_at は変わらない
  assert.equal(buildNodeRuntime({ previous: node, now: T2, advisories: [], nodeDist: [{ version: 'v24.22.1' }], endoflife: [{ product: 'nodejs', name: '24', isEol: false, isLts: true, eolFrom: '2028-04-30', latest: null }] }).updated_at, node.updated_at);
});

test('jp-alerts: 失敗した情報源は前回の項目を残し、first_seen_at を保つ', () => {
  const rec = (source, id) => ({ source, id, title: id, link: `https://x/${id}`, date: '2026-10-20', cves: [], verification_status: 'needs_review' });
  const first = normalizeJpAlerts({ previous: null, results: { jpcert: { ok: true, records: [rec('jpcert', 'a')] }, ipa: { ok: true, records: [rec('ipa', 'b')] } }, now: T1 });
  assertValid('jp-alerts', first);
  const second = normalizeJpAlerts({ previous: first, results: { jpcert: { ok: false, records: [] }, ipa: { ok: true, records: [rec('ipa', 'b'), rec('ipa', 'c')] } }, now: T2 });
  assert.equal(second.items.length, 3);
  assert.equal(second.items.find((i) => i.id === 'b').first_seen_at, '2026-10-25T00:00:00Z');
  const third = normalizeJpAlerts({ previous: second, results: { ipa: { ok: true, records: [rec('ipa', 'b'), rec('ipa', 'c')] } }, now: new Date('2026-10-26T00:00:00Z') });
  assert.equal(third.updated_at, second.updated_at);
});

test('packagist: 初回と7日経過で全件、それ以外は差分。GHSA を持つものは入れない', () => {
  assert.deepEqual(planPackagistFetch(null, T1), { full: true, updatedSince: 0 });
  const rec = (id, ghsa) => ({ advisoryId: id, packageName: 'v/p', affectedVersions: '<1.0.0', cve: null, title: 't', link: null, reportedAt: null, sources: ghsa ? [{ name: 'GitHub', remoteId: 'GHSA-x' }] : [] });
  const plan = planPackagistFetch(null, T1);
  const first = applyPackagist({ previous: null, plan, result: { ok: true, records: [rec('PKSA-1', false), rec('PKSA-2', true)] }, now: T1 });
  assertValid('packagist-advisories', first);
  assert.deepEqual(Object.keys(first.advisories), ['PKSA-1']);
  assert.equal(first.full_sync_at, '2026-10-25T00:00:00Z');

  const diffPlan = planPackagistFetch(first, T2);
  assert.equal(diffPlan.full, false);
  assert.ok(diffPlan.updatedSince > 0);
  // 差分が空でも既存は消えない
  const empty = applyPackagist({ previous: first, plan: diffPlan, result: { ok: true, records: [] }, now: T2 });
  assert.deepEqual(Object.keys(empty.advisories), ['PKSA-1']);
  // 失敗した回はファイルを変えない
  assert.equal(applyPackagist({ previous: first, plan: diffPlan, result: { ok: false, records: [] }, now: T2 }), first);
  // 7日後は全件を作り直し、取り下げられたものが消える
  const later = new Date('2026-11-02T00:00:00Z');
  const fullPlan = planPackagistFetch(first, later);
  assert.equal(fullPlan.full, true);
  const rebuilt = applyPackagist({ previous: first, plan: fullPlan, result: { ok: true, records: [rec('PKSA-3', false)] }, now: later });
  assert.deepEqual(Object.keys(rebuilt.advisories), ['PKSA-3']);
  assert.equal(emptyPackagist().full_sync_at, null);
});

test('runtimes: published_at は source のうち最も古いものが入り、なければ null', () => {
  const advisory = (sources) => ({ key: 'CVE-P', aliases: { cve: ['CVE-P'], ghsa: [], other: [] }, category: 'runtime', ecosystem: 'php', status: 'active', superseded_by: null, affected: [{ ranges: [{ type: 'PHP_BRANCH', branch: '8.2', fixed: '8.2.1' }] }], sources });
  const build = (sources) => buildPhpRuntime({ previous: null, now: T1, advisories: [advisory(sources)], phpReleases: [], endoflife: [] });
  const source = (published_at) => ({ name: 'x', id: 'i', url: 'https://example.com/a', published_at, withdrawn_at: null });
  const php = build([source('2026-10-21T13:34:25Z'), source('2026-10-20T00:00:00Z'), source(null)]);
  assertValid('runtimes', php);
  assert.equal(php.advisories[0].published_at, '2026-10-20T00:00:00Z');
  assert.equal(build([source(null)]).advisories[0].published_at, null);
});
