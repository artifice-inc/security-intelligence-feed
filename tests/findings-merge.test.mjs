import test from 'node:test';
import assert from 'node:assert/strict';
import { mergeFindings } from '../src/match/findings-merge.mjs';
import { decideScanStatus, requiredSources, requiredOsvEcosystems } from '../src/match/scan-status.mjs';
import { assertValid } from '../src/lib/schema.mjs';
import { inventoryOf } from './helpers/match-fixtures.mjs';

const T0 = '2026-10-24T00:00:00Z';
const T1 = '2026-10-25T00:00:00Z';
const PROV0 = { scanner_version: '2.7.0', script_version: 'old', osv_db: {}, inventory_commit: 'c0' };
const PROV1 = { scanner_version: '2.7.0', script_version: 'new', osv_db: {}, inventory_commit: 'c1' };

const loc = (lockfile, version, at, provenance) => ({ lockfile, package: 'p', ecosystem: 'npm', installed_version: version, last_confirmed_at: at, last_confirmed_provenance: provenance });
const item = (key, aliases, locations, extra = {}) => ({
  advisory_key: key, aliases, title: key, locations, fixed_versions: ['9.9.9'], source_urls: [], judgement: 'affected', priority: 'P2',
  evidence: 'e', kev: false, issue_number: null, first_detected_at: T0,
  last_confirmed_at: locations[0].last_confirmed_at, last_confirmed_provenance: locations[0].last_confirmed_provenance, ...extra,
});
const status = (overrides = {}) => ({
  project: 'demo', monitor_ref: 'master', inventory_status: 'fresh', scan_status: 'complete', scan_errors: [], provenance: PROV1,
  scanned_at: T1, inventory_as_of: T1, ...overrides,
});
const previousOf = (items, extra = {}) => ({ ...status({ scanned_at: T0, inventory_as_of: T0, provenance: PROV0 }), items, ...extra });

test('complete: items と locations は今回の値で置き換わり、first_detected_at と issue_number は引き継ぐ', () => {
  const previous = previousOf([item('CVE-A', ['CVE-A'], [loc('l1', '1.0.0', T0, PROV0), loc('l2', '1.0.0', T0, PROV0)], { issue_number: 7 }), item('CVE-GONE', ['CVE-GONE'], [loc('l1', '1.0.0', T0, PROV0)])]);
  const current = [item('CVE-A', ['CVE-A'], [loc('l1', '1.0.0', T1, PROV1)], { first_detected_at: T1 })];
  const merged = mergeFindings({ previous, current, status: status() });
  assertValid('findings', merged);
  assert.deepEqual(merged.items.map((i) => i.advisory_key), ['CVE-A']);
  assert.equal(merged.items[0].locations.length, 1, '一部の箇所が解消した');
  assert.equal(merged.items[0].issue_number, 7);
  assert.equal(merged.items[0].first_detected_at, T0);
  assert.equal(merged.items[0].last_confirmed_at, T1);
});

test('試験2d: partial で脆弱性 B を新規検出。A は前回の根拠のまま、B には今回の根拠が付く', () => {
  const previous = previousOf([item('CVE-A', ['CVE-A'], [loc('l1', '1.0.0', T0, PROV0)])]);
  const current = [item('CVE-B', ['CVE-B'], [loc('l1', '2.0.0', T1, PROV1)], { first_detected_at: T1 })];
  const merged = mergeFindings({ previous, current, status: status({ scan_status: 'partial' }) });
  assertValid('findings', merged);
  assert.deepEqual(merged.items.map((i) => i.advisory_key), ['CVE-A', 'CVE-B']);
  const a = merged.items[0];
  const b = merged.items[1];
  assert.equal(a.last_confirmed_at, T0);
  assert.deepEqual(a.last_confirmed_provenance, PROV0);
  assert.equal(b.last_confirmed_at, T1);
  assert.deepEqual(b.last_confirmed_provenance, PROV1);
  assert.equal(merged.scan_status, 'partial');
  assert.equal(merged.scanned_at, T1);
  assert.deepEqual(merged.provenance, PROV1);
});

test('location の根拠: 2箇所のうち1箇所だけ partial で再検出すると、もう1箇所は前回のまま', () => {
  const previous = previousOf([item('CVE-A', ['CVE-A'], [loc('l1', '1.0.0', T0, PROV0), loc('l2', '1.0.0', T0, PROV0)])]);
  const current = [item('CVE-A', ['CVE-A'], [loc('l1', '1.0.0', T1, PROV1)], { first_detected_at: T1 })];
  const merged = mergeFindings({ previous, current, status: status({ scan_status: 'partial' }) });
  const [first, second] = merged.items[0].locations;
  assert.equal(first.last_confirmed_at, T1);
  assert.equal(second.last_confirmed_at, T0);
  assert.deepEqual(second.last_confirmed_provenance, PROV0);
  assert.equal(merged.items[0].last_confirmed_at, T1, '項目の値は最も新しい箇所の派生値');
  assert.equal(merged.items[0].first_detected_at, T0);
});

test('partial: 別名が一致すれば前回の項目に統合し、別名は和集合になる', () => {
  const previous = previousOf([item('GHSA-x', ['GHSA-x'], [loc('l1', '1.0.0', T0, PROV0)], { issue_number: 3 })]);
  const current = [item('CVE-A', ['CVE-A', 'GHSA-x'], [loc('l1', '1.0.0', T1, PROV1)], { first_detected_at: T1 })];
  const merged = mergeFindings({ previous, current, status: status({ scan_status: 'partial' }) });
  assert.equal(merged.items.length, 1);
  assert.deepEqual(merged.items[0].aliases, ['CVE-A', 'GHSA-x']);
  assert.equal(merged.items[0].issue_number, 3);
});

test('partial: 今回検出されなかった項目も location も削除しない', () => {
  const previous = previousOf([item('CVE-A', ['CVE-A'], [loc('l1', '1.0.0', T0, PROV0)])]);
  const merged = mergeFindings({ previous, current: [], status: status({ scan_status: 'partial' }) });
  assert.equal(merged.items.length, 1);
  assert.equal(merged.items[0].locations[0].last_confirmed_at, T0);
});

test('試験2e: failed は項目と根拠をすべて残し、その回の状態だけ更新する', () => {
  const previous = previousOf([item('CVE-A', ['CVE-A'], [loc('l1', '1.0.0', T0, PROV0)])]);
  const errors = [{ kind: 'scanner', target: 'osv-scanner', message: 'x' }];
  const merged = mergeFindings({ previous, current: [], status: status({ scan_status: 'failed', scan_errors: errors }) });
  assertValid('findings', merged);
  assert.deepEqual(merged.items, previous.items);
  assert.equal(merged.scan_status, 'failed');
  assert.deepEqual(merged.scan_errors, errors);
  assert.equal(merged.scanned_at, T1);
  assert.deepEqual(merged.provenance, PROV1);
});

test('試験2c: fresh だった export が stale になった回は inventory_as_of を維持して partial', () => {
  const previous = previousOf([item('CVE-A', ['CVE-A'], [loc('l1', '1.0.0', T0, PROV0)])], { inventory_as_of: '2026-09-01T00:00:00Z' });
  const merged = mergeFindings({ previous, current: [], status: status({ inventory_status: 'stale_inventory', scan_status: 'partial', inventory_as_of: '2026-09-01T00:00:00Z' }) });
  assert.equal(merged.inventory_status, 'stale_inventory');
  assert.equal(merged.scan_status, 'partial');
  assert.equal(merged.inventory_as_of, '2026-09-01T00:00:00Z');
  assert.equal(merged.items.length, 1);
});

test('unavailable: inventory_as_of は前回の値を維持し、previous なしでも壊れない', () => {
  const previous = previousOf([], { inventory_as_of: '2026-10-01T00:00:00Z' });
  const merged = mergeFindings({ previous, current: [], status: status({ inventory_status: 'unavailable', scan_status: 'partial', inventory_as_of: null }) });
  assert.equal(merged.inventory_as_of, '2026-10-01T00:00:00Z');
  const first = mergeFindings({ previous: null, current: [], status: status({ scan_status: 'failed' }) });
  assertValid('findings', first);
  assert.deepEqual(first.items, []);
});

test('入力を書き換えない', () => {
  const previous = previousOf([item('CVE-A', ['CVE-A'], [loc('l1', '1.0.0', T0, PROV0)])]);
  const snapshot = JSON.stringify(previous);
  mergeFindings({ previous, current: [item('CVE-A', ['CVE-A'], [loc('l1', '1.0.0', T1, PROV1)])], status: status({ scan_status: 'partial' }) });
  assert.equal(JSON.stringify(previous), snapshot);
});

const okSources = (names) => Object.fromEntries(names.map((n) => [n, { ok: true }]));
const decide = (inventory, overrides = {}) => decideScanStatus({
  inventory, inventoryStatus: 'fresh', sourceResults: okSources(requiredSources(inventory)),
  osvDb: Object.fromEntries(requiredOsvEcosystems(inventory).map((e) => [e, true])), packagistFullSyncAt: '2026-10-20T00:00:00Z', scanErrors: [], ...overrides,
});

test('scan_status: すべて成功すれば complete', () => {
  assert.equal(decide(inventoryOf()).scan_status, 'complete');
});

test('試験2b: 必要な情報源が1つでも失敗した回は partial（前回の成功では代用しない）', () => {
  const inventory = inventoryOf();
  const sourceResults = { ...okSources(requiredSources(inventory)), kev: { ok: false } };
  const result = decide(inventory, { sourceResults });
  assert.equal(result.scan_status, 'partial');
  assert.equal(result.scan_errors[0].kind, 'source');
});

test('scan_status: 案件に関係ない情報源の失敗は影響しない', () => {
  const inventory = inventoryOf();
  const sourceResults = { ...okSources(requiredSources(inventory)), 'php-ghsa': { ok: false }, packagist: { ok: false } };
  assert.equal(decide(inventory, { sourceResults }).scan_status, 'complete');
});

test('scan_status: OSV の DB を取得できなかった回、inventory が fresh でない回は partial', () => {
  assert.equal(decide(inventoryOf(), { osvDb: { npm: false } }).scan_status, 'partial');
  assert.equal(decide(inventoryOf(), { inventoryStatus: 'stale_inventory' }).scan_status, 'partial');
  assert.equal(decide(inventoryOf(), { inventoryStatus: 'unavailable' }).scan_status, 'partial');
});

test('Packagist: full_sync_at が null の間は composer の案件が complete にならない', () => {
  const inventory = inventoryOf({ lockfiles: ['composer.lock'], files: [{ path: 'composer.lock', sha256: 'a'.repeat(64), kind: 'lockfile' }, { path: 'composer.json', sha256: 'b'.repeat(64), kind: 'composer-json' }] });
  assert.ok(requiredSources(inventory).includes('packagist'));
  assert.equal(decide(inventory).scan_status, 'complete');
  assert.equal(decide(inventory, { packagistFullSyncAt: null }).scan_status, 'partial');
});

test('scan_status: lockfile の解析失敗は partial、scanner の実行エラーと例外は failed', () => {
  assert.equal(decide(inventoryOf(), { scanErrors: [{ kind: 'lockfile', target: 'x', message: 'm' }] }).scan_status, 'partial');
  assert.equal(decide(inventoryOf(), { scanErrors: [{ kind: 'scanner', target: 'x', message: 'm' }] }).scan_status, 'failed');
  assert.equal(decide(inventoryOf(), { matchFailed: true }).scan_status, 'failed');
});
