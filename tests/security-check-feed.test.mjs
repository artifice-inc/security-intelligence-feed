import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, writeFileSync, rmSync, readFileSync, cpSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { execFileSync } from 'node:child_process';
import path from 'node:path';
import { assertValid } from '../src/lib/schema.mjs';
import { ROOT_DIR } from '../src/lib/config.mjs';
import { VULN, NODE_FILES, tmp, writeJson, makePrivateRoot, setup } from './helpers/check-feed-setup.mjs';
import { NOW, collectedAt } from './helpers/match-harness.mjs';

test('配布先（--feed-dir だけ）: スキーマに合い、central_diff・central_issues は null。provenance に両方の SHA、KEV・EPSS の状態が載る', async () => {
  const s = setup();
  const output = await s.run();
  assertValid('security-check-output', output);
  assert.equal(output.central_diff, null);
  assert.equal(output.central_issues, null);
  assert.equal(output.provenance.script_version, 'code-sha');
  assert.equal(output.provenance.feed_version, 'feed-sha');
  assert.deepEqual(output.feed_signals, { mode: 'latest', kev: { confirmed: true, fetched_at: collectedAt(NOW) }, epss: { state: 'fresh', fetched_at: collectedAt(NOW) } });
  assert.equal(output.local_scan.complete, true);
  assert.equal(output.results.length, 1);
});

test('フィードの KEV が優先度を上げる（P1 → P0）', async () => {
  const s = setup({ feedOptions: { kevRecords: ['CVE-2026-1'] } });
  assert.equal((await s.run()).results[0].priority, 'P0');
  assert.equal((await setup().run()).results[0].priority, 'P1');
});

test('フィードの必須ファイルが欠けると縮退: ランタイム・カーネル・Packagist は unavailable、KEV は無視、OSV の照合は続く', async () => {
  const s = setup({ feedOptions: { kevRecords: ['CVE-2026-1'] } });
  rmSync(path.join(s.feedDir, 'runtimes/php.json'));
  const output = await s.run();
  assertValid('security-check-output', output);
  assert.equal(output.provenance.feed_version, null);
  assert.equal(output.feed_signals.mode, 'degraded');
  assert.equal(output.feed_signals.kev.confirmed, false);
  assert.equal(output.results[0].priority, 'P1', 'KEV で上がらない');
  assert.equal(output.summary.rows.find((r) => r.target === 'node').state, 'unavailable');
  assert.equal(output.dependency_checks.osv, 'ok');
  assert.equal(output.local_scan.complete, false);
  assert.ok(output.local_scan.reasons.includes('公開フィードを使えないため照合が不完全です'));
  assert.ok(output.scan_errors.some((e) => e.kind === 'feed'));
});

test('縮退でも Packagist と カーネルは unavailable（「0件」と出さない）', async () => {
  const s = setup({ files: { 'composer.lock': '{"packages":[]}', 'composer.json': '{}', '.security/stack.yml': 'runtimes:\n  php: "8.3.10"\nkernel: "6.1"\n' }, ecosystems: ['npm', 'Packagist'], vulns: [] });
  rmSync(path.join(s.feedDir, 'kev.json'));
  const output = await s.run();
  assert.equal(output.dependency_checks.packagist, 'unavailable');
  assert.equal(output.dependency_check, 'unavailable');
  assert.ok(output.summary.rows.filter((r) => r.kind !== 'lockfile').every((r) => r.state !== 'ok'));
});

test('--no-feed と、data がファイルで読めない場合も OSV の照合が続き、feed_version は null', async () => {
  const none = await setup().run({ feedDir: null, noFeed: true });
  assert.equal(none.results.length, 1);
  assert.equal(none.provenance.feed_version, null);
  assert.equal(none.local_scan.complete, false);
  assert.equal(none.local_scan.reasons[0], '公開フィードを使えないため照合が不完全です');
  const asFile = tmp('si-file-');
  const filePath = path.join(asFile, 'data');
  writeFileSync(filePath, 'x');
  const output = await setup().run({ feedDir: filePath });
  assert.equal(output.results.length, 1);
  assert.equal(output.provenance.feed_version, null);
});

test('--osv-db-dir がなければ新しい経路は始まらない（CLI は終了コード 2）', () => {
  const run = (...args) => { try { execFileSync('node', [path.join(ROOT_DIR, 'src/cli/security-check.mjs'), '--project-dir', tmp('si-p-'), ...args], { stdio: 'pipe' }); return 0; } catch (error) { return error.status; } };
  assert.equal(run('--feed-dir', tmp('si-f-')), 2);
  assert.equal(run('--no-feed'), 2);
  assert.equal(run('--no-feed', '--feed-dir', tmp('si-f-'), '--osv-db-dir', tmp('si-o-')), 2);
});

test('フィードは検証を通るが run_slot が古い／必須の情報源が枠で失敗: 結果は出るが complete: false', async () => {
  const stale = setup();
  const healthFile = path.join(stale.feedDir, 'health.json');
  writeJson(healthFile, { ...JSON.parse(readFileSync(healthFile, 'utf8')), run_slot: '2026-11-21T07:17Z' });
  const old = await stale.run();
  assert.equal(old.results.length, 1);
  assert.equal(old.local_scan.complete, false);
  assert.ok(old.local_scan.reasons.some((r) => r.includes('予定枠')));
  assert.notEqual(old.provenance.feed_version, null);

  const php = setup({ files: { 'composer.lock': '{"packages":[]}', 'composer.json': '{}', '.security/stack.yml': 'runtimes:\n  php: "8.3.10"\n' }, ecosystems: ['npm', 'Packagist'], vulns: [], feedOptions: { failing: ['php-ghsa'] } });
  const out = await php.run();
  assert.equal(out.local_scan.complete, false);
  assert.ok(out.local_scan.reasons.some((r) => r.includes('php-ghsa')));
});

test('スタッフ: 非公開側の閾値で判定する（公開側の EPSS の閾値が高ければ complete: false。配布先は公開側の値で fresh）', async () => {
  const privateRoot = makePrivateRoot({ thresholds: { epss_percentile_p1: 0.9 } });
  const staff = await setup({ feedOptions: { epssThreshold: 0.95 } }).run({ privateRoot });
  assert.equal(staff.feed_signals.epss.state, 'previous');
  assert.equal(staff.local_scan.complete, false);
  assert.ok(staff.local_scan.reasons.some((r) => r.includes('epss')));
  const distributor = await setup({ feedOptions: { epssThreshold: 0.95 } }).run();
  assert.equal(distributor.feed_signals.epss.state, 'fresh');
});

test('スタッフ: projects.yaml の exposure・lockfiles を使い、pull 失敗は complete: false', async () => {
  const privateRoot = makePrivateRoot({ projects: 'projects:\n  - project: demo\n    exposure: internal\n' });
  const output = await setup().run({ privateRoot, exposure: null, pullOk: false });
  assert.equal(output.results[0].priority, 'P2', 'internal の申告で P1 にならない');
  assert.equal(output.local_scan.complete, false);
  assert.equal(output.central_issues, null, 'issues.json がなければ null');
  assert.deepEqual(output.central_diff, {});
});

// 中央の findings を、手元の出力と同じ provenance で作る
const writeCentral = (privateRoot, output, extra = {}) => writeJson(path.join(privateRoot, 'data/findings/demo.json'), { scan_status: 'complete', provenance: output.provenance, items: output.results.map((r) => ({ advisory_key: r.advisory_key, aliases: r.aliases })), ...extra });

test('mismatch_with_same_provenance: 同じ provenance で差があれば立つ。フィード違い・中央 partial・縮退では立たない', async () => {
  const privateRoot = makePrivateRoot();
  const s = setup();
  writeCentral(privateRoot, await s.run({ privateRoot }));
  s.state.vulns = []; // 手元だけ検出が変わった
  const same = await s.run({ privateRoot });
  assert.deepEqual(same.central_diff.only_central, ['CVE-2026-1']);
  assert.equal(same.central_diff.mismatch_with_same_provenance, true);
  assert.equal((await s.run({ privateRoot, feedSha: 'other-sha' })).central_diff.mismatch_with_same_provenance, undefined);
  writeCentral(privateRoot, same, { scan_status: 'partial', provenance: { ...same.provenance } });
  assert.equal((await s.run({ privateRoot })).central_diff.mismatch_with_same_provenance, undefined);
  const degradedCentral = await s.run({ privateRoot, feedDir: null, noFeed: true });
  writeCentral(privateRoot, degradedCentral);
  assert.equal((await s.run({ privateRoot, feedDir: null, noFeed: true })).central_diff.mismatch_with_same_provenance, undefined);
});

test('--private-root がないと central_diff は null（--feed-dir なしの今の動きは tests/security-check.test.mjs が確かめる）', async () => {
  assert.equal((await setup().run()).central_diff, null);
});
