import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, readFileSync, readdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { makeMatchHarness, collectedAt, slotFor, sampleProjects, PROJECT, NOW } from './helpers/match-harness.mjs';
import { exportInventory } from '../src/inventory/export-inventory.mjs';
import { createGitHubApi } from '../src/publish/github-api.mjs';

const VULN = { id: 'GHSA-aaaa-bbbb-cccc', aliases: ['CVE-2026-1'], severity: 'HIGH' };
const MODERATE = { ...VULN, severity: 'MODERATE' };
const DAY_MS = 86_400_000;
const addDays = (iso, days) => new Date(new Date(iso).getTime() + days * DAY_MS).toISOString().replace(/\.\d{3}Z$/, 'Z');
const findings = (h) => h.readOut(`findings/${PROJECT}.json`);

test('優先度は非公開側の閾値で決まる（公開側 0.90・非公開側 0.95 で百分位 0.92 は上位でない）。0.97 なら P1', async () => {
  const h = makeMatchHarness();
  h.state.vulns = [MODERATE];
  assert.equal((await h.match({ feedOptions: { epssThreshold: 0.9, epssRows: [['CVE-2026-1', 0.92]] } })).status, 'success');
  assert.deepEqual([findings(h).items[0].priority, findings(h).items[0].priority_inputs.epss_high], ['P2', false]);
  const high = makeMatchHarness();
  high.state.vulns = [MODERATE];
  await high.match({ feedOptions: { epssThreshold: 0.9, epssRows: [['CVE-2026-1', 0.97]] } });
  assert.deepEqual([findings(high).items[0].priority, findings(high).items[0].priority_inputs.epss_high], ['P1', true]);
});

test('KEV: フィードの kev.json にある CVE の検出は P0', async () => {
  const h = makeMatchHarness();
  h.state.vulns = [VULN];
  await h.match({ feedOptions: { kevRecords: ['CVE-2026-1'] } });
  assert.equal(findings(h).items[0].priority, 'P0');
});

test('AWS だけが失敗: 最終の検証とコミットが通り、first_attempt_at が保たれて保存値・digest・health Issue に長期未取得の警告が出る', async () => {
  const h = makeMatchHarness();
  const awsFailing = (now) => ({ 'aws-bulletins': { last_attempt_at: collectedAt(now), last_success_at: null, last_attempt_slot: slotFor(now), last_success_slot: null, last_attempt_ok: false, last_error: { kind: 'network', at: collectedAt(now) } } });
  const first = await h.match({ feedOptions: { optional: awsFailing(NOW) } });
  assert.equal(first.committed, true, first.reasons.join('\n'));
  const firstAttempt = h.readOut('health.json').optional_sources['aws-bulletins'].first_attempt_at;
  assert.equal(firstAttempt, collectedAt(NOW));
  assert.equal(h.healthIssues().length, 0);
  const later = addDays(NOW, 8);
  const second = await h.match({ now: later, feedOptions: { optional: awsFailing(later) } });
  assert.equal(second.committed, true, second.reasons.join('\n'));
  assert.equal(h.readOut('health.json').optional_sources['aws-bulletins'].first_attempt_at, firstAttempt);
  assert.ok(h.readText('digest/latest.md').includes('7日以上取得できていません'));
  assert.ok(h.healthIssues()[0].body.includes('aws-bulletins'));
});

test('OSV の DB: キャッシュから復元した状態で、フィードの取得と DB の更新の両方に失敗しても、前回の DB による検出が保存される', async () => {
  const h = makeMatchHarness();
  h.state.vulns = [];
  await h.match();
  h.state.vulns = [VULN];
  h.state.osvOk = { npm: false, Packagist: false, PyPI: false };
  const out = await h.match({ feedOptions: false, feedUrl: 'file:///nonexistent-feed-remote' });
  assert.equal(out.status, 'partial');
  assert.equal(findings(h).items.length, 1);
  assert.equal(out.committed, true);
});

test('PyPI の DB だけが更新に失敗し PyPI を使う案件がない: 案件は complete、全体は partial、health Issue に PyPI が載る', async () => {
  const h = makeMatchHarness();
  h.state.osvOk = { npm: true, Packagist: true, PyPI: false };
  const out = await h.match();
  assert.equal(out.status, 'partial');
  assert.equal(findings(h).scan_status, 'complete');
  assert.ok(h.healthIssues()[0].body.includes('PyPI'));
  assert.equal(h.state.heartbeats, 0);
});

test('push の失敗・reconcile のエラー: 完了通知を送らず、health Issue にその失敗が載る', async () => {
  const pushFail = makeMatchHarness();
  pushFail.state.pushFails = true;
  const failed = await pushFail.match();
  assert.equal(failed.status, 'failed');
  assert.equal(pushFail.state.heartbeats, 0);
  assert.ok(pushFail.healthIssues()[0].body.includes('push'));

  const reconcile = makeMatchHarness();
  reconcile.state.vulns = [VULN];
  reconcile.api.failNext('createIssue', ([data]) => data.labels.includes('security-finding'), 99);
  const partial = await reconcile.match();
  assert.equal(partial.status, 'partial');
  assert.equal(reconcile.state.heartbeats, 0);
  assert.ok(reconcile.healthIssues()[0].body.includes('Issue 操作の失敗'));
});

test('1回目の検証の失敗: 脆弱性 Issue を操作せず、コミットも完了通知もない。最終の検証の失敗: コミットせず health Issue に載る', async () => {
  const first = makeMatchHarness();
  first.state.vulns = [VULN];
  const broken = { resolveInventory: async (args) => { const resolved = await first.deps.resolveInventory(args); resolved.inventory.files[0].sha256 = 'zz'; return resolved; } };
  const out = await first.match({ deps: broken });
  assert.equal(out.status, 'failed');
  assert.ok(out.reasons.some((r) => r.includes('1回目')));
  assert.equal(first.vulnIssues().length, 0);
  assert.equal(out.committed, false);
  assert.ok(first.healthIssues()[0].body.includes('1回目'));

  const last = makeMatchHarness();
  last.state.vulns = [VULN];
  last.state.osvMeta = { fetched_at: NOW }; // health.json の osv_db だけがスキーマに合わない
  const lastOut = await last.match();
  assert.equal(lastOut.status, 'failed');
  assert.ok(lastOut.reasons.some((r) => r.includes('最終')));
  assert.equal(lastOut.committed, false);
  assert.equal(last.state.heartbeats, 0);
  assert.ok(last.healthIssues()[0].body.includes('最終'));
});

test('取り下げ: 合成した成分のすべての情報源が取り下げ済みなら advisory-withdrawn。公開側に有効な情報源が残れば付かない。degraded の回は付かない', async () => {
  const withdrawnLabel = async ({ feedExtra = [], degraded = false }) => {
    const h = makeMatchHarness();
    h.state.vulns = [VULN];
    await h.match();
    const issueNumber = h.vulnIssues()[0].number;
    const advisoryFile = path.join(h.central.root, 'data', 'advisories');
    const [name] = readdirSync(advisoryFile);
    const advisory = JSON.parse(readFileSync(path.join(advisoryFile, name), 'utf8'));
    writeFileSync(path.join(advisoryFile, name), JSON.stringify({ ...advisory, sources: advisory.sources.map((s) => ({ ...s, withdrawn_at: '2026-11-21T00:00:00Z' })) }));
    h.commitData('withdraw');
    h.state.vulns = [];
    const options = degraded ? { feedOptions: false, feedUrl: 'file:///nonexistent-feed-remote' } : { feedOptions: { extraAdvisories: feedExtra(advisory) } };
    await h.match(options);
    return h.api.issues.get(issueNumber).labels.includes('advisory-withdrawn');
  };
  assert.equal(await withdrawnLabel({ feedExtra: () => [] }), true);
  // 公開側の有効な記録（別名で非公開側の記録とつながる）
  const publicFixture = JSON.parse(readFileSync(path.join(import.meta.dirname, 'fixtures', 'feed', 'advisories', 'CVE-2015-6764.json'), 'utf8'));
  const activePublic = (advisory) => [{ ...publicFixture, aliases: { ...publicFixture.aliases, ghsa: [advisory.key] } }];
  assert.equal(await withdrawnLabel({ feedExtra: activePublic }), false);
  assert.equal(await withdrawnLabel({ degraded: true }), false);
});

test('risk_accepted_days が公開側と非公開側で違う: Issue の状態と digest が非公開側の値に従う', async () => {
  const h = makeMatchHarness({ privateThresholds: { risk_accepted_days: 200 } });
  h.state.vulns = [VULN];
  await h.match();
  const number = h.vulnIssues()[0].number;
  h.api.humanClose(number);
  h.api.humanLabel(number, 'risk-accepted', addDays(NOW, -100));
  const later = addDays(NOW, 1);
  await h.match({ now: later });
  assert.equal(h.api.issues.get(number).state, 'closed', '公開側の90日なら期限切れで再オープンされる');
  assert.ok(h.readText('digest/latest.md').includes('200日で期限'));
});

test('export_max_days が公開側30日・非公開側14日で20日前の export: 期限切れとして partial、前回の項目は消えない', async () => {
  const projectDir = mkdtempSync(path.join(tmpdir(), 'export-src-'));
  writeFileSync(path.join(projectDir, 'package-lock.json'), '{}');
  writeFileSync(path.join(projectDir, '.nvmrc'), '22.11.0');
  const h = makeMatchHarness({ privateThresholds: { export_max_days: 14 }, projects: sampleProjects({ source: 'export', repo: undefined }) });
  h.state.vulns = [VULN];
  exportInventory({ projectDir, project: PROJECT, outDir: path.join(h.central.root, 'data', 'inventory-export', PROJECT), now: addDays(NOW, -1), sourceRef: 'main', sourceCommit: 'abc' });
  assert.equal((await h.match()).status, 'success');
  const later = addDays(NOW, 19);
  const out = await h.match({ now: later });
  assert.equal(out.status, 'partial');
  assert.equal(findings(h).inventory_status, 'stale_inventory');
  assert.equal(findings(h).items.length, 1);
});

test('python_release_grace_days が公開側7日・非公開側14日で PSF の同期がリリースの10日後: 非公開側の猶予中として partial、前回の項目は残る', async () => {
  const python = { runtime: 'python', updated_at: NOW, psf_synced_at: '2026-11-21T00:00:00Z', pending: [], advisories: [], branches: [{ branch: '3.12', state: 'maintained', security_support_end: '2028-10-31', is_eol: false, latest_version: '3.12.7', versions: [{ version: '3.12.7', date: '2026-11-11' }] }] };
  const h = makeMatchHarness({ privateThresholds: { python_release_grace_days: 14 }, projectFiles: { 'package-lock.json': '{}', '.nvmrc': '22.11.0', '.python-version': '3.12.7' } });
  h.state.vulns = [VULN];
  const out = await h.match({ feedOptions: { python } });
  assert.equal(out.status, 'partial');
  assert.ok(findings(h).scan_errors.some((e) => e.target === 'python-psf' && e.message.includes('14 日以内')), JSON.stringify(findings(h).scan_errors));
  assert.equal(findings(h).items.length, 1);
});

test('createGitHubApi は非公開側の bot_login と user_agent を使う', async () => {
  const calls = [];
  const api = createGitHubApi({ repo: 'o/r', token: 't', botLogin: 'private-bot', userAgent: 'private-agent', fetchImpl: async (url, init) => { calls.push(init.headers['User-Agent']); return { ok: true, status: 200, json: async () => [] }; } });
  await api.listLabels();
  assert.deepEqual([api.botLogin, calls[0]], ['private-bot', 'private-agent']);
});
