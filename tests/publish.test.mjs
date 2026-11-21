import test from 'node:test';
import assert from 'node:assert/strict';
import { sendHeartbeat } from '../src/publish/heartbeat.mjs';
import { renderDigest } from '../src/publish/digest.mjs';
import { buildHealth, staleSources } from '../src/publish/health.mjs';
import { assertValid } from '../src/lib/schema.mjs';
import { loadSchedule } from '../src/lib/config.mjs';

const URL_SECRET = 'https://hc-ping.example/very-secret-uuid';

test('heartbeat: 本体なしの GET を送り、失敗しても URL を返さない', async () => {
  let seen;
  assert.deepEqual(await sendHeartbeat({ url: URL_SECRET, fetchImpl: async (u, init) => { seen = init; return { ok: true }; } }), { ok: true });
  assert.equal(seen.method, 'GET');
  assert.equal(seen.body, undefined);
  const failed = await sendHeartbeat({ url: URL_SECRET, fetchImpl: async () => { throw new Error(`boom ${URL_SECRET}`); } });
  assert.equal(failed.ok, false);
  assert.ok(!JSON.stringify(failed).includes('secret'));
  assert.equal((await sendHeartbeat({ url: undefined })).ok, false);
});

const now = '2026-10-25T00:00:00Z';
const health = buildHealth({ previous: null, now, startedAt: now, status: 'partial', sourceResults: { kev: { ok: false, error: { kind: 'network', message: 'x', http_status: null } }, epss: { ok: true } }, projectStates: {}, osvMeta: {}, packagistUpdatedSince: null });

test('health: partial では last_success_at を更新せず、失敗した情報源の最終成功を保つ', () => {
  assert.equal(health.last_success_at, null);
  assertValid('health', health);
  const next = buildHealth({ previous: health, now: '2026-10-26T00:00:00Z', startedAt: now, status: 'success', sourceResults: { kev: { ok: true } }, projectStates: {}, osvMeta: {}, packagistUpdatedSince: 5 });
  assert.equal(next.last_success_at, '2026-10-26T00:00:00Z');
  assert.equal(next.sources.kev.last_success_at, '2026-10-26T00:00:00Z');
  assert.equal(next.sources.epss.last_success_at, now, '試行しなかった情報源は前回のまま');
  assert.ok(staleSources(next, '2026-10-26T00:00:00Z').includes('node-core'), '一度も成功していない情報源は古い扱い');
  assert.ok(!staleSources(next, '2026-10-26T00:00:00Z').includes('kev'));
});

test('digest: 照合に失敗した案件も省略せず、外部の文字列は無害化され、生成日時を含まない', () => {
  const projects = [{ project: 'a', repo: 'o/a', monitor_ref: 'main', owners: ['x'], exposure: 'internet' }, { project: 'b', source: 'export', monitor_ref: 'main', owners: ['x'], exposure: 'internal' }];
  const findings = new Map([['a', { monitor_ref: 'main', scanned_at: now, scan_status: 'failed', inventory_status: 'unavailable', items: [{ priority: 'P0', advisory_key: 'CVE-1 @evil', kev: true, issue_number: 4, locations: [{ package: '<script>' }], first_detected_at: now }] }]]);
  const text = renderDigest({ projects, findingsByProject: findings, snapshot: [{ issue_number: 4, project: 'a', state: 'open', labels: ['P0'] }], digestInfo: { fixedInRepo: [], riskAccepted: [], transitions: [] }, health, schedule: loadSchedule(), now, centralRepo: 'org/central', kevRecords: [], jpItems: [] });
  assert.match(text, /\| a \|/);
  assert.match(text, /\| b \|.*未照合/);
  assert.ok(!text.includes('<script>'));
  assert.ok(!text.includes('@evil'));
  assert.match(text, /次の予定時刻/);
  assert.ok(!/生成日時/.test(text));
});
