import test from 'node:test';
import assert from 'node:assert/strict';
import { reconcileIssues } from '../src/publish/issues-reconcile.mjs';
import { createGitHubApi } from '../src/publish/github-api.mjs';
import { FakeGitHub } from './helpers/fake-github.mjs';

const NOW = '2026-10-25T00:00:00Z';
const project = { project: 'demo', owners: ['alice'] };
const itemOf = (key) => ({
  advisory_key: key, aliases: [key], title: 'Example', locations: [{ lockfile: 'package-lock.json', package: 'pkg', ecosystem: 'npm', installed_version: '1.0.0', last_confirmed_at: NOW, last_confirmed_provenance: {} }],
  fixed_versions: [], source_urls: [], judgement: 'affected', priority: 'P1', evidence: 'ev', kev: false, issue_number: null, first_detected_at: NOW, last_confirmed_at: NOW, last_confirmed_provenance: {},
});
const run = (api, keys, previousSnapshot = []) => reconcileIssues({
  api, projects: [project], findingsByProject: new Map([['demo', { project: 'demo', scan_status: 'complete', items: keys.map(itemOf) }]]), now: NOW, previousSnapshot,
});

// 一覧 API の不具合を再現するフェイク: hidden の番号は返さない / duplicated の番号は2回返す
class FlakyListing extends FakeGitHub {
  hidden = new Set();
  duplicated = new Set();
  async listIssues(args) {
    const rows = await super.listIssues(args);
    return [...rows.filter((i) => !this.hidden.has(i.number)), ...rows.filter((i) => this.duplicated.has(i.number))];
  }
}

test('一覧が同じ Issue を重複して返しても、スナップショットと索引には1回だけ載り、起票も増えない', async () => {
  const api = new FlakyListing();
  await run(api, ['CVE-1']);
  api.duplicated.add(1);
  api.resetWrites();
  const result = await run(api, ['CVE-1']);
  assert.deepEqual(result.snapshot.map((s) => s.issue_number), [1]);
  assert.equal(api.writeCount, 0);
  assert.equal(result.issueNumbers.get('demo').get('CVE-1'), 1);
});

test('作った直後の Issue を一覧が返さなくても、スナップショットには載る', async () => {
  const api = new FlakyListing();
  api.hidden.add(1);
  const result = await run(api, ['CVE-1']);
  assert.equal(api.issues.size, 1);
  assert.deepEqual(result.snapshot.map((s) => [s.issue_number, s.project, s.aliases]), [[1, 'demo', ['CVE-1']]]);
});

test('次回: 一覧が返さなくても、前回のスナップショットの番号から取得して二重に起票しない', async () => {
  const api = new FlakyListing();
  api.hidden.add(1);
  const first = await run(api, ['CVE-1']);
  api.resetWrites();
  const second = await run(api, ['CVE-1'], first.snapshot);
  assert.equal(api.issues.size, 1, '二重起票しない');
  assert.equal(api.writeCount, 0);
  assert.equal(second.issueNumbers.get('demo').get('CVE-1'), 1);
  assert.deepEqual(second.snapshot.map((s) => s.issue_number), [1]);
});

test('次回: 一覧が返す場合も二重に起票しない。前回の番号が削除済み(404)なら警告だけで続行', async () => {
  const api = new FlakyListing();
  const first = await run(api, ['CVE-1']);
  const again = await run(api, ['CVE-1'], first.snapshot);
  assert.equal(api.issues.size, 1);
  assert.equal(again.errors.length, 0);
  const missing = await run(new FlakyListing(), [], [{ issue_number: 99, project: 'demo', aliases: ['X'], state: 'open', labels: [] }]);
  assert.equal(missing.errors.length, 0);
  assert.equal(missing.warnings.length, 1);
});

test('実 API クライアント: 一覧は作成順を固定し、番号で重複を除く', async () => {
  const urls = [];
  const row = (number) => ({ number, state: 'open', title: 't', body: '', labels: [{ name: 'security-finding' }], assignees: [] });
  const fetchImpl = async (url) => { urls.push(url); return { ok: true, status: 200, json: async () => [row(19), row(20), row(19)] }; };
  const api = createGitHubApi({ repo: 'o/r', token: 't', fetchImpl, botLogin: 'bot' });
  const issues = await api.listIssues({ label: 'security-finding' });
  assert.deepEqual(issues.map((i) => i.number), [19, 20]);
  assert.match(urls[0], /sort=created&direction=asc/);
});
