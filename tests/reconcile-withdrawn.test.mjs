import test from 'node:test';
import assert from 'node:assert/strict';
import { reconcileIssues } from '../src/publish/issues-reconcile.mjs';
import { FakeGitHub } from './helpers/fake-github.mjs';

const NOW = '2026-10-25T00:00:00Z';
const project = { project: 'demo', owners: ['alice'] };
const itemOf = (key) => ({
  advisory_key: key, aliases: [key], title: 'Example', locations: [{ lockfile: 'package-lock.json', package: 'pkg', ecosystem: 'npm', installed_version: '1.0.0', last_confirmed_at: NOW, last_confirmed_provenance: {} }],
  fixed_versions: [], source_urls: [], judgement: 'affected', priority: 'P1', evidence: 'ev', kev: false, issue_number: null, first_detected_at: NOW, last_confirmed_at: NOW, last_confirmed_provenance: {},
});
const run = (api, items, withdrawn = () => false) => reconcileIssues({
  api, projects: [project], findingsByProject: new Map([['demo', { project: 'demo', scan_status: 'complete', items }]]), now: NOW, isWithdrawnAliases: withdrawn,
});
const issue = (api) => [...api.issues.values()][0];

test('a. 全情報源が取り下げられ項目が消えた: advisory-withdrawn が付き、fixed-in-repo は付かない。コメントは1回、2回目は書き込み0件', async () => {
  const api = new FakeGitHub();
  await run(api, [itemOf('CVE-1')]);
  const withdrawn = (aliases) => aliases.includes('CVE-1');
  await run(api, [], withdrawn);
  assert.ok(issue(api).labels.includes('advisory-withdrawn'));
  assert.ok(!issue(api).labels.includes('fixed-in-repo'));
  assert.equal(issue(api).state, 'open');
  assert.equal(api.comments.get(1).length, 1);
  assert.match(api.comments.get(1)[0].body, /取り下げ/);
  api.resetWrites();
  await run(api, [], withdrawn);
  assert.equal(api.writeCount, 0);
});

test('b. 一部の情報源だけが取り下げられ、項目が残っている: advisory-withdrawn は付かない', async () => {
  const api = new FakeGitHub();
  await run(api, [itemOf('CVE-1')]);
  await run(api, [itemOf('CVE-1')], () => false);
  assert.ok(!issue(api).labels.includes('advisory-withdrawn'));
  assert.equal((api.comments.get(1) ?? []).length, 0);
});

test('c. 取り下げではなく本当に解消した: 従来どおり fixed-in-repo（回帰）', async () => {
  const api = new FakeGitHub();
  await run(api, [itemOf('CVE-1')]);
  await run(api, [], () => false);
  assert.ok(issue(api).labels.includes('fixed-in-repo'));
  assert.ok(!issue(api).labels.includes('advisory-withdrawn'));
  assert.equal((api.comments.get(1) ?? []).length, 0, 'コメントしない（U1）');
});
