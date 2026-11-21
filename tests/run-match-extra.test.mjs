import test from 'node:test';
import assert from 'node:assert/strict';
import { makeMatchHarness, PROJECT, NOW } from './helpers/match-harness.mjs';

const VULN = { id: 'GHSA-aaaa-bbbb-cccc', aliases: ['CVE-2026-1'], severity: 'HIGH' };
const MODERATE = { ...VULN, severity: 'MODERATE' };
const OLD = '2026-11-01T00:00:00Z';
const findings = (h) => h.readOut(`findings/${PROJECT}.json`);

test('フィードの ALAS の retry・Python の pending が長期に残る: 収集が成功扱いでも health Issue に警告が残り、閉じられない', async () => {
  const h = makeMatchHarness();
  const python = { runtime: 'python', updated_at: NOW, psf_synced_at: OLD, pending: [{ id: 'PSF-1', reason: 'osv_missing', since: OLD }], advisories: [], branches: [] };
  const feedOptions = { alasRetry: [{ cve: 'CVE-2026-9', since: '2026-11-01' }], python };
  const first = await h.match({ feedOptions });
  assert.equal(h.readOut('health.json').last_run.status, first.status);
  const issue = h.healthIssues()[0];
  assert.ok(issue.body.includes('ALAS') && issue.body.includes('CPython'));
  await h.match({ feedOptions });
  assert.equal(h.healthIssues()[0].state, 'open');
  assert.ok(h.healthIssues()[0].body.includes('ALAS'));
  await h.match({});
  assert.equal(h.healthIssues()[0].state, 'closed', '解消すれば閉じる');
});

test('reconcile の後: findings の issue_number と issues.json が反映され、digest の健全性欄がその回の health.json と一致する', async () => {
  const h = makeMatchHarness();
  h.state.vulns = [VULN];
  await h.match({ feedOptions: { failing: ['jpcert'] } });
  const number = h.vulnIssues()[0].number;
  assert.equal(findings(h).items[0].issue_number, number);
  assert.ok(h.readOut('issues.json').some((i) => i.issue_number === number));
  const health = h.readOut('health.json');
  const rows = Object.fromEntries(h.readText('digest/latest.md').split('\n').filter((l) => /^\| [a-z-]+ \|/.test(l)).map((l) => { const c = l.split('|').map((x) => x.trim()); return [c[1], c]; }));
  for (const [name, source] of Object.entries(health.sources)) {
    assert.ok(rows[name], name);
    assert.equal(rows[name][3].includes('失敗'), Boolean(source.last_error), name);
  }
  assert.ok(health.sources.jpcert.last_error);
});

test('bot_login が公開側と違う設定: 非公開側の bot のコメントで送信済みを判定し、通知が重複しない。優先度は非公開側の閾値', async () => {
  const h = makeMatchHarness();
  h.api.botLogin = 'private-bot';
  h.state.vulns = [MODERATE];
  const feedOptions = { epssThreshold: 0.9, epssRows: [['CVE-2026-1', 0.92]] };
  await h.match({ feedOptions });
  assert.equal(findings(h).items[0].priority, 'P2', '非公開側の閾値 0.95 では 0.92 は上位でない');
  const number = h.vulnIssues()[0].number;
  h.api.humanLabel(number, 'fixed-in-repo', NOW);
  // 再発の通知: 本文のマーカー更新（2回目の PATCH）だけを失敗させ、pending を残す
  h.api.failNext('updateIssue', ([, patch]) => !patch.labels && patch.body, 1);
  await h.match({ feedOptions });
  const recurrences = () => (h.api.comments.get(number) ?? []).filter((c) => c.body.includes('再発') && c.author === 'private-bot');
  assert.equal(recurrences().length, 1);
  await h.match({ feedOptions });
  await h.match({ feedOptions });
  assert.equal(recurrences().length, 1, 'pending が残っていても、bot のコメントで送信済みと判定し重複しない');
});

test('縮退照合: Python の疑似検出が出ず、Python は feed エラーになる', async () => {
  const h = makeMatchHarness({ projectFiles: { 'package-lock.json': '{}', '.nvmrc': '22.11.0', '.python-version': '3.12.7' } });
  h.state.vulns = [VULN];
  const out = await h.match({ feedOptions: false, feedUrl: 'file:///nonexistent-feed-remote' });
  assert.equal(out.feedMode, 'degraded');
  const f = findings(h);
  assert.ok(f.scan_errors.some((e) => e.kind === 'feed' && e.target === 'runtime:python'));
  assert.ok(f.items.every((i) => i.locations.every((l) => l.ecosystem !== 'runtime')), 'ランタイムの疑似検出がない');
  assert.equal(f.items.length, 1);
});
