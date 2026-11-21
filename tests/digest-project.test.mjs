import test from 'node:test';
import assert from 'node:assert/strict';
import { renderDigest } from '../src/publish/digest.mjs';
import { reconcileIssues } from '../src/publish/issues-reconcile.mjs';
import { buildHealth } from '../src/publish/health.mjs';
import { loadSchedule } from '../src/lib/config.mjs';
import { FakeGitHub } from './helpers/fake-github.mjs';

const NOW = '2026-10-25T00:00:00Z';
const health = buildHealth({ previous: null, now: NOW, startedAt: NOW, status: 'success', sourceResults: {}, projectStates: {}, osvMeta: {}, packagistUpdatedSince: null });
const projectOf = (name) => ({ project: name, repo: `o/${name}`, monitor_ref: 'main', owners: ['x'], exposure: 'internet' });
const loc = (lockfile, extra = {}) => ({ lockfile, package: 'pkg', ecosystem: 'npm', installed_version: '1.0.0', last_confirmed_at: NOW, ...extra });
const item = (key, priority, locations, extra = {}) => ({ advisory_key: key, aliases: [key], title: key, priority, judgement: 'affected', locations, fixed_versions: [], source_urls: [], kev: false, issue_number: null, first_detected_at: '2026-10-01T00:00:00Z', ...extra });
const render = (o = {}) => renderDigest({
  projects: [projectOf('b-proj'), projectOf('a-proj')], findingsByProject: new Map(), snapshot: [], digestInfo: { fixedInRepo: [], riskAccepted: [], transitions: [], superseded: [] },
  health, schedule: loadSchedule(), now: NOW, centralRepo: 'org/central', kevRecords: [], jpItems: [], ...o,
});

test('案件別の状況は projects の登録順に並び、照合に失敗した案件も省略しない', () => {
  const text = render({ findingsByProject: new Map([['a-proj', { monitor_ref: 'main', scanned_at: NOW, scan_status: 'complete', inventory_status: 'fresh', items: [] }]]) });
  const b = text.indexOf('### b-proj');
  const a = text.indexOf('### a-proj');
  assert.ok(b > 0 && a > b, '登録順（b-proj → a-proj）');
  assert.match(text.slice(b, a), /未照合/);
  assert.match(text.slice(a), /### a-proj\n\n- 未解決なし/);
});

test('案件別: lockfile ごとの件数、対応が必要、ランタイムのまとめ1行、本番反映待ち（14日超）、移行済みが出る', () => {
  const runtime = (key, p) => item(key, p, [loc('.security/stack.yml', { package: 'php', ecosystem: 'runtime', installed_version: '8.1.21' })], { issue_number: 7 });
  const findings = new Map([['b-proj', { monitor_ref: 'main', scanned_at: NOW, scan_status: 'complete', inventory_status: 'fresh', items: [
    item('CVE-1', 'P1', [loc('sys/yarn.lock')]), item('CVE-2', 'P2', [loc('sys/yarn.lock')]), item('CVE-3', 'P3', [loc('sys/yarn.lock')], { judgement: 'needs_review' }),
    runtime('CVE-R1', 'P0'), runtime('CVE-R2', 'P1'),
  ] }]]);
  const snapshot = [
    { issue_number: 7, project: 'b-proj', aliases: ['RUNTIME-php-8.1.21'], state: 'open', labels: ['P0'], superseded_by: null },
    { issue_number: 3, project: 'b-proj', aliases: ['CVE-OLD'], state: 'open', labels: ['fixed-in-repo'], superseded_by: null },
    { issue_number: 2, project: 'b-proj', aliases: ['CVE-R1'], state: 'open', labels: ['superseded', 'P0'], superseded_by: 7 },
    { issue_number: 1, project: 'b-proj', aliases: ['CVE-R2'], state: 'open', labels: ['superseded', 'P1'], superseded_by: 99 },
  ];
  const digestInfo = { fixedInRepo: [{ issue_number: 3, project: 'b-proj', since: '2026-09-01T00:00:00Z' }], riskAccepted: [], transitions: [], superseded: [{ issue_number: 2, project: 'b-proj', superseded_by: 7 }, { issue_number: 1, project: 'b-proj', superseded_by: 99 }] };
  const text = render({ findingsByProject: findings, snapshot, digestInfo });
  const section = text.split('### b-proj')[1].split('### a-proj')[0];
  assert.match(section, /- sys\/yarn\.lock：P1 1 \/ P2 1 \/ P3 1/);
  assert.match(section, /\*\*P0\*\* php 8\.1\.21 の脆弱性 2件 \[#7\]/);
  assert.equal((section.match(/php 8\.1\.21 の脆弱性/g) ?? []).length, 1, 'まとめは1行');
  assert.match(section, /#### 要確認（P3）[\s\S]*CVE-3/);
  assert.match(section, /#### 本番反映待ち[\s\S]*#3\]\([^)]*\) `CVE-OLD`（14日超）/);
  assert.match(section, /\[#2\][^\n]* → まとめ先 \[#7\]\([^)]*\)\n/);
  assert.match(section, /\[#1\][^\n]* → まとめ先 \[#99\][^\n]*（見つかりません）/);
  // 件数の表: superseded は未解決に数えない（P0 は #7 の1件だけ、P1 は 0）
  assert.match(text, /\| b-proj \|.*\| 1 \/ 0 \/ 0 \| 1 \| 0 \|/);
});

test('一覧リンクはラベルで絞り込み、案件名に記号があってもクエリがエンコードされる', () => {
  const text = render({ projects: [{ ...projectOf('x'), project: 'a&b c(d)' }] });
  const row = text.split('\n').find((l) => l.includes('[未解決]'));
  const open = /\[未解決\]\((https:\/\/github\.com\/org\/central\/issues\?q=[^)\s]+)\)/.exec(row)[1];
  const waiting = /\[本番反映待ち\]\((https:\/\/github\.com\/org\/central\/issues\?q=[^)\s]+)\)/.exec(row)[1];
  const query = (url) => decodeURIComponent(new URL(url).searchParams.get('q') ?? url.split('q=')[1]);
  assert.equal(query(open), 'is:issue is:open label:security-finding label:"project:a&b c(d)" -label:fixed-in-repo -label:superseded');
  assert.equal(query(waiting), 'is:issue is:open label:"project:a&b c(d)" label:fixed-in-repo');
  assert.ok(!open.includes(' ') && !open.includes('&b') && !open.includes('(d'), 'そのままの記号は URL に残らない');
});

test('同じ入力で2回描画しても出力が一致し、生成日時を含まない', () => {
  const input = { findingsByProject: new Map([['a-proj', { monitor_ref: 'main', scanned_at: NOW, scan_status: 'complete', inventory_status: 'fresh', items: [item('CVE-1', 'P1', [loc('package-lock.json')], { issue_number: 4 })] }]]) };
  const first = render(input);
  assert.equal(render(input), first);
  assert.ok(!/生成日時/.test(first));
});

test('案件名は snapshot の件数に superseded を含めない（sb 由来の値で判定）', () => {
  const snapshot = [
    { issue_number: 1, project: 'a-proj', aliases: ['X'], state: 'open', labels: ['P1'], superseded_by: 5 },
    { issue_number: 2, project: 'a-proj', aliases: ['Y'], state: 'open', labels: ['P1'], superseded_by: null },
  ];
  assert.match(render({ snapshot }), /\| a-proj \|.*\| 0 \/ 1 \/ 0 \|/);
});

test('project:<案件名> ラベル: 作成時に付き、ラベルの無い既存 Issue は次の実行で付与される。2回目は書き込みなし', async () => {
  const api = new FakeGitHub();
  const findings = (items) => new Map([['demo', { project: 'demo', scan_status: 'complete', items }]]);
  const run = () => reconcileIssues({ api, projects: [{ project: 'demo', owners: ['alice'] }], findingsByProject: findings([item('CVE-1', 'P1', [loc('package-lock.json')])]), now: NOW });
  await run();
  assert.ok(api.labels.has('project:demo'));
  assert.ok(api.issues.get(1).labels.includes('project:demo'));
  api.issues.get(1).labels = api.issues.get(1).labels.filter((l) => l !== 'project:demo'); // T-E 以前に作られた Issue
  await run();
  assert.ok(api.issues.get(1).labels.includes('project:demo'));
  api.resetWrites();
  await run();
  assert.equal(api.writeCount, 0);
});
