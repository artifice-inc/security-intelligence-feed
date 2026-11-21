import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync, existsSync } from 'node:fs';
import path from 'node:path';
import { makeHarness, T0, T1 } from './helpers/central-harness.mjs';
import { collect as realCollect, FEED_URL } from '../src/collect/aws-bulletins.mjs';
import { writeJsonAtomic } from '../src/publish/central-data.mjs';
import { staleSources, HEALTH_TITLE } from '../src/publish/health.mjs';
import { fakeHttp } from './helpers/fake-http.mjs';

const AWS_FILE = 'aws-bulletins.json';
const bulletin = (id, title = 'T', rss_pub_date = '2026-10-24T00:00:00Z') => ({ id, title, rss_pub_date, cves: [] });
const OK_COLLECTOR = async () => ({ ok: true, records: [bulletin('2026-001-aws')] });
const failure = (kind) => async () => ({ ok: false, records: [], error: { kind, message: `${kind} の失敗`, http_status: null } });
const feedCollector = (xml) => (args) => realCollect({ ...args, http: fakeHttp({ [FEED_URL]: xml }) });
const rss = (channel) => `<?xml version="1.0"?><rss version="2.0">${channel}</rss>`;
const CHANNEL_HEAD = '<title>t</title><link>l</link><description>d</description>';

// S7 の失敗ケース（ハーネスの設定を返る関数）
const FAILURE_CASES = {
  timeout: (h) => { h.state.optionalCollectors = { 'aws-bulletins': failure('timeout') }; },
  http: (h) => { h.state.optionalCollectors = { 'aws-bulletins': failure('http_status') }; },
  '壊れた XML': (h) => { h.state.optionalCollectors = { 'aws-bulletins': feedCollector('<rss><channel>') }; },
  '必須項目の欠けた XML': (h) => { h.state.optionalCollectors = { 'aws-bulletins': feedCollector(rss('<channel><title>t</title></channel>')) }; },
  'スキーマ違反': (h) => { h.state.optionalCollectors = { 'aws-bulletins': OK_COLLECTOR }; h.state.optionalOverrides = { normalize: () => ({ updated_at: 'x', items: [{ id: 'bad' }] }) }; },
  'collect が例外': (h) => { h.state.optionalCollectors = { 'aws-bulletins': async () => { throw new Error('想定外'); } }; },
};

// 既存案件の結果が S7 なしの場合と同じになることを確かめる比較項目（outcome.committed は比べない）
async function observe(configure) {
  const h = makeHarness();
  h.state.vulns = [{ id: 'GHSA-aaaa-bbbb-cccc', aliases: ['CVE-2026-1111'] }];
  configure(h);
  const outcome = await h.run(T0);
  return {
    h, outcome,
    core: { status: outcome.status, reasons: outcome.reasons, heartbeats: h.state.heartbeats, findings: JSON.parse(JSON.stringify(h.read('findings/demo.json')).replace(/"inventory_commit":"[0-9a-f]+"/g, '"inventory_commit":"-"')), // 案件のリポジトリはハーネスごとに別なのでコミット ID は除く
    issues: h.api.writes.filter((w) => w.op !== 'createLabel').length, vuln: h.vulnIssues().map((i) => i.title) },
  };
}

test('S7 の失敗（6種）は既存案件の結果に影響せず、前回のファイルを残して health に記録される', async () => {
  const baseline = await observe((h) => { h.state.optionalCollectors = {}; });
  for (const [name, configure] of Object.entries(FAILURE_CASES)) {
    const { h, outcome, core } = await observe(configure);
    assert.deepEqual(core, baseline.core, name);
    assert.equal(outcome.status, 'success', name);
    assert.equal(h.exists(AWS_FILE), false, `${name}: 前回がなければ作らない`);
    const health = h.read('health.json');
    assert.ok(health.optional_sources['aws-bulletins'].last_error, name);
    assert.equal(health.sources['aws-bulletins'], undefined, name);
    assert.deepEqual(staleSources(health, T0), staleSources(baseline.h.read('health.json'), T0), name);
  }
});

test('S7 が締め切りまでに終わらない: 照合は待たず、signal が中断され、unfinished が記録され、success で終わる', async () => {
  const h = makeHarness();
  let aborted = false;
  let matchStartedWhilePending = false;
  let pending = true;
  h.state.optionalCollectors = { 'aws-bulletins': ({ signal }) => new Promise((resolve) => signal.addEventListener('abort', () => { aborted = true; pending = false; resolve({ ok: true, records: [] }); })) };
  const resolveInventory = h.deps.resolveInventory;
  h.deps.resolveInventory = (args) => { matchStartedWhilePending ||= pending; return resolveInventory(args); };
  const outcome = await h.run(T0);
  assert.equal(matchStartedWhilePending, true);
  assert.equal(aborted, true);
  assert.equal(h.read('health.json').optional_sources['aws-bulletins'].last_error.kind, 'unfinished');
  assert.equal(outcome.status, 'success');
  assert.equal(h.state.heartbeats, 1);
  assert.equal(h.exists(AWS_FILE), false, '遅れて完了した結果は使わない');
});

test('S7 の正規化が例外なら normalize を記録し、前回のファイルを残して success で終わる', async () => {
  const h = makeHarness();
  h.state.optionalCollectors = { 'aws-bulletins': OK_COLLECTOR };
  await h.run(T0);
  const before = h.read(AWS_FILE);
  h.state.optionalOverrides = { normalize: () => { throw new Error('正規化の失敗'); } };
  const outcome = await h.run(T1);
  assert.equal(outcome.status, 'success');
  assert.equal(h.read('health.json').optional_sources['aws-bulletins'].last_error.kind, 'normalize');
  assert.deepEqual(h.read(AWS_FILE), before);
  h.state.optionalOverrides = { validate: () => { throw new Error('未定義のスキーマ'); } };
  assert.equal((await h.run('2026-10-25T18:00:00Z')).status, 'success');
  assert.deepEqual(h.read(AWS_FILE), before);
});

test('S7 の書き込みが置き換えで失敗したら write を記録し、前回のコピーと最終検証が無傷で success になる', async () => {
  const h = makeHarness();
  h.state.optionalCollectors = { 'aws-bulletins': OK_COLLECTOR };
  await h.run(T0);
  const before = h.read(AWS_FILE);
  h.state.optionalCollectors = { 'aws-bulletins': async () => ({ ok: true, records: [bulletin('2026-001-aws', '変更後'), bulletin('2026-002-aws')] }) };
  h.state.optionalOverrides = { writeJsonAtomic: (dir, rel, value) => writeJsonAtomic(dir, rel, value, { rename: () => { throw new Error('置き換えの失敗'); } }) };
  const outcome = await h.run(T1);
  assert.equal(outcome.status, 'success');
  assert.equal(h.state.heartbeats, 2);
  assert.equal(h.read('health.json').optional_sources['aws-bulletins'].last_error.kind, 'write');
  assert.deepEqual(h.read(AWS_FILE), before);
  const outDir = path.join(h.central.root, '.work', 'out');
  assert.deepEqual(readdirSync(outDir).filter((n) => n.includes('.tmp-')), []);
});

test('writeJsonAtomic: 通常は置き換わり、一時ファイルは残らない', () => {
  const h = makeHarness();
  const outDir = path.join(h.central.root, '.work', 'tmpcheck', 'data');
  writeJsonAtomic(outDir, AWS_FILE, { a: 1 });
  assert.deepEqual(JSON.parse(readFileSync(path.join(outDir, AWS_FILE), 'utf8')), { a: 1 });
  assert.deepEqual(readdirSync(path.dirname(outDir)).filter((n) => n.includes('.tmp-')), []);
});

test('同じ RSS で2回巡回しても aws-bulletins.json に差分が出ず、optional_sources は first_attempt_at を保つ', async () => {
  const h = makeHarness();
  await h.run(T0);
  const first = readFileSync(path.join(h.central.root, 'data', AWS_FILE), 'utf8');
  await h.run(T1);
  assert.equal(readFileSync(path.join(h.central.root, 'data', AWS_FILE), 'utf8'), first);
  const source = h.read('health.json').optional_sources['aws-bulletins'];
  assert.equal(source.first_attempt_at, T0);
  assert.equal(source.last_success_at, T1);
});

test('試行しなかった回は optional_sources の前回の値を残す', async () => {
  const h = makeHarness();
  await h.run(T0);
  h.state.optionalCollectors = {};
  await h.run(T1);
  assert.equal(h.read('health.json').optional_sources['aws-bulletins'].last_attempt_at, T0);
});

const healthIssues = (h) => [...h.api.issues.values()].filter((i) => i.title === HEALTH_TITLE && i.state === 'open');
const DAY_MS = 86_400_000;
const at = (days) => new Date(new Date(T0).getTime() + days * DAY_MS).toISOString().replace(/\.\d{3}Z$/, 'Z');

test('7日ルール: 成功の実績がなければ初回の試行から7日を超えるまで health Issue を作らない。本文は安定し、成功で閉じる', async () => {
  const h = makeHarness();
  h.state.optionalCollectors = { 'aws-bulletins': failure('network') };
  await h.run(T0);
  await h.run(at(6.9));
  assert.equal(healthIssues(h).length, 0);
  const created = await h.run(at(7.5));
  assert.equal(created.healthIssue.action, 'created');
  assert.match(healthIssues(h)[0].body, /情報源 aws-bulletins は 7日以上取得できていません（成功の記録なし、初回の試行: 2026-10-25T00:00:00Z）/);
  assert.equal(created.status, 'success');
  assert.equal((await h.run(at(8))).healthIssue.action, 'unchanged');
  assert.match(readFileSync(path.join(h.central.root, 'data', 'digest', 'latest.md'), 'utf8'), /aws-bulletins（任意） \|.*\*\*7日以上取得できていません\*\*/);
  h.state.optionalCollectors = { 'aws-bulletins': OK_COLLECTOR };
  assert.equal((await h.run(at(8.5))).healthIssue.action, 'closed');
});

test('7日ルール: 成功の実績があれば最終成功から7日以内は、失敗が続いても health Issue を作らない', async () => {
  const h = makeHarness();
  await h.run(T0);
  h.state.optionalCollectors = { 'aws-bulletins': failure('network') };
  await h.run(at(6.5));
  assert.equal(healthIssues(h).length, 0);
  const over = await h.run(at(7.5));
  assert.equal(over.healthIssue.action, 'created');
  assert.match(healthIssues(h)[0].body, /最終成功: 2026-10-25T00:00:00Z/);
});

test('digest: 新着・更新・なし が出て、title は無害化される。公開日とは書かない', async () => {
  const h = makeHarness();
  const md = () => readFileSync(path.join(h.central.root, 'data', 'digest', 'latest.md'), 'utf8');
  const longTail = 'x'.repeat(100); // cell() の80文字で切れていた長さ
  h.state.optionalCollectors = { 'aws-bulletins': async () => ({ ok: true, records: [{ id: '2026-001-aws', title: `CVE-2026-0001 - A|B <b>x</b> [l](https://evil.example) ${longTail}`, rss_pub_date: '2026-10-24T00:00:00Z', cves: ['CVE-2026-0001'] }] }) };
  await h.run(T0);
  assert.match(md(), /### AWS の公開注意喚起（Security Bulletins）\n\n- \[2026-001-aws\]\(https:\/\/aws\.amazon\.com\/security\/security-bulletins\/2026-001-aws\/\) CVE-2026-0001 - .* 掲載日時（RSS）: 2026-10-24 09:00:00 JST/);
  assert.ok(md().includes(`${longTail} 掲載日時（RSS）`), '長いタイトルも80文字で切らない');
  assert.ok(!md().includes('（CVE:'), 'タイトルにある CVE を重ねて書かない');
  assert.ok(!md().includes('<b>') && md().includes('\\[l\\]'), 'HTML と Markdown のリンクは無害化される');
  assert.ok(!md().includes('公開日'));
  h.state.optionalCollectors = { 'aws-bulletins': async () => ({ ok: true, records: [{ id: '2026-001-aws', title: '改題', rss_pub_date: '2026-10-24T00:00:00Z', cves: [] }] }) };
  await h.run(at(30)); // 新着の期間を過ぎてから title が変わった
  assert.match(md(), /- （更新）\[2026-001-aws\]/);
  await h.run(at(60));
  assert.match(md(), /### AWS の公開注意喚起（Security Bulletins）\n\n- なし/);
  assert.ok(existsSync(path.join(h.central.root, 'data', AWS_FILE)));
});

// 作業領域の data/ 全体を {相対パス: 内容} にする。案件リポジトリはハーネスごとに別なのでコミット ID は揃える
function snapshotData(h) {
  const root = path.join(h.central.root, 'data');
  const files = {};
  const walk = (dir) => readdirSync(dir, { withFileTypes: true }).forEach((entry) => {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) { walk(full); return; }
    files[path.relative(root, full)] = readFileSync(full, 'utf8').replace(/"(inventory_commit|source_commit)":\s*"[0-9a-f]+"/g, '"$1": "-"');
  });
  walk(root);
  return files;
}

// S7 に由来する部分（aws-bulletins.json・optional_sources・digest の S7 の節と §6 の「（任意）」の行）を取り除く
function withoutS7(files) {
  const rest = { ...files };
  delete rest[AWS_FILE];
  const health = JSON.parse(rest['health.json']);
  delete health.optional_sources;
  rest['health.json'] = JSON.stringify(health);
  rest['digest/latest.md'] = rest['digest/latest.md']
    .replace(/### AWS の公開注意喚起（Security Bulletins）\n\n[\s\S]*?(?=\n## 6\.)/, '')
    .split('\n').filter((l) => !l.includes('（任意）')).join('\n');
  return rest;
}

test('公開データの差分は S7 由来の部分に限られる（S7 なし・成功・失敗の比較）', async () => {
  const bare = makeHarness();
  bare.state.optionalCollectors = {};
  await bare.run(T0);
  const baseline = snapshotData(bare);
  assert.equal(AWS_FILE in baseline, false);
  assert.equal('optional_sources' in JSON.parse(baseline['health.json']), false);

  const variants = { 成功: OK_COLLECTOR, 失敗: failure('network') };
  for (const [name, collector] of Object.entries(variants)) {
    const h = makeHarness();
    h.state.optionalCollectors = { 'aws-bulletins': collector };
    await h.run(T0);
    const files = snapshotData(h);
    assert.deepEqual(withoutS7(files), withoutS7(baseline), `${name}: S7 由来以外のファイルが変わった`);
    assert.deepEqual(Object.keys(files).filter((f) => !(f in baseline)), name === '成功' ? [AWS_FILE] : [], name);
  }
});

test('前回の aws-bulletins.json がある状態で S7 が失敗しても、前回の内容のまま残る（6種）', async () => {
  for (const [name, configure] of Object.entries(FAILURE_CASES)) {
    const h = makeHarness();
    h.state.optionalCollectors = { 'aws-bulletins': OK_COLLECTOR };
    await h.run(T0);
    const previous = readFileSync(path.join(h.central.root, 'data', AWS_FILE), 'utf8');
    configure(h);
    const outcome = await h.run(T1);
    assert.equal(outcome.status, 'success', name);
    assert.equal(readFileSync(path.join(h.central.root, 'data', AWS_FILE), 'utf8'), previous, name);
    assert.ok(h.read('health.json').optional_sources['aws-bulletins'].last_error, name);
  }
});
