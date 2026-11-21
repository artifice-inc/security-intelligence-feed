import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { makeMatchHarness, PROJECT } from './helpers/match-harness.mjs';
import { failing } from './helpers/central-harness.mjs';

const VULN = { id: 'GHSA-aaaa-bbbb-cccc', aliases: ['CVE-2026-1'], severity: 'HIGH' };
const LEGACY_AT = '2026-11-20T00:00:00Z';
const LATER = '2026-11-23T07:47:00Z';
const PUBLIC_ONLY = 'CVE-2015-6764';

const advisoryDir = (h) => path.join(h.central.root, 'data', 'advisories');
const readAdvisory = (h, key) => JSON.parse(readFileSync(path.join(advisoryDir(h), `${key}.json`), 'utf8'));
const writeAdvisory = (h, advisory) => writeFileSync(path.join(advisoryDir(h), `${advisory.key}.json`), `${JSON.stringify(advisory, null, 2)}\n`);

// 旧処理（runCentral）で作った今の data/ に、公開由来だけ・照合由来だけ・混在の記録を足して、切り替え前の状態にする
async function legacyHarness() {
  const h = makeMatchHarness();
  h.state.vulns = [VULN];
  await h.runCentralAt(LEGACY_AT);
  const matched = readdirSync(advisoryDir(h)).map((n) => readAdvisory(h, n.replace('.json', ''))).find((a) => a.sources.every((s) => s.name === 'osv'));
  assert.ok(matched, '旧処理が OSV 由来の記録を作る');
  const publicSource = JSON.parse(readFileSync(path.join(import.meta.dirname, 'fixtures', 'feed', 'advisories', `${PUBLIC_ONLY}.json`), 'utf8'));
  writeAdvisory(h, publicSource);
  writeAdvisory(h, { ...matched, key: 'GHSA-zzzz-zzzz-zzzz', aliases: { cve: [], ghsa: ['GHSA-zzzz-zzzz-zzzz'], other: [] }, sources: matched.sources.map((s) => ({ ...s, id: 'GHSA-zzzz-zzzz-zzzz' })) });
  writeAdvisory(h, { ...matched, sources: [...matched.sources, { ...publicSource.sources[0] }] }); // 混在（今回も検出される脆弱性）
  const findings = h.readOut(`findings/${PROJECT}.json`);
  findings.items[0].priority = 'P0'; // 旧処理の高い優先度。新しい経路は自動で下げない
  writeFileSync(path.join(h.central.root, 'data', 'findings', `${PROJECT}.json`), `${JSON.stringify(findings, null, 2)}\n`);
  h.commitData('legacy additions');
  return { h, mixedKey: matched.key };
}

test('M3 の最初の回: 照合由来の記録だけが残り、混在の記録は検出から作り直され、cutover_data_commit が bot のコミットに記録される', async () => {
  const { h, mixedKey } = await legacyHarness();
  const before = h.headSha();
  const out = await h.match();
  assert.equal(out.status, 'success', out.reasons.join('\n'));
  const keys = readdirSync(advisoryDir(h)).map((n) => n.replace('.json', ''));
  assert.ok(!keys.includes(PUBLIC_ONLY), '公開由来だけの記録は捨てる');
  assert.ok(keys.includes('GHSA-zzzz-zzzz-zzzz'), '照合由来だけの記録は残る');
  assert.ok(readAdvisory(h, mixedKey).sources.every((s) => ['osv', 'packagist'].includes(s.name)), '混在の記録はスキャナの出力から作り直される');
  for (const common of ['runtimes', 'os', 'jp-alerts.json', 'packagist-advisories.json', 'aws-bulletins.json']) assert.equal(h.has(common), false, common);
  assert.equal(h.readOut('feed-state.json').cutover_data_commit, before);
  assert.equal(h.central.git('log', '-1', '--format=%an').trim(), 'security-intelligence[bot]');
  const item = h.readOut(`findings/${PROJECT}.json`).items[0];
  assert.equal(item.priority, 'P0');
  assert.ok(item.priority_note.startsWith('計算上は'));
  assert.ok(h.readText('digest/latest.md').includes('### 自動で下げなかった優先度'));
  assert.deepEqual(h.vulnIssues().length, 1);

  await h.match();
  assert.equal(h.readOut('feed-state.json').cutover_data_commit, before, '2回目以降は変わらない');
});

test('切り戻し先の起動: M3 の形式の data/ から旧処理が起動し、項目を消さず、その後の run-match が再切り替えの最初の回になる', async () => {
  const { h } = await legacyHarness();
  await h.match();
  await h.match();
  h.state.collectors = { ...h.state.collectors, kev: failing() };
  const rolledBack = await h.runCentralAt('2026-11-22T09:00:00Z');
  assert.notEqual(rolledBack.status, 'failed', rolledBack.reasons.join('\n'));
  assert.equal(h.has('jp-alerts.json'), true, '旧処理は共通の生成物を書く');
  assert.ok(h.readOut(`findings/${PROJECT}.json`).items.length >= 1, 'partial の案件の項目は消えない');
  const before = h.headSha();
  h.state.collectors = { ...h.state.collectors, kev: async () => ({ ok: true, records: [] }) };
  const out = await h.match({ now: LATER });
  assert.equal(out.status, 'success', out.reasons.join('\n'));
  assert.equal(h.readOut('feed-state.json').cutover_data_commit, before, '再切り替えの最初の回で直前のコミットに更新される');
  assert.equal(h.has('jp-alerts.json'), false);
  assert.ok(!readdirSync(advisoryDir(h)).includes(`${PUBLIC_ONLY}.json`));
});
