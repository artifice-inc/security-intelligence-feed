import test from 'node:test';
import assert from 'node:assert/strict';
import { renderBody } from '../src/publish/issue-body.mjs';
import { renderDigest } from '../src/publish/digest.mjs';
import { buildHealth } from '../src/publish/health.mjs';
import { mergeFindings } from '../src/match/findings-merge.mjs';
import { makeSignals, detection, advisory, runTwoRounds, ctxOf, storedItem, priorityLabels, statusOf, assemble, SCHEDULE, NOW, T0 } from './helpers/priority-fixtures.mjs';

const loc = (lockfile, extra = {}) => ({ lockfile, package: 'pkg', ecosystem: 'npm', installed_version: '1.0.0', last_confirmed_at: T0, last_confirmed_provenance: {}, ...extra });
const cpython = (extra = {}) => ({ lockfile: '.security/stack.yml', package: 'cpython', ecosystem: 'runtime', installed_version: '3.11.0', ...extra });
const bodyOf = (item) => renderBody({ project: 'demo', item, owners: ['alice'], scannedAt: NOW });
const strip = (items) => items.map((i) => ({ ...i, issue_number: null }));
const BOTH = ['complete', 'partial'];

test('自動で下げない: 前回 P1 が計算上 P2 になる各場合で P1 を保ち、注記・Issue のラベル・digest の欄に出る', async () => {
  const previous = () => [storedItem('CVE-1', ['CVE-1'], { priority: 'P1' })];
  const cases = {
    'EPSS の上位から外れた': { signals: makeSignals() },
    'exposure を internal に変えた': { signals: makeSignals({ epssRows: [['CVE-1', 0.99]] }), exposure: 'internal' },
    'previous': { signals: makeSignals({ epss: 'previous' }) },
    'expired': { signals: makeSignals({ epss: 'expired' }) },
  };
  for (const scanStatus of BOTH) {
    for (const [name, options] of Object.entries(cases)) {
      const { findings, api } = await runTwoRounds({ previousItems: previous(), detections: [detection(['CVE-1'])], scanStatus, ctx: ctxOf(options.signals), ...options });
      const [item] = findings.items;
      assert.equal(item.priority, 'P1', `${scanStatus}/${name}`);
      assert.match(item.priority_note, /^計算上は P2。自動では下げない/);
      assert.deepEqual(priorityLabels(api), ['P1']);
      const digest = renderDigest({
        projects: [{ project: 'demo', repo: 'o/demo', monitor_ref: 'main' }], findingsByProject: new Map([['demo', { ...findings, items: findings.items }]]), snapshot: [],
        digestInfo: { fixedInRepo: [], riskAccepted: [], transitions: [], superseded: [] }, health: buildHealth({ previous: null, now: NOW, startedAt: NOW, status: 'success', sourceResults: {}, projectStates: {}, osvMeta: {}, packagistUpdatedSince: null }),
        schedule: SCHEDULE, now: NOW, centralRepo: 'org/central', kevRecords: [], jpItems: [], priorityNotes: true,
      });
      assert.match(digest, /### 自動で下げなかった優先度\n\n- `demo` `CVE-1` \*\*P1\*\* 計算上は P2/);
    }
  }
});

test('旧形式（priority_inputs なし）の P1 も下げない。計算が前回以上なら注記はなく、priorityNotes を渡さない digest は注記の欄を出さない', async () => {
  const kept = await runTwoRounds({ previousItems: [storedItem('CVE-1', ['CVE-1'], { priority: 'P1' })], detections: [detection(['CVE-1'])], signals: makeSignals() });
  assert.equal(kept.findings.items[0].priority, 'P1');
  const raised = await runTwoRounds({ previousItems: [storedItem('CVE-1', ['CVE-1'], { priority: 'P2' })], detections: [detection(['CVE-1'])], signals: makeSignals({ epssRows: [['CVE-1', 0.99]] }) });
  assert.equal(raised.findings.items[0].priority, 'P1');
  assert.equal(raised.findings.items[0].priority_note, undefined);
  const base = { projects: [{ project: 'demo', repo: 'o/demo', monitor_ref: 'main' }], findingsByProject: new Map([['demo', kept.findings]]), snapshot: [], digestInfo: { fixedInRepo: [], riskAccepted: [], transitions: [], superseded: [] }, health: buildHealth({ previous: null, now: NOW, startedAt: NOW, status: 'success', sourceResults: {}, projectStates: {}, osvMeta: {}, packagistUpdatedSince: null }), schedule: SCHEDULE, now: NOW, centralRepo: 'org/central', kevRecords: [], jpItems: [] };
  assert.doesNotMatch(renderDigest(base), /自動で下げなかった/);
  assert.match(renderDigest({ ...base, priorityNotes: true }), /自動で下げなかった/);
});

test('ランタイムのまとめ項目に入る項目の注記は、まとめのキーを併記して digest に載る', async () => {
  const runtimeItem = storedItem('CVE-R', ['CVE-R'], { priority: 'P1', locations: [loc('.security/stack.yml', { package: 'php', ecosystem: 'runtime', installed_version: '8.1.0' })] });
  const { findings } = await runTwoRounds({ previousItems: [runtimeItem], detections: [detection(['CVE-R'], { lockfile: '.security/stack.yml', package: 'php', ecosystem: 'runtime', installed_version: '8.1.0' })], signals: makeSignals() });
  const digest = renderDigest({
    projects: [{ project: 'demo', repo: 'o/demo', monitor_ref: 'main' }], findingsByProject: new Map([['demo', findings]]), snapshot: [], digestInfo: { fixedInRepo: [], riskAccepted: [], transitions: [], superseded: [] },
    health: buildHealth({ previous: null, now: NOW, startedAt: NOW, status: 'success', sourceResults: {}, projectStates: {}, osvMeta: {}, packagistUpdatedSince: null }), schedule: SCHEDULE, now: NOW, centralRepo: 'org/central', kevRecords: [], jpItems: [], priorityNotes: true,
  });
  assert.match(digest, /`CVE-R`（まとめ: `RUNTIME-php-8\.1\.0`） \*\*P1\*\* 計算上は P2/);
});

test('前回の P1 が CVE と GHSA を持ち、今回は別々の項目（CPython の needs_review と依存の affected）: complete・partial とも1項目・Issue 1件で、両方の箇所が本文に出る', async () => {
  for (const scanStatus of BOTH) {
    const previousItems = [storedItem('CVE-1', ['CVE-1', 'GHSA-a'], { priority: 'P1' })];
    const detections = [detection(['CVE-1'], cpython({ judgement: 'needs_review', fixed_versions: ['3.11.5'] })), detection(['GHSA-a'], { fixed_versions: ['2.0.0'] })];
    const { findings, api } = await runTwoRounds({ previousItems, detections, scanStatus, signals: makeSignals() });
    assert.equal(findings.items.length, 1, scanStatus);
    const [item] = findings.items;
    assert.equal(item.judgement, 'affected');
    assert.equal(item.priority, 'P1');
    assert.equal(api.issues.size, 1);
    const body = bodyOf(item);
    assert.match(body, /cpython/);
    assert.match(body, /pkg/);
    assert.match(body, /要確認/);
    assert.match(body, /3\.11\.5/);
    assert.match(body, /2\.0\.0/);
    assert.ok(item.locations.every((l) => l.judgement && Array.isArray(l.fixed_versions)));
  }
});

test('partial: 前回が混在の1項目で依存の箇所が今回 needs_review、CPython の箇所だけ未再検出なら hold は働かず needs_review（優先度は前回を下限に保つ）', async () => {
  const previousItems = [storedItem('CVE-1', ['CVE-1'], { priority: 'P1', locations: [loc('package-lock.json', { judgement: 'affected', fixed_versions: ['1.0.1'] }), loc('.security/stack.yml', { ...cpython(), judgement: 'needs_review', fixed_versions: [] })] })];
  const { findings } = await runTwoRounds({ previousItems, detections: [detection(['CVE-1'], { judgement: 'needs_review' })], scanStatus: 'partial', signals: makeSignals() });
  const [item] = findings.items;
  assert.equal(item.judgement, 'needs_review');
  assert.equal(item.priority_inputs.judgement, 'needs_review');
  assert.equal(item.priority, 'P1');
  assert.equal(item.locations.length, 2);
});

test('partial: 前回は別項目の CVE と GHSA が同じ箇所を持ち判定が違う。別の箇所の検出で両項目がつながる: 箇所は affected（修正版は和集合）で hold が働き、前回の順を入れ替えても同じ', async () => {
  const a = storedItem('CVE-A', ['CVE-A'], { priority: 'P2', locations: [loc('package-lock.json', { installed_version: '9.0.0' })], fixed_versions: ['1.0.0'] });
  const b = storedItem('GHSA-B', ['GHSA-B'], { priority: 'P2', judgement: 'needs_review', locations: [loc('package-lock.json', { installed_version: '9.0.0' })], fixed_versions: ['2.0.0'] });
  const detections = [detection(['CVE-A', 'GHSA-B'], { judgement: 'needs_review', lockfile: 'other-lock.json' })];
  const forward = (await runTwoRounds({ previousItems: [a, b], detections, scanStatus: 'partial', signals: makeSignals() })).findings.items;
  const reversed = (await runTwoRounds({ previousItems: [b, a], detections, scanStatus: 'partial', signals: makeSignals() })).findings.items;
  assert.equal(forward.length, 1);
  assert.equal(forward[0].judgement, 'affected');
  const held = forward[0].locations.find((l) => l.installed_version === '9.0.0');
  assert.deepEqual([held.judgement, held.fixed_versions], ['affected', ['1.0.0', '2.0.0']]);
  assert.deepEqual(strip(forward), strip(reversed));
  assert.equal(bodyOf(forward[0]), bodyOf(reversed[0]));
});

test('partial: 前回の A（affected。箇所は今回 needs_review で再検出）と B（needs_review。箇所は保持）が1つの成分: hold は働かず needs_review。A・B の順を入れ替えても同じ', async () => {
  const a = storedItem('CVE-A', ['CVE-A'], { priority: 'P1', locations: [loc('package-lock.json')] });
  const b = storedItem('GHSA-B', ['GHSA-B'], { priority: 'P2', judgement: 'needs_review', locations: [loc('b-lock.json')] });
  const detections = [detection(['CVE-A', 'GHSA-B'], { judgement: 'needs_review' })];
  const run = (items) => runTwoRounds({ previousItems: items, detections, scanStatus: 'partial', signals: makeSignals() });
  const forward = (await run([a, b])).findings.items;
  assert.equal(forward[0].judgement, 'needs_review');
  assert.equal(forward[0].priority, 'P1');
  assert.deepEqual(strip(forward), strip((await run([b, a])).findings.items));
});

test('partial: 前回 affected の依存の箇所を未確認のまま保持し、今回は CPython の needs_review だけを再検出: affected で、箇所ごとの判定と修正版が本文に残る', async () => {
  const previousItems = [storedItem('CVE-1', ['CVE-1'], { priority: 'P1', locations: [loc('package-lock.json')], fixed_versions: ['1.0.1'] })];
  const { findings } = await runTwoRounds({ previousItems, detections: [detection(['CVE-1'], cpython({ judgement: 'needs_review', fixed_versions: ['3.11.5'] }))], scanStatus: 'partial', signals: makeSignals() });
  const [item] = findings.items;
  assert.equal(item.judgement, 'affected');
  assert.equal(item.priority, 'P1');
  assert.match(bodyOf(item), /影響あり/);
  assert.match(bodyOf(item), /3\.11\.5/);
  assert.match(bodyOf(item), /1\.0\.1/);
});

test('OSV と Packagist の検出が同じ CVE を持ち、同じ箇所と別の箇所を含む: 同じ箇所は1行（affected 優先・修正版は和集合）。入力の順を変えても同じ', () => {
  const osv = detection(['CVE-1'], { lockfile: 'composer.lock', fixed_versions: ['1.1.0'], judgement: 'needs_review' });
  const packagist = detection(['CVE-1'], { lockfile: 'composer.lock', fixed_versions: ['1.2.0'] });
  const extra = detection(['CVE-1'], { lockfile: 'other.lock', fixed_versions: ['3.0.0'] });
  const signals = makeSignals();
  const forward = assemble([osv, packagist, extra], { signals });
  const reversed = assemble([extra, packagist, osv], { signals });
  assert.deepEqual(forward, reversed);
  const same = forward[0].locations.find((l) => l.lockfile === 'composer.lock');
  assert.equal(forward[0].locations.length, 2);
  assert.deepEqual([same.judgement, same.fixed_versions], ['affected', ['1.1.0', '1.2.0']]);
  assert.deepEqual(forward[0].locations.find((l) => l.lockfile === 'other.lock').fixed_versions, ['3.0.0']);
});

test('前回の別名でつながる今回の OSV と Packagist の検出が同じ箇所を指す: complete・partial とも箇所は1行（affected・修正版は和集合）。順を変えても同じ', async () => {
  for (const scanStatus of BOTH) {
    const previousItems = [storedItem('CVE-1', ['CVE-1', 'GHSA-a'], { priority: 'P2', locations: [loc('composer.lock')] })];
    const osv = detection(['CVE-1'], { lockfile: 'composer.lock', fixed_versions: ['1.1.0'], judgement: 'needs_review' });
    const packagist = detection(['GHSA-a'], { lockfile: 'composer.lock', fixed_versions: ['1.2.0'] });
    const one = await runTwoRounds({ previousItems, detections: [osv, packagist], scanStatus, signals: makeSignals() });
    const two = await runTwoRounds({ previousItems, detections: [packagist, osv], scanStatus, signals: makeSignals() });
    assert.equal(one.findings.items.length, 1);
    assert.equal(one.findings.items[0].locations.length, 1);
    assert.equal(one.findings.items[0].judgement, 'affected');
    assert.deepEqual(one.findings.items[0].fixed_versions, ['1.1.0', '1.2.0']);
    assert.deepEqual(strip(one.findings.items), strip(two.findings.items));
    assert.equal(bodyOf(one.findings.items[0]), bodyOf(two.findings.items[0]));
  }
});

test('前回の別名でつながる今回の2項目のうち、統合先に選ばれなかった項目の索引にだけ High がある: 前回 P2 から P1 に上がる', async () => {
  const advisories = [advisory('GHSA-z', { ghsa: ['GHSA-z'], severity: 'high' })];
  const previousItems = [storedItem('CVE-1', ['CVE-1', 'GHSA-z'], { priority: 'P2' })];
  const detections = [detection(['CVE-1']), detection(['GHSA-z'], { package: 'other' })];
  const without = await runTwoRounds({ previousItems, detections, signals: makeSignals() });
  assert.equal(without.findings.items[0].priority, 'P2', '深刻度がなければ P2 のまま');
  const raised = await runTwoRounds({ previousItems, detections: detections, advisories: [{ ...advisories[0], key: 'GHSA-z' }], signals: makeSignals() });
  assert.equal(raised.findings.items.length, 1);
  assert.equal(raised.findings.items[0].priority, 'P1');
  assert.deepEqual(priorityLabels(raised.api), ['P1']);
});

test('統合: 旧データの別々の項目 CVE（#20・P1）と GHSA（#10・P2）が今回1つ: 番号 #10、別名は和集合、P1 を保ち、#20 は reconcile で duplicate-candidate', async () => {
  for (const scanStatus of BOTH) {
    const cve = storedItem('CVE-1', ['CVE-1'], { priority: 'P1' });
    const ghsa = storedItem('GHSA-a', ['GHSA-a'], { priority: 'P2', locations: [loc('package-lock.json', { package: 'other' })] });
    const { findings, api, numbered } = await runTwoRounds({ previousItems: [cve, ghsa], detections: [detection(['CVE-1', 'GHSA-a'], { package: 'other' })], scanStatus, signals: makeSignals() });
    const numberOf = (key) => numbered.find((i) => i.advisory_key === key).issue_number;
    assert.equal(findings.items.length, 1);
    const [item] = findings.items;
    assert.equal(item.issue_number, Math.min(numberOf('CVE-1'), numberOf('GHSA-a')));
    assert.deepEqual(item.aliases, ['CVE-1', 'GHSA-a']);
    assert.equal(item.priority, 'P1');
    const labelsOf = (n) => api.issues.get(n).labels;
    const other = Math.max(numberOf('CVE-1'), numberOf('GHSA-a'));
    assert.ok(labelsOf(other).includes('duplicate-candidate'), `${scanStatus}: 番号の大きい Issue は duplicate-candidate`);
    assert.ok(labelsOf(item.issue_number).includes('P1'), '正の Issue のラベルは P1');
  }
});

test('項目が今回検出されなくなる（complete で消える）と、次に同じ脆弱性が検出されたときは下限がない', () => {
  const signals = makeSignals();
  const first = { ...statusOf('complete', T0), items: [storedItem('CVE-1', ['CVE-1'], { priority: 'P1' })] };
  const gone = mergeFindings({ previous: first, current: [], status: statusOf('complete'), signals, ctx: ctxOf(signals) });
  assert.equal(gone.items.length, 0);
  const again = mergeFindings({ previous: gone, current: assemble([detection(['CVE-1'])], { signals }), status: statusOf('complete'), signals, ctx: ctxOf(signals) });
  assert.equal(again.items[0].priority, 'P2');
});

test('signals を渡さない mergeFindings・assembleItems は優先度の記録（priority_inputs・priority_note）を足さない', () => {
  const current = assemble([detection(['CVE-1'])], { signals: null });
  assert.equal(current[0].priority_inputs, undefined);
  const merged = mergeFindings({ previous: null, current, status: statusOf('complete') });
  assert.equal(merged.items[0].priority_note, undefined);
});
