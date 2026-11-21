import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdirSync, writeFileSync, readFileSync, cpSync, existsSync, symlinkSync, chmodSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import path from 'node:path';
import { assertValid } from '../src/lib/schema.mjs';
import { ROOT_DIR } from '../src/lib/config.mjs';
import { zipPathOf } from '../src/collect/osv-db.mjs';
import { VULN, NODE_FILES, tmp, writeJson, makePrivateRoot, setup } from './helpers/check-feed-setup.mjs';
import { makeFeedData, makeFeedRepo, NOW, collectedAt } from './helpers/match-harness.mjs';
import { git } from './helpers/feed-git.mjs';

const sh = (script, ...args) => execFileSync('sh', ['-c', script, 'sh', ...args], { encoding: 'utf8' });
const archiveTo = (gitDir, sha, dest, paths = []) => { sh('git --git-dir "$1" archive "$2" $4 | tar -x -C "$3"', gitDir, sha, dest, paths.join(' ')); return dest; };

// 今の作業ツリーのコードを commit した上流と、そこから作った bare（SKILL.md 手順1の1）。ネットワークには出ない
function makeCodeCache() {
  const upstream = tmp('si-code-up-');
  git(upstream, 'init', '-q', '-b', 'main');
  for (const entry of ['src', 'config', 'schemas']) cpSync(path.join(ROOT_DIR, entry), path.join(upstream, entry), { recursive: true });
  cpSync(path.join(ROOT_DIR, 'package.json'), path.join(upstream, 'package.json'));
  git(upstream, 'add', '-A');
  git(upstream, 'commit', '-q', '-m', 'code');
  const bare = tmp('si-code-bare-');
  git(bare, 'clone', '-q', '--bare', upstream, '.');
  return {
    bare, shaOf: () => git(bare, 'rev-parse', 'refs/heads/main').trim(),
    // 上流で新しいコミットを積み、SKILL.md と同じ ref 指定で bare の main を更新する
    advance: () => { writeFileSync(path.join(upstream, 'MARKER'), 'v2'); git(upstream, 'add', '-A'); git(upstream, 'commit', '-q', '-m', 'next'); git(bare, 'fetch', '-q', 'origin', '+refs/heads/main:refs/heads/main'); },
  };
}

// osv-scanner の代わり（--version と、空の結果だけ返す）
function makeScannerStub() {
  const file = path.join(tmp('si-scanner-'), 'osv-scanner');
  writeFileSync(file, '#!/bin/sh\nif [ "$1" = "--version" ]; then echo "osv-scanner version: 2.7.0"; else echo \'{"results":[]}\'; fi\n');
  chmodSync(file, 0o755);
  return file;
}

function runCli({ codeDir, codeSha, feedDir, feedSha, osvDir, scanner }) {
  const project = tmp('si-cli-project-');
  writeFileSync(path.join(project, 'package-lock.json'), '{}');
  const stdout = execFileSync('node', [path.join(codeDir, 'src/cli/security-check.mjs'), '--project-dir', project, '--feed-dir', feedDir, '--feed-sha', feedSha, '--code-sha', codeSha, '--osv-db-dir', osvDir, '--scanner', scanner, '--json'], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
  return JSON.parse(stdout);
}

test('配布先: bare から展開した先の CLI が起動し、スキーマに合う。main を更新した bare から再展開すると新しいコミットから起動する', () => {
  const code = makeCodeCache();
  const feedRemote = makeFeedRepo();
  const feedSha = feedRemote.publish(makeFeedData({ now: NOW }));
  const feedDir = archiveTo(feedRemote.remote, feedSha, tmp('si-feed-x-'), ['data']) + '/data';
  const osvDir = tmp('si-cli-osv-');
  mkdirSync(path.dirname(zipPathOf(osvDir, 'npm')), { recursive: true });
  writeFileSync(zipPathOf(osvDir, 'npm'), 'placeholder');
  writeJson(path.join(osvDir, 'meta.json'), { npm: { fetched_at: new Date().toISOString().replace(/\.\d{3}Z$/, 'Z'), sha256: 'a'.repeat(64) } });
  const scanner = makeScannerStub();
  const extract = () => { const dir = archiveTo(code.bare, code.shaOf(), tmp('si-code-x-')); symlinkSync(path.join(ROOT_DIR, 'node_modules'), path.join(dir, 'node_modules')); return dir; };

  const first = extract();
  const firstSha = code.shaOf();
  const output = runCli({ codeDir: first, codeSha: firstSha, feedDir, feedSha, osvDir, scanner });
  assertValid('security-check-output', output);
  assert.equal(output.central_diff, null);
  assert.equal(output.provenance.script_version, firstSha);
  assert.equal(output.provenance.feed_version, feedSha);
  assert.equal(existsSync(path.join(first, 'MARKER')), false);

  code.advance();
  assert.notEqual(code.shaOf(), firstSha);
  const second = extract();
  assert.equal(existsSync(path.join(second, 'MARKER')), true, '新しいコミットの内容が展開される');
  assert.equal(runCli({ codeDir: second, codeSha: code.shaOf(), feedDir, feedSha, osvDir, scanner }).provenance.script_version, code.shaOf());
});

test('フィードのキャッシュの作業ツリーを書き換えても、git archive したコミットの内容だけが照合に使われる', async () => {
  const remote = makeFeedRepo();
  const sha = remote.publish(makeFeedData({ now: NOW }));
  const cache = tmp('si-feed-cache-');
  git(cache, 'clone', '-q', '-b', 'feed', remote.remote, '.');
  const kevFile = path.join(cache, 'data/kev.json');
  const kev = JSON.parse(readFileSync(kevFile, 'utf8'));
  writeJson(kevFile, { ...kev, records: [{ ...(kev.records[0] ?? { vendorProject: 'Example', product: 'Example', dateAdded: '2026-11-20', knownRansomwareCampaignUse: 'Unknown' }), cveID: 'CVE-2026-1' }] });
  assert.notEqual(readFileSync(kevFile, 'utf8'), git(cache, 'show', `${sha}:data/kev.json`).trim(), '作業ツリーだけが書き換わっている');
  const extracted = archiveTo(path.join(cache, '.git'), sha, tmp('si-feed-x-'), ['data']);
  const s = setup();
  const output = await s.run({ feedDir: path.join(extracted, 'data'), feedSha: sha });
  assert.equal(output.results[0].priority, 'P1', '作業ツリーの KEV は反映されない');
  assert.equal(output.provenance.feed_version, sha);
});

test('展開先を消した次の実行で DB の取得に失敗しても、--osv-db-dir の期限内の DB で照合できる', async () => {
  const s = setup();
  writeJson(path.join(s.osvDir, 'meta.json'), { npm: { fetched_at: '2026-11-20T00:00:00Z', sha256: 'a'.repeat(64) } }); // 12時間を過ぎている
  s.deps.fetchOsvDb = async ({ ecosystems, dest }) => {
    writeFileSync(zipPathOf(dest, 'npm'), 'placeholder');
    const meta = { npm: { fetched_at: NOW, sha256: 'b'.repeat(64) } };
    writeJson(path.join(dest, 'meta.json'), meta);
    return { meta, outcomes: Object.fromEntries(ecosystems.map((e) => [e, { ok: true }])) };
  };
  assert.equal((await s.run()).osv_db.npm.state, 'fresh');
  s.deps.now = new Date(new Date(NOW).getTime() + 13 * 3_600_000);
  s.deps.fetchOsvDb = async ({ ecosystems }) => ({ meta: JSON.parse(readFileSync(path.join(s.osvDir, 'meta.json'), 'utf8')), outcomes: Object.fromEntries(ecosystems.map((e) => [e, { ok: false, error: { message: 'offline' } }])) });
  const second = await s.run({ cacheRoot: tmp('si-cache-new-') });
  assert.equal(second.osv_db.npm.state, 'stale_warn');
  assert.equal(second.dependency_checks.osv, 'ok');
  assert.equal(second.results.length, 1);
});

test('スタッフ: 同じ入力で、旧の経路（cacheRoot/data）と新の経路（フィード＋--private-root）の検出・該当箇所・exposure・lockfiles が一致する', async () => {
  const projects = 'projects:\n  - project: demo\n    exposure: internet\n    lockfiles: [package-lock.json]\n';
  const files = { ...NODE_FILES, 'sub/package-lock.json': '{}' };
  const s = setup({ files });
  const privateRoot = makePrivateRoot({ projects });
  const newer = await s.run({ privateRoot, exposure: null });
  const cacheRoot = tmp('si-old-cache-');
  cpSync(s.feedDir, path.join(cacheRoot, 'data'), { recursive: true });
  cpSync(s.osvDir, path.join(cacheRoot, 'osv-db'), { recursive: true });
  mkdirSync(path.join(cacheRoot, 'config'));
  writeFileSync(path.join(cacheRoot, 'config/projects.yaml'), projects);
  const older = await s.run({ cacheRoot, exposure: null, feedDir: null, osvDbDir: null });
  assert.deepEqual(newer.stack.lockfiles, ['package-lock.json']);
  assert.deepEqual(newer.stack.lockfiles, older.stack.lockfiles);
  const shape = (o) => o.results.map((r) => [r.advisory_key, r.priority, r.judgement, JSON.stringify(r.locations)]);
  assert.equal(newer.results.length, 1);
  assert.deepEqual(shape(newer), shape(older));
  assert.equal(newer.results[0].priority, 'P1', 'exposure: internet が適用される');
});

test('python_release_grace_days: スタッフは非公開側の値（14日で猶予中）、配布先は公開側の値（7日で猶予外）に従う', async () => {
  const python = { runtime: 'python', updated_at: NOW, psf_synced_at: '2026-11-21T00:00:00Z', pending: [], advisories: [], branches: [{ branch: '3.12', state: 'maintained', security_support_end: '2028-10-31', is_eol: false, latest_version: '3.12.7', versions: [{ version: '3.12.7', date: '2026-11-11' }] }] };
  const files = { ...NODE_FILES, '.python-version': '3.12.7' };
  const graceError = (o) => o.scan_errors.some((e) => e.target === 'python-psf' && e.message.includes('日以内'));
  const staff = await setup({ files, feedOptions: { python } }).run({ privateRoot: makePrivateRoot({ thresholds: { python_release_grace_days: 14 } }) });
  assert.ok(staff.scan_errors.some((e) => e.target === 'python-psf' && e.message.includes('14 日以内')), JSON.stringify(staff.scan_errors));
  assert.equal(staff.local_scan.complete, false);
  assert.equal((await setup({ files, feedOptions: { python } }).run()).scan_errors.some(graceError), false);
});

test('OSV だけを使うスタッフの案件で、フィードが検証で拒否される: complete: false・resolved_locally: null', async () => {
  const privateRoot = makePrivateRoot();
  writeJson(path.join(privateRoot, 'data/issues.json'), [{ issue_number: 1, project: 'demo', aliases: ['CVE-OLD-1'], state: 'open', labels: ['security-finding', 'P1'] }]);
  const s = setup({ files: { 'package-lock.json': '{}' }, vulns: [] });
  const healthy = await s.run({ privateRoot });
  assert.equal(healthy.feed_signals.mode, 'latest');
  writeFileSync(path.join(s.feedDir, 'kev.json'), '{broken');
  const output = await s.run({ privateRoot });
  assert.equal(output.feed_signals.mode, 'degraded');
  assert.equal(output.local_scan.complete, false);
  assert.equal(output.central_issues.resolved_locally, null);
});
