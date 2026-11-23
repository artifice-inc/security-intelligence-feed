import { cpSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { runMatch } from '../../src/match-central/run-match.mjs';
import { runCentral } from '../../src/publish/run-central.mjs';
import { SOURCE_NAMES } from '../../src/collect/index.mjs';
import { NEVER_FETCHED_AT } from '../../src/feed/definition.mjs';
import { slotOf } from '../../src/lib/schedule.mjs';
import { ROOT_DIR, loadSchedule } from '../../src/lib/config.mjs';
import { makeHarness } from './central-harness.mjs';
import { makeValidFeed, writeJson } from './feed-fixture.mjs';
import { git } from './feed-git.mjs';

export const NOW = '2026-11-21T22:47:00Z'; // 予定枠 2026-11-21T22:17Z。公開側の収集はその30分前
const MS_PER_MINUTE = 60_000;
const COLLECT_LEAD_MINUTES = 27;
const schedule = loadSchedule();
export const slotFor = (now) => slotOf(schedule, now);
export const collectedAt = (now) => new Date(new Date(now).getTime() - COLLECT_LEAD_MINUTES * MS_PER_MINUTE).toISOString().replace(/\.\d{3}Z$/, 'Z');

// 公開側のフィード（data/ のルート）を作る。failing: 失敗した情報源の名前、kevRecords・epssRows: 一覧の中身
export function makeFeedData({ now = NOW, failing = [], kevRecords = [], epssRows = [], epssThreshold = 0.5, health = {}, formatVersion = 1, kevOk = true, epssOk = true, optional = null, extraAdvisories = [], python = null, omitSources = [], neverLists = false, jpIds = null, alasRetry = null } = {}) {
  const dir = makeValidFeed();
  const at = collectedAt(now);
  const slot = slotFor(now);
  const entry = (ok) => ({ last_attempt_at: at, last_success_at: ok ? at : null, last_attempt_slot: slot, last_success_slot: ok ? slot : null, last_attempt_ok: ok, last_error: ok ? null : { kind: 'network', at } });
  writeJson(dir, 'health.json', {
    run_slot: slot, last_run: { started_at: at, finished_at: at, status: failing.length > 0 ? 'partial' : 'success' }, last_success_at: at,
    sources: Object.fromEntries(SOURCE_NAMES.filter((name) => !omitSources.includes(name)).map((name) => [name, entry(!failing.includes(name))])), packagist_updated_since: null,
    ...(optional ? { optional_sources: optional } : {}), ...health,
  });
  writeJson(dir, 'kev.json', { fetched_at: at, ok: kevOk, catalog_version: '1', records: kevRecords.map((cveID) => ({ cveID, vendorProject: 'Example', product: 'Example', dateAdded: '2026-11-20', knownRansomwareCampaignUse: 'Unknown' })) });
  writeJson(dir, 'epss-high.json', { fetched_at: at, ok: epssOk, model_version: 'v1', score_date: '2026-11-20', threshold: epssThreshold, records: epssRows.map(([cve, percentile]) => ({ cve, epss: 0.5, percentile })) });
  writeJson(dir, 'feed-format.json', { format_version: formatVersion });
  if (neverLists) { // build-public の初期フィード（未取得の空の一覧）
    writeJson(dir, 'kev.json', { fetched_at: NEVER_FETCHED_AT, ok: false, catalog_version: null, records: [] });
    writeJson(dir, 'epss-high.json', { fetched_at: NEVER_FETCHED_AT, ok: false, model_version: null, score_date: null, threshold: epssThreshold, records: [] });
  }
  for (const advisory of extraAdvisories) writeJson(dir, `advisories/${advisory.key}.json`, advisory);
  if (python) writeJson(dir, 'runtimes/python.json', python);
  if (alasRetry) writeJson(dir, 'os/amazon-linux-kernel.json', { updated_at: at, cursor: null, backfill_complete: false, last_success_date: null, retry: alasRetry, known_packages: [], cves: [] });
  if (jpIds) writeJson(dir, 'jp-alerts.json', { updated_at: at, items: jpIds.map((id) => ({ source: 'jpcert', id, title: `Alert ${id}`, link: `https://example.invalid/${id}`, date: '2026-11-20', cves: [], verification_status: 'text_extracted', first_seen_at: '2026-11-20T00:00:00Z' })) });
  return dir;
}

// feed ブランチを持つ bare の remote。publish で新しいコミットを積む
export function makeFeedRepo() {
  const remote = mkdtempSync(path.join(tmpdir(), 'feed-remote-'));
  git(remote, 'init', '-q', '--bare', '-b', 'feed');
  const work = mkdtempSync(path.join(tmpdir(), 'feed-work-'));
  git(work, 'init', '-q', '-b', 'feed');
  git(work, 'remote', 'add', 'origin', remote);
  const publish = (dataDir, { files = {} } = {}) => {
    rmSync(path.join(work, 'data'), { recursive: true, force: true });
    cpSync(dataDir, path.join(work, 'data'), { recursive: true });
    for (const [rel, content] of Object.entries(files)) { mkdirSync(path.dirname(path.join(work, rel)), { recursive: true }); writeFileSync(path.join(work, rel), content); }
    git(work, 'add', '-A');
    git(work, 'commit', '-q', '--allow-empty', '-m', 'feed');
    git(work, 'push', '-q', 'origin', 'feed');
    return git(work, 'rev-parse', 'HEAD').trim();
  };
  return { remote, url: `file://${remote}`, work, publish, git: (...args) => git(work, ...args) };
}

const SYNTHETIC_CENTRAL = { central_org: 'example-org', central_repo: 'example-private', contact_email: 'ops@example.invalid', user_agent: 'example-agent', bot_login: 'github-actions[bot]' };

// 非公開側のチェックアウト（config/ を持つ）・公開側の remote・案件のリポジトリ・フェイクの GitHub を組み立てる
export const PROJECT = 'sample-app';
export const sampleProjects = (extra = {}) => ({ project_owner: 'example-owner', projects: [{ project: PROJECT, repo: `example-owner/${PROJECT}`, monitor_ref: 'master', owners: ['alice'], exposure: 'internet', ...extra }] });

export function makeMatchHarness({ privateThresholds = {}, projects = sampleProjects(), ...options } = {}) {
  const base = makeHarness({ projects, ...options });
  const config = path.join(base.central.root, 'config');
  mkdirSync(config, { recursive: true });
  const thresholds = JSON.parse(readFileSync(path.join(ROOT_DIR, 'config', 'thresholds.json'), 'utf8'));
  writeJson(config, 'thresholds.json', { ...thresholds, ...privateThresholds });
  cpSync(path.join(ROOT_DIR, 'config', 'schedule.json'), path.join(config, 'schedule.json'));
  writeJson(config, 'central.json', SYNTHETIC_CENTRAL);
  base.central.git('add', '-A');
  base.central.git('commit', '-q', '-m', 'config');
  base.central.git('push', '-q');
  const feed = makeFeedRepo();
  const env = { ...base.env, SI_CODE_SHA: 'code-sha' };
  const harness = {
    ...base, feed, env,
    // now に合わせた新しいフィードを積む（false なら積まない）。戻り値はそのコミットの SHA
    publish: (feedOptions = {}) => feed.publish(makeFeedData({ now: NOW, ...feedOptions })),
    async match({ now = NOW, feedOptions = {}, feedUrl = feed.url, deps = {} } = {}) {
      if (feedOptions !== false) harness.lastSha = feed.publish(makeFeedData({ now, ...feedOptions }));
      return runMatch({ privateRoot: base.central.root, projectsConfig: base.projectsConfig, feedUrl, now, deps: { ...base.deps, clock: () => new Date(now), ...deps }, env });
    },
    runCentralAt: (now) => runCentral({ rootDir: base.central.root, projectsConfig: base.projectsConfig, now, deps: base.deps, env: base.env }),
    readOut: (rel) => JSON.parse(readFileSync(path.join(base.central.root, 'data', rel), 'utf8')),
    readText: (rel) => readFileSync(path.join(base.central.root, 'data', rel), 'utf8'),
    // ファイルが1つでもあれば true（同じ作業ツリーには空のディレクトリが残りうる）
    has: (rel) => { const target = path.join(base.central.root, 'data', rel); return existsSync(target) && (!statSync(target).isDirectory() || readdirSync(target, { recursive: true }).some((n) => statSync(path.join(target, n)).isFile())); },
    headSha: () => base.central.git('rev-parse', 'HEAD').trim(),
    commitData: (message = 'edit') => { base.central.git('add', '-A'); base.central.git('commit', '-q', '-m', message); base.central.git('push', '-q'); },
    healthIssues: () => [...base.api.issues.values()].filter((i) => i.labels.includes('health')),
  };
  return harness;
}
