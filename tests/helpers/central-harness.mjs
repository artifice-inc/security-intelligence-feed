import { mkdirSync, writeFileSync, readFileSync, existsSync } from 'node:fs';
import path from 'node:path';
import { runCentral } from '../../src/publish/run-central.mjs';
import { resolveInventory } from '../../src/inventory/resolve.mjs';
import { guardCommit } from '../../src/publish/guard-commit.mjs';
import { zipPathOf } from '../../src/collect/osv-db.mjs';
import { FakeGitHub } from './fake-github.mjs';
import { makeCentralRepo, makeRepo } from './tree.mjs';

export const T0 = '2026-10-25T00:00:00Z';
export const T1 = '2026-10-25T09:00:00Z';

const okRecords = (records = []) => async () => ({ ok: true, records });
// 任意の情報源（S7）の既定: 合成の2件を返す
const syntheticBulletins = async () => ({ ok: true, records: [
  { id: '2026-002-aws', title: 'Synthetic bulletin (CVE-2026-0002)', rss_pub_date: '2026-10-24T00:00:00Z', cves: ['CVE-2026-0002'] },
  { id: '2026-001-aws', title: 'Synthetic bulletin 1', rss_pub_date: '2026-10-23T00:00:00Z', cves: [] },
] });
export const failing = (kind = 'network') => async () => ({ ok: false, records: [], error: { kind, message: `${kind} error`, http_status: null } });

// 既定の収集結果（すべて成功・脆弱性情報なし）。テストごとに上書きする
export const defaultCollectors = () => ({
  kev: okRecords(), epss: okRecords(), 'node-core': okRecords(), 'node-dist': okRecords([{ version: 'v22.11.0', date: null, lts: 'Jod', security: false }]),
  'php-ghsa': okRecords(), 'php-releases': okRecords([{ type: 'branch', branch: '8.3', state: 'stable', security_support_end: '2027-12-31', active_support_end: null }]),
  endoflife: okRecords([
    { product: 'php', name: '8.3', isEol: false, eolFrom: '2027-12-31', isLts: false, latest: '8.3.14' },
    { product: 'nodejs', name: '22', isEol: false, eolFrom: '2027-04-30', isLts: true, latest: '22.23.4' },
    { product: 'nodejs', name: '18', isEol: true, eolFrom: '2025-04-30', isLts: false, latest: '18.20.8' },
  ]),
  alas: async () => ({ ok: true, records: [], meta: { cursor: null, backfill_complete: false, last_success_date: '2026-10-25', retry: [], index_total: 0 } }),
  'python-psf': async () => ({ ok: true, records: [], missing: [] }), 'python-releases': okRecords([{ version: '3.12.7', date: '2024-10-01' }]), 'endoflife-python': okRecords(),
  packagist: okRecords(), jpcert: okRecords(), ipa: okRecords(), jvn: okRecords(),
});

// スキャナのスタブ: --lockfile の引数から結果を組み立てる（vulns は package-lock.json にだけ付ける）
export function scannerStub(state) {
  const calls = [];
  const exec = async (cmd, args) => {
    calls.push(args);
    const files = args.filter((a) => a.startsWith('--lockfile=')).map((a) => a.slice('--lockfile='.length));
    const results = files.map((file) => ({
      source: { path: file, type: 'lockfile' },
      packages: path.basename(file) === 'package-lock.json' && state.vulns.length > 0 ? [{
        package: { name: 'example-package', version: '1.2.0', ecosystem: 'npm' },
        vulnerabilities: state.vulns.map((v) => ({ id: v.id, aliases: v.aliases ?? [], summary: `Example ${v.id}`, database_specific: { severity: v.severity ?? 'HIGH' }, affected: [{ package: { ecosystem: 'npm', name: 'example-package' }, ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '1.2.3' }] }] }] })),
      }] : [],
    }));
    return { code: state.vulns.length > 0 ? 1 : 0, stdout: JSON.stringify({ results }) };
  };
  exec.calls = calls;
  return exec;
}

export function makeHarness({ projectFiles = { 'package-lock.json': '{}', '.nvmrc': '22.11.0' }, projects } = {}) {
  const central = makeCentralRepo();
  const project = makeRepo({ master: projectFiles });
  const api = new FakeGitHub();
  const state = { vulns: [], collectors: defaultCollectors(), optionalCollectors: { 'aws-bulletins': syntheticBulletins }, pushFails: false, osvMeta: null, cloneUrl: () => project.url, heartbeats: 0, osvOk: { npm: true, Packagist: true, PyPI: true } };
  const projectsConfig = projects ?? { project_owner: 'o', projects: [{ project: 'demo', repo: 'o/demo', monitor_ref: 'master', owners: ['alice'], exposure: 'internet' }] };
  const exec = scannerStub(state);
  const deps = {
    http: {}, get collectors() { return state.collectors; }, get optionalCollectors() { return state.optionalCollectors; }, get optionalOverrides() { return state.optionalOverrides; }, exec, scannerPath: 'osv-scanner', scannerVersion: '2.7.0', scriptVersion: 'test-sha', centralRepo: 'org/central', api,
    async fetchOsvDb({ ecosystems, dest, now }) {
      const outcomes = {};
      const meta = {};
      for (const eco of ecosystems) {
        outcomes[eco] = { ok: state.osvOk[eco] };
        if (!state.osvOk[eco]) continue;
        mkdirSync(path.dirname(zipPathOf(dest, eco)), { recursive: true });
        writeFileSync(zipPathOf(dest, eco), 'placeholder');
        meta[eco] = state.osvMeta ?? { fetched_at: now, sha256: 'a'.repeat(64) };
      }
      writeFileSync(path.join(dest, 'meta.json'), JSON.stringify(meta));
      return { meta, outcomes };
    },
    resolveInventory: (args) => resolveInventory({ ...args, cloneUrl: (repo) => state.cloneUrl(repo) }),
    guardCommit: async (args) => { if (state.pushFails) { await guardCommit({ ...args, push: false }); throw new Error('push に失敗'); } return guardCommit(args); },
    sendHeartbeat: async ({ url }) => { state.heartbeats += 1; return { ok: Boolean(url) }; },
  };
  const env = { SI_APP_TOKEN: 'token', HEALTHCHECK_PING_URL: 'https://hc.example/ping' };
  return {
    central, project, api, state, deps, env, projectsConfig,
    run: (now = T0) => runCentral({ rootDir: central.root, projectsConfig, now, deps, env }),
    read: (rel) => JSON.parse(readFileSync(path.join(central.root, 'data', rel), 'utf8')),
    exists: (rel) => existsSync(path.join(central.root, 'data', rel)),
    vulnIssues: () => [...api.issues.values()].filter((i) => i.labels.includes('security-finding')),
  };
}
