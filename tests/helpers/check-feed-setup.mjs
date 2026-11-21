import { mkdirSync, mkdtempSync, writeFileSync, readFileSync, cpSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { securityCheck } from '../../src/local/security-check.mjs';
import { zipPathOf } from '../../src/collect/osv-db.mjs';
import { ROOT_DIR } from '../../src/lib/config.mjs';
import { scannerStub } from './central-harness.mjs';
import { makeTree } from './tree.mjs';
import { makeFeedData, NOW, collectedAt } from './match-harness.mjs';

export const VULN = { id: 'GHSA-aaaa-bbbb-cccc', aliases: ['CVE-2026-1'], severity: 'HIGH' };
export const NODE_FILES = { 'package-lock.json': '{}', '.nvmrc': '22.11.0' };
export const tmp = (prefix) => mkdtempSync(path.join(tmpdir(), prefix));
export const writeJson = (file, value) => { mkdirSync(path.dirname(file), { recursive: true }); writeFileSync(file, JSON.stringify(value)); };

// 非公開側のチェックアウトの代わり（config/ と data/ だけ。公開側と違う閾値を持てる）
export function makePrivateRoot({ thresholds = {}, projects = null } = {}) {
  const root = tmp('si-private-');
  mkdirSync(path.join(root, 'config'), { recursive: true });
  for (const name of ['schedule.json', 'thresholds.json']) cpSync(path.join(ROOT_DIR, 'config', name), path.join(root, 'config', name));
  const file = path.join(root, 'config', 'thresholds.json');
  writeJson(file, { ...JSON.parse(readFileSync(file, 'utf8')), ...thresholds });
  if (projects) writeFileSync(path.join(root, 'config', 'projects.yaml'), projects);
  return root;
}

export function setup({ vulns = [VULN], files = NODE_FILES, feedOptions = {}, ecosystems = ['npm'] } = {}) {
  const state = { vulns };
  const osvDir = tmp('si-osvdb-');
  for (const eco of ecosystems) { mkdirSync(path.dirname(zipPathOf(osvDir, eco)), { recursive: true }); writeFileSync(zipPathOf(osvDir, eco), 'placeholder'); }
  writeJson(path.join(osvDir, 'meta.json'), Object.fromEntries(ecosystems.map((eco) => [eco, { fetched_at: collectedAt(NOW), sha256: 'a'.repeat(64) }])));
  const feedDir = makeFeedData({ now: NOW, ...feedOptions });
  const projectDir = makeTree(files);
  const deps = { now: new Date(NOW), exec: scannerStub(state), scannerPath: 'osv-scanner', scannerVersion: async () => '2.7.0', fetchOsvDb: async (o) => ({ meta: {}, outcomes: Object.fromEntries(o.ecosystems.map((e) => [e, { ok: false, error: { message: 'offline' } }])) }) };
  const run = (extra = {}) => securityCheck({ cacheRoot: tmp('si-cache-'), projectDir, projectName: 'demo', deps, scriptVersion: 'code-sha', feedDir, feedSha: 'feed-sha', osvDbDir: osvDir, exposure: 'internet', ...extra });
  return { run, feedDir, state, deps, osvDir };
}

