#!/usr/bin/env node
// 中央の定期実行の入口。秘密情報は環境変数から受け取り、ログには出さない
import { execFile, execFileSync } from 'node:child_process';
import { promisify } from 'node:util';
import { ROOT_DIR, loadCentral, loadProjects, loadToolVersions } from '../lib/config.mjs';
import { assertValid } from '../lib/schema.mjs';
import { createHttp, COLLECT_HOSTS } from '../lib/http.mjs';
import { COLLECTORS, OPTIONAL_COLLECTORS } from '../collect/index.mjs';
import { fetchOsvDb } from '../collect/osv-db.mjs';
import { resolveInventory } from '../inventory/resolve.mjs';
import { createGitHubApi } from '../publish/github-api.mjs';
import { guardCommit } from '../publish/guard-commit.mjs';
import { sendHeartbeat } from '../publish/heartbeat.mjs';
import { runCentral } from '../publish/run-central.mjs';
import { toIso } from '../lib/time.mjs';

const run = promisify(execFile);
const SCANNER_PATH = process.env.OSV_SCANNER_PATH ?? 'osv-scanner';
const EXIT_PARTIAL = 3;

// 脆弱性ありは非0で終わるため、終了コードと出力を分けて返す
const exec = (cmd, args, { env = {} } = {}) => run(cmd, args, { env: { ...process.env, ...env }, maxBuffer: 256 * 1024 * 1024 })
  .then(({ stdout }) => ({ code: 0, stdout })).catch((error) => ({ code: typeof error.code === 'number' ? error.code : 127, stdout: error.stdout ?? '' }));

async function scannerVersion() {
  const out = await run(SCANNER_PATH, ['--version']).then((r) => r.stdout, () => '');
  return /(\d+\.\d+\.\d+)/.exec(out)?.[1] ?? null;
}

const central = loadCentral();
const centralRepo = process.env.GITHUB_REPOSITORY ?? `${central.central_org}/${central.central_repo}`;
const projectsConfig = assertValid('projects', loadProjects());
const now = toIso(new Date());
const version = await scannerVersion();
const expected = loadToolVersions()['osv-scanner'].version;
if (version && version !== expected) console.warn(`警告: OSV-Scanner の版が固定版と違います（${version} / ${expected}）`);

const outcome = await runCentral({
  rootDir: ROOT_DIR, projectsConfig, now, env: process.env,
  deps: {
    http: createHttp({ allowedHosts: COLLECT_HOSTS }), collectors: COLLECTORS, optionalCollectors: OPTIONAL_COLLECTORS, exec, scannerPath: SCANNER_PATH, scannerVersion: version ?? expected,
    scriptVersion: process.env.GITHUB_SHA ?? execFileSync('git', ['rev-parse', 'HEAD'], { cwd: ROOT_DIR, encoding: 'utf8' }).trim(),
    fetchOsvDb: (options) => fetchOsvDb(options), resolveInventory, guardCommit, sendHeartbeat, centralRepo,
    api: createGitHubApi({ repo: centralRepo, token: process.env.GITHUB_TOKEN }),
  },
});
console.log(JSON.stringify({ status: outcome.status, reasons: outcome.reasons, committed: outcome.committed, healthIssue: outcome.healthIssue }, null, 2));
// 終了状態が success 以外ならジョブを失敗させる（GitHub の失敗通知メールが届く）。完了通知は run-central が success のときだけ送る
process.exit(outcome.status === 'success' ? 0 : outcome.status === 'partial' ? EXIT_PARTIAL : 1);
