#!/usr/bin/env node
// 非公開側の定期実行の入口。固定したコードの展開先から実行し、設定とデータは --private-root（非公開側のチェックアウト）のものを使う
import { execFile } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { parseArgs, promisify } from 'node:util';
import path from 'node:path';
import { loadCentral, loadProjects, loadToolVersions } from '../lib/config.mjs';
import { assertValid } from '../lib/schema.mjs';
import { fetchOsvDb } from '../collect/osv-db.mjs';
import { resolveInventory } from '../inventory/resolve.mjs';
import { createGitHubApi } from '../publish/github-api.mjs';
import { guardCommit } from '../publish/guard-commit.mjs';
import { sendHeartbeat } from '../publish/heartbeat.mjs';
import { runMatch } from '../match-central/run-match.mjs';
import { toIso } from '../lib/time.mjs';

const run = promisify(execFile);
const SCANNER_PATH = process.env.OSV_SCANNER_PATH ?? 'osv-scanner';
const EXIT_PARTIAL = 3;
const { values } = parseArgs({ options: { 'private-root': { type: 'string' } } });
if (!values['private-root']) {
  console.error('使い方: node src/cli/run-match.mjs --private-root <非公開側のチェックアウト>');
  process.exit(2);
}
const privateRoot = path.resolve(values['private-root']);

// 脆弱性ありは非0で終わるため、終了コードと出力を分けて返す
const exec = (cmd, args, { env = {} } = {}) => run(cmd, args, { env: { ...process.env, ...env }, maxBuffer: 256 * 1024 * 1024 })
  .then(({ stdout }) => ({ code: 0, stdout })).catch((error) => ({ code: typeof error.code === 'number' ? error.code : 127, stdout: error.stdout ?? '' }));

const version = await run(SCANNER_PATH, ['--version']).then((r) => /(\d+\.\d+\.\d+)/.exec(r.stdout)?.[1] ?? null, () => null);
const expected = loadToolVersions()['osv-scanner'].version;
if (version && version !== expected) console.warn(`警告: OSV-Scanner の版が固定版と違います（${version} / ${expected}）`);

const central = loadCentral(privateRoot);
const feedCode = JSON.parse(readFileSync(path.join(privateRoot, 'config', 'feed-code.json'), 'utf8'));
const centralRepo = process.env.GITHUB_REPOSITORY ?? `${central.central_org}/${central.central_repo}`;
const outcome = await runMatch({
  privateRoot, projectsConfig: assertValid('projects', loadProjects(privateRoot)), feedUrl: `https://github.com/${feedCode.repo}.git`, now: toIso(new Date()), env: process.env,
  deps: {
    exec, scannerPath: SCANNER_PATH, scannerVersion: version ?? expected, scriptVersion: process.env.SI_CODE_SHA ?? null,
    fetchOsvDb: (options) => fetchOsvDb(options), resolveInventory, guardCommit, sendHeartbeat, centralRepo,
    api: createGitHubApi({ repo: centralRepo, token: process.env.GITHUB_TOKEN, botLogin: central.bot_login, userAgent: central.user_agent }),
  },
});
console.log(JSON.stringify({ status: outcome.status, reasons: outcome.reasons, committed: outcome.committed, healthIssue: outcome.healthIssue, feedMode: outcome.feedMode }, null, 2));
process.exit(outcome.status === 'success' ? 0 : outcome.status === 'partial' ? EXIT_PARTIAL : 1);
