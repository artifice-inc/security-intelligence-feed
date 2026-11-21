#!/usr/bin/env node
import { parseArgs } from 'node:util';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import path from 'node:path';
import { readFile } from 'node:fs/promises';
import { ROOT_DIR, loadToolVersions } from '../lib/config.mjs';
import { assertValid } from '../lib/schema.mjs';
import { fetchOsvDb } from '../collect/osv-db.mjs';
import { securityCheck } from '../local/security-check.mjs';
import { startWindowsRun, guardScannerExec } from '../local/windows-exec.mjs';

const run = promisify(execFile);
const { values } = parseArgs({ options: { 'project-dir': { type: 'string' }, project: { type: 'string' }, json: { type: 'boolean' }, 'pull-failed': { type: 'boolean' }, scanner: { type: 'string' }, exposure: { type: 'string' }, 'feed-dir': { type: 'string' }, 'feed-sha': { type: 'string' }, 'no-feed': { type: 'boolean' }, 'private-root': { type: 'string' }, 'code-sha': { type: 'string' }, 'osv-db-dir': { type: 'string' } } });
if (!values['project-dir']) { console.error('使い方: security-check.mjs --project-dir <案件のルート> [--project <名前>] --json'); process.exit(2); }

const newRoute = Boolean(values['feed-dir'] || values['no-feed']);
if (values['feed-dir'] && values['no-feed']) { console.error('--feed-dir と --no-feed は同時に指定できません'); process.exit(2); }
if (newRoute && !values['osv-db-dir']) { console.error('--feed-dir または --no-feed を使うときは --osv-db-dir が必要です'); process.exit(2); }

// Windows だけ: パス解決 → chdir(codeRoot) → スキャナの sha256 検証（失敗しても照合は続け、osv を unavailable にする）
const windowsRun = await startWindowsRun({ platform: process.platform, values, cwd: process.cwd(), codeRoot: ROOT_DIR, chdir: (dir) => process.chdir(dir), toolVersions: loadToolVersions(), readFile });
const options = windowsRun?.values ?? values;
const scannerPath = windowsRun ? (windowsRun.scannerPath ?? values.scanner ?? 'osv-scanner') : (values.scanner ?? process.env.OSV_SCANNER_PATH ?? 'osv-scanner');
const baseExec = (cmd, args, { env = {} } = {}) => run(cmd, args, { env: { ...process.env, ...env }, maxBuffer: 256 * 1024 * 1024 })
  .then(({ stdout }) => ({ code: 0, stdout })).catch((error) => ({ code: typeof error.code === 'number' ? error.code : 127, stdout: error.stdout ?? '' }));
const exec = guardScannerExec(baseExec, scannerPath, windowsRun && !windowsRun.ok ? windowsRun.message : null);
const projectDir = path.resolve(options['project-dir']);

const output = await securityCheck({
  cacheRoot: ROOT_DIR, projectDir, projectName: options.project ?? path.basename(projectDir), pullOk: !values['pull-failed'], exposure: values.exposure ?? null, scriptVersion: values['code-sha'],
  feedDir: options['feed-dir'] ? path.resolve(options['feed-dir']) : null, feedSha: values['feed-sha'] ?? null, noFeed: Boolean(values['no-feed']),
  privateRoot: options['private-root'] ? path.resolve(options['private-root']) : null, osvDbDir: options['osv-db-dir'] ? path.resolve(options['osv-db-dir']) : null,
  deps: {
    exec, scannerPath, fetchOsvDb,
    scannerVersion: async () => (windowsRun && !windowsRun.ok ? null : /(\d+\.\d+\.\d+)/.exec((await run(scannerPath, ['--version']).catch(() => ({ stdout: '' }))).stdout)?.[1] ?? null),
  },
});
assertValid('security-check-output', output);
console.log(JSON.stringify(output, null, 2));
