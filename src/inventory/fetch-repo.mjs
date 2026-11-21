import { execFile } from 'node:child_process';
import { mkdir, rm } from 'node:fs/promises';
import { promisify } from 'node:util';
import path from 'node:path';
import { readFileSync, existsSync } from 'node:fs';
import YAML from 'yaml';
import { STACK_PATH, DEFAULT_LOCKFILES, isSafeRelativePath, siblingManifests } from './detect-stack.mjs';
import { validate } from '../lib/schema.mjs';

const run = promisify(execFile);
const DETECTION_FILES = ['package.json', 'composer.json', '.nvmrc', '.node-version', 'pyproject.toml', 'Pipfile', '.python-version', 'Dockerfile*', STACK_PATH];
const GIT_TIMEOUT_MS = 120_000;

export class FetchRepoError extends Error {
  constructor(message) { super(message); this.kind = 'inventory'; }
}

// トークンは URL にもコマンド引数にも入れず、環境変数の extraheader で渡す（指示書 §6.2）
export function gitEnv(token) {
  if (!token) return { ...process.env };
  const basic = Buffer.from(`x-access-token:${token}`).toString('base64');
  return {
    ...process.env, GIT_TERMINAL_PROMPT: '0', GIT_CONFIG_COUNT: '1',
    GIT_CONFIG_KEY_0: 'http.extraheader', GIT_CONFIG_VALUE_0: `AUTHORIZATION: basic ${basic}`,
  };
}

const scrub = (text, token) => (token ? String(text).split(token).join('***') : String(text));

async function git(args, { cwd, token }) {
  try {
    return (await run('git', args, { cwd, env: gitEnv(token), timeout: GIT_TIMEOUT_MS, maxBuffer: 10 * 1024 * 1024 })).stdout;
  } catch (error) {
    throw new FetchRepoError(`git ${args[0]} に失敗しました: ${scrub(error.stderr || error.message, token).split('\n')[0]}`);
  }
}

const lockfilePatterns = (lockfiles) => [...lockfiles, ...siblingManifests(lockfiles)].map((file) => `/${file}`);

function readStack(dir) {
  const file = path.join(dir, STACK_PATH);
  if (!existsSync(file)) return null;
  try {
    const parsed = YAML.parse(readFileSync(file, 'utf8')) ?? {};
    return validate('stack', parsed).ok ? parsed : null;
  } catch { return null; }
}

async function cloneSparse({ url, ref, dir, token }) {
  await rm(dir, { recursive: true, force: true });
  await mkdir(path.dirname(dir), { recursive: true });
  await git(['clone', '--depth', '1', '--filter=blob:none', '--sparse', '--branch', ref, url, dir], { token });
  await git(['sparse-checkout', 'set', '--no-cone', `/${STACK_PATH}`], { cwd: dir, token });
}

// url: 通常は https://github.com/<owner>/<repo>.git。テストではローカルの file:// を渡す
export async function fetchRepo({ url, monitorRef, dir, token, lockfileOverride = null }) {
  let ref = monitorRef;
  await cloneSparse({ url, ref, dir, token });
  const declared = readStack(dir)?.monitor_ref;
  if (declared && declared !== ref) {
    ref = declared;
    await cloneSparse({ url, ref, dir, token });
  }
  const stack = readStack(dir);
  const requested = (stack?.lockfiles ?? lockfileOverride ?? DEFAULT_LOCKFILES).filter(isSafeRelativePath);
  await git(['sparse-checkout', 'set', '--no-cone', ...lockfilePatterns(requested), ...DETECTION_FILES.map((f) => `/${f}`)], { cwd: dir, token });
  const sourceCommit = (await git(['rev-parse', 'HEAD'], { cwd: dir, token })).trim();
  return { dir, monitorRef: ref, sourceCommit };
}
