import { execFile } from 'node:child_process';
import { cpSync, existsSync, mkdirSync, readFileSync, readdirSync, rmSync, writeFileSync, statSync } from 'node:fs';
import { promisify } from 'node:util';
import path from 'node:path';

const run = promisify(execFile);
const IDENTITY = ['-c', 'user.name=security-intelligence[bot]', '-c', 'user.email=noreply@users.noreply.github.com'];
// 人が PR で追加する領域。bot の同期対象に含めない
export const PROTECTED_DIRS = ['inventory-export'];

export class GuardError extends Error {}

const listFiles = (dir, base = dir) => (existsSync(dir) ? readdirSync(dir).flatMap((name) => {
  const full = path.join(dir, name);
  return statSync(full).isDirectory() ? listFiles(full, base) : [path.relative(base, full)];
}) : []);

const isProtected = (rel) => PROTECTED_DIRS.some((d) => rel === d || rel.startsWith(`${d}${path.sep}`));

// .work/out/data → data へ反映する（差分のあるファイルだけ書く・out にないファイルは消す）
export function syncData(outDataDir, dataDir) {
  const wanted = new Set(listFiles(outDataDir).filter((r) => !isProtected(r)));
  for (const rel of wanted) {
    const target = path.join(dataDir, rel);
    const content = readFileSync(path.join(outDataDir, rel));
    if (existsSync(target) && readFileSync(target).equals(content)) continue;
    mkdirSync(path.dirname(target), { recursive: true });
    writeFileSync(target, content);
  }
  for (const rel of listFiles(dataDir).filter((r) => !isProtected(r) && !wanted.has(r))) rmSync(path.join(dataDir, rel));
}

async function git(repoDir, args) {
  return (await run('git', [...IDENTITY, ...args], { cwd: repoDir, maxBuffer: 10 * 1024 * 1024 })).stdout;
}

// data/ 以外に変更があれば中止。差分がなければコミットしない。push の失敗は呼び出し側が failed として扱う
// branch を渡すと git push origin HEAD:<branch>（公開側の feed ブランチ用）。省略時は実行中のブランチへの git push
export async function guardCommit({ repoDir, outDataDir, message, push = true, branch = null }) {
  syncData(outDataDir, path.join(repoDir, 'data'));
  const changed = (await git(repoDir, ['status', '--porcelain', '--untracked-files=all'])).split('\n').filter(Boolean).map((l) => l.slice(3).replace(/^"|"$/g, ''));
  const outside = changed.filter((file) => !file.startsWith('data/'));
  if (outside.length > 0) throw new GuardError(`data/ 以外のファイルに変更があるため中止します: ${outside.slice(0, 5).join(', ')}`);
  if (changed.length === 0) return { committed: false, pushed: false };
  await git(repoDir, ['add', '--', 'data']);
  await git(repoDir, ['commit', '-q', '-m', message]);
  if (!push) return { committed: true, pushed: false };
  await git(repoDir, branch ? ['push', 'origin', `HEAD:${branch}`] : ['push']);
  return { committed: true, pushed: true };
}

export const copyDirectory = (from, to) => { if (existsSync(from)) cpSync(from, to, { recursive: true, filter: (src) => !isProtected(path.relative(from, src)) }); };
