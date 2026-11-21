import { execFile } from 'node:child_process';
import { mkdirSync, rmSync } from 'node:fs';
import { promisify } from 'node:util';
import path from 'node:path';
import { validateFeed } from '../feed/validate-feed.mjs';
import { inspectTree, maskPath, SECRET_PATTERNS } from '../feed/inspect-tree.mjs';

const run = promisify(execFile);
const GIT_ENV = { ...process.env, GIT_TERMINAL_PROMPT: '0' };
const FEED_BRANCH = 'feed';
export const MESSAGES = {
  unsupported: 'コードの固定値の更新が必要です（読めないフィードの版）',
  caseInfo: '公開側のフィードに案件情報の語または秘密情報の形が含まれています',
  restored: 'フィードの最新を使えないため、前回検証したフィードで照合しました',
  degraded: 'フィードを使えないため、縮退照合（OSV の検出だけ）にしました',
};

const git = (cwd, args) => run('git', args, { cwd, env: GIT_ENV, maxBuffer: 16 * 1024 * 1024 });

// 指定の ref（ブランチ名または SHA）を空の場所に取り出し、検証する。語や自由文をログに出さないよう、メッセージは固定にする
async function tryCheckout({ url, ref, dir, needles }) {
  rmSync(dir, { recursive: true, force: true });
  mkdirSync(dir, { recursive: true });
  try {
    await git(dir, ['init', '-q']);
    await git(dir, ['remote', 'add', 'origin', url]);
    await git(dir, ['fetch', '-q', '--depth', '1', 'origin', ref]);
    await git(dir, ['checkout', '-q', '--detach', 'FETCH_HEAD']);
  } catch {
    return { ok: false, problems: [`フィードを取得できませんでした（${ref === FEED_BRANCH ? '最新' : '前回検証した版'}）`] };
  }
  const sha = (await git(dir, ['rev-parse', 'HEAD'])).stdout.trim();
  const dataDir = path.join(dir, 'data');
  const mask = (text) => maskPath(text, needles, Object.values(SECRET_PATTERNS));
  const problems = [];
  let violations;
  try { violations = validateFeed(dataDir); } catch (error) { violations = [{ file: 'data', message: `検査で例外: ${error.message}` }]; }
  for (const v of violations) problems.push(v.kind === 'unsupported_format' ? MESSAGES.unsupported : mask(`フィードの検証に失敗: ${v.file}: ${v.message}`));
  let findings;
  try { findings = inspectTree({ dir, needles }); } catch (error) { findings = [{ file: 'data', patternName: 'exception' }]; }
  if (findings.length > 0) problems.push(MESSAGES.caseInfo);
  return problems.length > 0 ? { ok: false, problems: [...new Set(problems)] } : { ok: true, sha, dataDir, problems: [] };
}

// 公開側のフィードを取得して検証する。最新 → 前回検証した版 → 縮退の順（指示書 T4）
export async function fetchFeed({ url, lastValidatedSha = null, needles = [], workDir }) {
  const latest = await tryCheckout({ url, ref: FEED_BRANCH, dir: workDir, needles });
  if (latest.ok) return { dataDir: latest.dataDir, sha: latest.sha, mode: 'latest', problems: [] };
  const problems = [...latest.problems];
  if (lastValidatedSha) {
    const restored = await tryCheckout({ url, ref: lastValidatedSha, dir: workDir, needles });
    if (restored.ok) return { dataDir: restored.dataDir, sha: restored.sha, mode: 'restored', problems: [...problems, MESSAGES.restored] };
    problems.push(...restored.problems);
  }
  rmSync(workDir, { recursive: true, force: true });
  return { dataDir: null, sha: null, mode: 'degraded', problems: [...problems, MESSAGES.degraded] };
}
