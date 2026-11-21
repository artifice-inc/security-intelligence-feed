import { mkdirSync, writeFileSync, readFileSync, readdirSync, renameSync, existsSync, rmSync } from 'node:fs';
import path from 'node:path';
import { detectStack } from './detect-stack.mjs';
import { findUrlCredentials } from './requirements.mjs';
import { sha256Hex } from '../lib/hash.mjs';
import { validate } from '../lib/schema.mjs';
import { toIso, daysBetween } from '../lib/time.mjs';
import { loadThresholds } from '../lib/config.mjs';

const BACKUP_PATTERN = /\.bak-\d+$/;

// 検査した Buffer をそのまま書き出す。一時ディレクトリに書き終えてから置き換えるので、途中で失敗しても前回の出力は残る
// io: テストで失敗を再現するための注入口
export function exportInventory({ projectDir, project, outDir, now, sourceRef, sourceCommit, exposure = null, io = {} }) {
  const { readFile = readFileSync, writeFile = writeFileSync, rename = renameSync } = io;
  const detected = detectStack(projectDir);
  // 手順1〜3: 1回だけ読んだ Buffer を、検出時の sha256 と照合し、認証情報を検査する（読み直さない）
  const buffers = detected.files.map((file) => {
    const buffer = readFile(path.join(projectDir, file.path));
    if (sha256Hex(buffer) !== file.sha256) throw new Error(`検出のあとでファイルが変わりました: ${file.path}`);
    const credentialLines = findUrlCredentials(buffer.toString('utf8'));
    if (credentialLines.length > 0) {
      throw new Error(`認証情報を含む URL があるため export できません: ${file.path}（${credentialLines.map((n) => `${n}行目`).join('、')}）`);
    }
    return { path: file.path, buffer };
  });
  const manifest = {
    project, exported_at: toIso(now), source_ref: sourceRef, source_commit: sourceCommit,
    exposure: detected.stack?.exposure ?? exposure, runtimes_detected: detected.runtimes, files: detected.files,
  };
  const tempDir = `${outDir}.tmp-${process.pid}`;
  const backupDir = `${outDir}.bak-${process.pid}`;
  try {
    rmSync(tempDir, { recursive: true, force: true });
    for (const { path: file, buffer } of buffers) {
      const target = path.join(tempDir, 'files', file);
      mkdirSync(path.dirname(target), { recursive: true });
      writeFile(target, buffer);
    }
    writeFile(path.join(tempDir, 'manifest.json'), `${JSON.stringify(manifest, null, 2)}\n`);
    swapDirectory({ tempDir, outDir, backupDir, rename });
  } catch (error) {
    rmSync(tempDir, { recursive: true, force: true });
    throw error;
  }
  return { manifest, problems: detected.problems, leftovers: leftoverBackups(outDir) };
}

// 前回の出力を退避 → 一時ディレクトリを置き換え → 退避を削除。2つ目の rename が失敗したら退避を戻す
function swapDirectory({ tempDir, outDir, backupDir, rename }) {
  mkdirSync(path.dirname(outDir), { recursive: true });
  const hadPrevious = existsSync(outDir);
  rmSync(backupDir, { recursive: true, force: true });
  if (hadPrevious) rename(outDir, backupDir);
  try {
    rename(tempDir, outDir);
  } catch (error) {
    if (hadPrevious) rename(backupDir, outDir);
    throw error;
  }
  rmSync(backupDir, { recursive: true, force: true });
}

// rename の間にプロセスが止まると .bak が残る。次の実行で気づけるように返す
function leftoverBackups(outDir) {
  const parent = path.dirname(outDir);
  const base = path.basename(outDir);
  return readdirSync(parent).filter((name) => name.startsWith(`${base}.bak-`) && BACKUP_PATTERN.test(name));
}

// 中央側の判定: 30日以内で検証を通り、sha256 が全て一致 → fresh / 30日超 → stale_inventory / 不一致・欠落 → unavailable
export function evaluateExport({ dir, now, thresholds = loadThresholds() }) {
  const manifestPath = path.join(dir, 'manifest.json');
  if (!existsSync(manifestPath)) return { status: 'unavailable', reason: 'manifest.json がありません' };
  let manifest;
  try { manifest = JSON.parse(readFileSync(manifestPath, 'utf8')); } catch { return { status: 'unavailable', reason: 'manifest.json を解析できません' }; }
  const check = validate('export-manifest', manifest);
  if (!check.ok) return { status: 'unavailable', reason: 'manifest.json がスキーマに合いません' };
  for (const file of manifest.files) {
    const full = path.join(dir, 'files', file.path);
    if (!existsSync(full)) return { status: 'unavailable', reason: `ファイルが欠けています: ${file.path}` };
    if (sha256Hex(readFileSync(full)) !== file.sha256) return { status: 'unavailable', reason: `sha256 が一致しません: ${file.path}` };
  }
  const stale = daysBetween(manifest.exported_at, now) > thresholds.export_max_days;
  return { status: stale ? 'stale_inventory' : 'fresh', manifest, filesDir: path.join(dir, 'files') };
}
