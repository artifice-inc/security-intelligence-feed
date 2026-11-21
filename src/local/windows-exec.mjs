import path from 'node:path';
import { sha256Hex } from '../lib/hash.mjs';

// Windows でだけ使う起動の準備。OS・ファイル読み込み・chdir は引数で受け取る（どの OS の試験でも走らせるため）
const WINDOWS_ABSOLUTE_EXE = /^(?:[A-Za-z]:[\\/]|\\\\[^\\/]+[\\/]).*\.exe$/i;
const PATH_OPTIONS = ['project-dir', 'feed-dir', 'osv-db-dir', 'private-root'];

// 戻り値: win32 以外は null。win32 は { ok: true, scannerPath } か { ok: false, message }
export async function prepareWindowsRun({ platform, scannerPath, toolVersions, readFile }) {
  if (platform !== 'win32') return null;
  if (!scannerPath || !WINDOWS_ABSOLUTE_EXE.test(scannerPath)) return { ok: false, message: 'Windows では --scanner に osv-scanner.exe の完全なパスが必要です' };
  let content;
  try { content = await readFile(scannerPath); } catch { return { ok: false, message: 'osv-scanner.exe がありません（または読めません）。導入の手順で入れてください' }; }
  const expected = toolVersions['osv-scanner'].assets.windows_amd64.sha256;
  if (sha256Hex(content) !== expected.toLowerCase()) return { ok: false, message: '固定版と一致しない osv-scanner です。導入の手順で入れ直してください' };
  return { ok: true, scannerPath };
}

// 順序が要点: パスのオプションを元の現在のディレクトリ基準で絶対化 → chdir(codeRoot) → 準備。
// chdir 後は git などを案件のフォルダから探さない。--scanner は解決せず、元の値のまま検査する
export async function startWindowsRun({ platform, values, cwd, codeRoot, chdir, toolVersions, readFile }) {
  if (platform !== 'win32') return null;
  const resolved = { ...values };
  for (const key of PATH_OPTIONS) if (values[key]) resolved[key] = path.win32.resolve(cwd, values[key]);
  chdir(codeRoot);
  const prepared = await prepareWindowsRun({ platform, scannerPath: values.scanner, toolVersions, readFile });
  return { values: resolved, ...prepared };
}

// 準備に失敗したら、スキャナだけ起動せず理由を返す（照合の理由は scan_errors に載る）
export const guardScannerExec = (exec, scannerPath, failure) => (failure
  ? (cmd, args, options) => (cmd === scannerPath ? Promise.resolve({ code: 127, stdout: '', reason: failure }) : exec(cmd, args, options))
  : exec);
