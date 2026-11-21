import { readFileSync, mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { checkRequirementsPinned } from '../inventory/requirements.mjs';
import { sha256Hex } from '../lib/hash.mjs';

const CHANGED = 'インベントリの作成後に内容が変わったため照合できません';

// 固定されていない行の行番号だけを載せる（行の中身は載せない）
export const unpinnedMessage = (lines) => `版を == で固定していない行があるため照合できません（${lines.map((n) => `${n}行目`).join('、')}）`;

const readOnce = (workdir, file) => { try { return readFileSync(path.join(workdir, file)); } catch { return null; } };

// requirements の lockfile は、検査した Buffer をそのまま一時ファイルに書いてスキャンさせる。
// インベントリ作成後に元ファイルが変わっても、検査していない内容をスキャンしない（不変条件2）
export function prepareRequirementsInputs({ workdir, files, inventory, io = {} }) {
  const { writeFile = writeFileSync } = io; // テストで書き込みの失敗を再現するための注入口
  const inputs = [];
  const errors = [];
  const dirs = [];
  const cleanup = () => dirs.forEach((dir) => rmSync(dir, { recursive: true, force: true }));
  try {
    for (const file of files) {
      const buffer = readOnce(workdir, file);
      const expected = inventory.files.find((f) => f.path === file)?.sha256;
      if (!buffer || sha256Hex(buffer) !== expected) { errors.push({ kind: 'lockfile', target: file, message: CHANGED }); continue; }
      const checked = checkRequirementsPinned(buffer.toString('utf8'));
      if (!checked.ok) { errors.push({ kind: 'lockfile', target: file, message: unpinnedMessage(checked.lines) }); continue; }
      const dir = mkdtempSync(path.join(os.tmpdir(), 'si-req-'));
      dirs.push(dir);
      const scanPath = path.join(dir, 'requirements.txt');
      writeFile(scanPath, buffer);
      inputs.push({ file, scanPath });
    }
  } catch (error) {
    cleanup(); // 途中で失敗しても、作成済みの一時ディレクトリを残さない
    throw error;
  }
  return { inputs, errors, cleanup };
}

// kind: requirements-unpinned のファイル。スキャンせず、行番号つきで照合不能にする
export function unpinnedErrors({ workdir, inventory }) {
  return inventory.files.filter((f) => f.kind === 'requirements-unpinned').map((f) => {
    const buffer = readOnce(workdir, f.path);
    const checked = buffer ? checkRequirementsPinned(buffer.toString('utf8')) : { ok: true, lines: [] };
    return { kind: 'lockfile', target: f.path, message: checked.ok ? CHANGED : unpinnedMessage(checked.lines) };
  });
}
