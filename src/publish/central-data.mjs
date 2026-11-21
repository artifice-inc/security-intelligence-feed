import { readFileSync, writeFileSync, mkdirSync, existsSync, readdirSync, renameSync, rmSync } from 'node:fs';
import path from 'node:path';

export const readJsonIfExists = (file, fallback = null) => (existsSync(file) ? JSON.parse(readFileSync(file, 'utf8')) : fallback);

const listJson = (dir) => (existsSync(dir) ? readdirSync(dir).filter((n) => n.endsWith('.json')).sort() : []);

// 前回の状態を data/ から読む（保存後に読み直されるもの。指示書 §1）
export function loadData(dataDir) {
  const mapOf = (sub, key) => new Map(listJson(path.join(dataDir, sub)).map((n) => { const v = readJsonIfExists(path.join(dataDir, sub, n)); return [key(v, n), v]; }));
  return {
    advisories: listJson(path.join(dataDir, 'advisories')).map((n) => readJsonIfExists(path.join(dataDir, 'advisories', n))),
    runtimes: { php: readJsonIfExists(path.join(dataDir, 'runtimes', 'php.json')), nodejs: readJsonIfExists(path.join(dataDir, 'runtimes', 'nodejs.json')), python: readJsonIfExists(path.join(dataDir, 'runtimes', 'python.json')) },
    jpAlerts: readJsonIfExists(path.join(dataDir, 'jp-alerts.json')),
    packagist: readJsonIfExists(path.join(dataDir, 'packagist-advisories.json')),
    amazonLinuxKernel: readJsonIfExists(path.join(dataDir, 'os', 'amazon-linux-kernel.json')),
    findings: mapOf('findings', (v) => v.project),
    inventory: mapOf('inventory', (v) => v.project),
    awsBulletins: readJsonIfExists(path.join(dataDir, 'aws-bulletins.json')),
    health: readJsonIfExists(path.join(dataDir, 'health.json')),
    issues: readJsonIfExists(path.join(dataDir, 'issues.json'), []),
  };
}

export function writeJson(outDataDir, rel, value) {
  const target = path.join(outDataDir, rel);
  mkdirSync(path.dirname(target), { recursive: true });
  writeFileSync(target, `${JSON.stringify(value, null, 2)}\n`);
}

// 一時ファイルに書き切ってから置き換える（途中で失敗しても対象を壊さない）。
// 一時ファイルは outDataDir の親に置く（検証・公開の対象は outDataDir の中だけ）
export function writeJsonAtomic(outDataDir, rel, value, { rename = renameSync } = {}) {
  const target = path.join(outDataDir, rel);
  const tmp = path.join(path.dirname(outDataDir), `.${path.basename(rel)}.tmp-${process.pid}`);
  mkdirSync(path.dirname(target), { recursive: true });
  try {
    writeFileSync(tmp, `${JSON.stringify(value, null, 2)}\n`);
    rename(tmp, target);
  } finally {
    rmSync(tmp, { force: true });
  }
}

export function writeText(outDataDir, rel, text) {
  const target = path.join(outDataDir, rel);
  mkdirSync(path.dirname(target), { recursive: true });
  if (existsSync(target) && readFileSync(target, 'utf8') === text) return; // 内容が同じなら更新しない
  writeFileSync(target, text);
}

export const advisoryMapOf = (advisories) => new Map(advisories.map((a) => [a.key, a]));
