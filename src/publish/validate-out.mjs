import { readFileSync, readdirSync, existsSync, statSync } from 'node:fs';
import path from 'node:path';
import { validate } from '../lib/schema.mjs';

// ファイルの位置 → スキーマ名。ここにないファイルは未知として違反にする
const RULES = [
  [/^advisories\/[^/]+\.json$/, 'advisory'], [/^runtimes\/(php|nodejs|python)\.json$/, 'runtimes'], [/^jp-alerts\.json$/, 'jp-alerts'],
  [/^packagist-advisories\.json$/, 'packagist-advisories'], [/^inventory\/[^/]+\.json$/, 'inventory'], [/^findings\/[^/]+\.json$/, 'findings'],
  [/^issues\.json$/, 'issues'], [/^aws-bulletins\.json$/, 'aws-bulletins'], [/^health\.json$/, 'health'], [/^feed-state\.json$/, 'feed-state'], [/^os\/amazon-linux-kernel\.json$/, 'amazon-linux-kernel'],
];
const TEXT_FILES = new Set(['digest/latest.md', '.gitkeep']);

const walk = (dir, base = dir) => readdirSync(dir).flatMap((n) => {
  const full = path.join(dir, n);
  return statSync(full).isDirectory() ? walk(full, base) : [path.relative(base, full).split(path.sep).join('/')];
});

// 生成物の全体を検証する。違反の一覧を返す（空なら通過）
export function validateOutDir(outDataDir) {
  const violations = [];
  if (!existsSync(outDataDir)) return [{ file: outDataDir, message: '出力ディレクトリがありません' }];
  for (const rel of walk(outDataDir).filter((r) => !r.startsWith('inventory-export/'))) {
    if (TEXT_FILES.has(rel)) continue;
    const rule = RULES.find(([pattern]) => pattern.test(rel));
    if (!rule) { violations.push({ file: rel, message: '未知のファイルです' }); continue; }
    try {
      const result = validate(rule[1], JSON.parse(readFileSync(path.join(outDataDir, rel), 'utf8')));
      if (!result.ok) violations.push({ file: rel, message: `${result.errors[0].instancePath || '/'} ${result.errors[0].message}` });
    } catch (error) { violations.push({ file: rel, message: `JSON として読めません: ${error.message}` }); }
  }
  return violations;
}
