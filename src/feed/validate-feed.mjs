import { readFileSync, readdirSync, lstatSync } from 'node:fs';
import path from 'node:path';
import { validate } from '../lib/schema.mjs';
import { FEED_RULES, REQUIRED_FEED_FILES, PUBLIC_ADVISORY_SOURCES, SUPPORTED_FEED_FORMATS } from './definition.mjs';

const isUnsafeSegment = (segment) => segment.startsWith('.') || segment.includes('..');

// lstat でたどり、通常のファイルだけを相対パスで返す。それ以外は violations に積む
function collect(dir, base, violations) {
  const files = [];
  for (const name of readdirSync(dir)) {
    const full = path.join(dir, name);
    const rel = path.relative(base, full).split(path.sep).join('/');
    const stat = lstatSync(full);
    if (stat.isSymbolicLink() || !(stat.isFile() || stat.isDirectory())) {
      violations.push({ file: rel, message: '通常のファイルとディレクトリ以外は置けません' });
    } else if (stat.isDirectory()) {
      if (isUnsafeSegment(name)) violations.push({ file: rel, message: '隠しディレクトリまたは .. を含むパスは置けません' });
      files.push(...collect(full, base, violations));
    } else files.push(rel);
  }
  return files;
}

// フィードのデータのルート（.../data）を検査し、違反の配列を返す（空なら通過）
export function validateFeed(feedDataDir) {
  // ルート自体がシンボリックリンクなら、有効な別のディレクトリを指していても通さない
  let root;
  try { root = lstatSync(feedDataDir); } catch { return [{ file: feedDataDir, message: 'フィードのディレクトリがありません' }]; }
  if (!root.isDirectory()) return [{ file: feedDataDir, message: 'フィードのルートが通常のディレクトリではありません' }];
  const violations = [];
  const files = collect(feedDataDir, feedDataDir, violations);
  const present = new Set(files);
  for (const required of REQUIRED_FEED_FILES) {
    if (!present.has(required)) violations.push({ file: required, message: '必須ファイルがありません' });
  }
  if (!files.some((rel) => rel.startsWith('advisories/'))) violations.push({ file: 'advisories/', message: 'アドバイザリが1件もありません' });
  for (const rel of files) {
    if (rel.split('/').some(isUnsafeSegment)) { violations.push({ file: rel, message: '隠しファイルまたは .. を含むパスは置けません' }); continue; }
    const rule = FEED_RULES.find(([pattern]) => pattern.test(rel));
    if (!rule) { violations.push({ file: rel, message: '許可されていないパスです' }); continue; }
    let data;
    try { data = JSON.parse(readFileSync(path.join(feedDataDir, rel), 'utf8')); } catch (error) {
      violations.push({ file: rel, message: `JSON として読めません: ${error.message}` });
      continue;
    }
    const result = validate(rule[1], data);
    if (!result.ok) { violations.push({ file: rel, message: `${result.errors[0].instancePath || '/'} ${result.errors[0].message}` }); continue; }
    if (rule[1] === 'feed-format' && !SUPPORTED_FEED_FORMATS.includes(data.format_version)) {
      violations.push({ file: rel, kind: 'unsupported_format', message: `読めないフィードの版です: ${data.format_version}` });
    }
    if (rule[1] === 'advisory' && !(data.sources ?? []).every((s) => PUBLIC_ADVISORY_SOURCES.includes(s.name))) {
      violations.push({ file: rel, message: '公開の情報源以外の記録が含まれています' });
    }
  }
  return violations;
}
