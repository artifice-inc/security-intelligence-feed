import { readFileSync, readdirSync, lstatSync } from 'node:fs';
import path from 'node:path';

// 形式と長さを含めるので、この定義の文字列自身には一致しない
export const SECRET_PATTERNS = {
  github_token: /ghp_[A-Za-z0-9]{36}/,
  github_fine_grained_token: /github_pat_[A-Za-z0-9_]{82}/,
  aws_access_key: /AKIA[0-9A-Z]{16}/,
  private_key: /-----BEGIN [A-Z ]*PRIVATE KEY-----/,
};

const escapeRegExp = (text) => text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

// 一致した部分を *** にしたパスを返す（語そのものを出さない）
export const maskPath = (rel, needles, patterns) => {
  let masked = rel;
  for (const needle of needles) masked = masked.replace(new RegExp(escapeRegExp(needle), 'gi'), '***');
  for (const pattern of patterns) masked = masked.replace(new RegExp(pattern.source, 'g'), '***');
  return masked;
};

function* walkTree(dir, base) {
  for (const name of readdirSync(dir)) {
    if (name === '.git') continue;
    const full = path.join(dir, name);
    const stat = lstatSync(full);
    const rel = path.relative(base, full).split(path.sep).join('/');
    if (stat.isSymbolicLink()) yield { rel, symlink: true };
    else if (stat.isDirectory()) { yield { rel, directory: true }; yield* walkTree(full, base); } else if (stat.isFile()) yield { rel, full };
  }
}

// dir 以下を検査する。戻り値は [{ file(伏せ字), needleIndex | patternName }]
export function inspectTree({ dir, needles = [], secretPatterns = SECRET_PATTERNS }) {
  const patterns = Object.values(secretPatterns);
  const lowered = needles.map((n) => n.toLowerCase());
  const findings = [];
  const check = (text, file) => {
    const lowerText = text.toLowerCase();
    lowered.forEach((needle, needleIndex) => { if (needle && lowerText.includes(needle)) findings.push({ file, needleIndex }); });
    for (const [patternName, pattern] of Object.entries(secretPatterns)) if (pattern.test(text)) findings.push({ file, patternName });
  };
  try {
    if (!lstatSync(dir).isDirectory()) return [{ file: '.', patternName: 'invalid_root' }];
  } catch {
    return [{ file: '.', patternName: 'invalid_root' }];
  }
  for (const entry of walkTree(dir, dir)) {
    const file = maskPath(entry.rel, needles, patterns);
    if (entry.symlink) { findings.push({ file, patternName: 'symlink' }); continue; }
    check(entry.rel, file);
    if (!entry.directory) check(readFileSync(entry.full, 'utf8'), file);
  }
  return findings;
}

// 非公開側の設定から、公開側に出してはいけない語を集める（空と重複は除く）
export function needlesFromPrivateConfig({ projectsConfig, central }) {
  const projects = projectsConfig?.projects ?? [];
  const words = [
    ...projects.flatMap((p) => [p.project, ...String(p.repo ?? '').split('/')]),
    projectsConfig?.project_owner,
    central?.contact_email,
  ];
  return [...new Set(words.filter((w) => typeof w === 'string' && w.length > 0))];
}
