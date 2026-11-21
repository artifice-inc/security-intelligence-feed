import { readFileSync, readdirSync, existsSync, statSync } from 'node:fs';
import path from 'node:path';
import YAML from 'yaml';
import { sha256Hex } from '../lib/hash.mjs';
import { validate } from '../lib/schema.mjs';
import { checkRequirementsPinned } from './requirements.mjs';

// 作業ツリーを読むだけの純粋な処理。ネットワーク通信も書き込みもしない（中央とローカルで共用）
export const DEFAULT_LOCKFILES = [
  'package-lock.json', 'pnpm-lock.yaml', 'yarn.lock', 'composer.lock', 'poetry.lock', 'uv.lock', 'Pipfile.lock', 'pdm.lock', 'requirements.txt',
];

// lockfile の名前 → OSV のエコシステム。表にない名前は null（対応していない形式。黙って npm 扱いにしない）
export const LOCKFILE_ECOSYSTEM = {
  'package-lock.json': 'npm', 'pnpm-lock.yaml': 'npm', 'yarn.lock': 'npm', 'composer.lock': 'Packagist',
  'poetry.lock': 'PyPI', 'uv.lock': 'PyPI', 'Pipfile.lock': 'PyPI', 'pdm.lock': 'PyPI',
};
// requirements 形式は名前を問わない（stack.yml の lockfiles で requirements/prod.txt なども指定できる）
export const isRequirementsFile = (file) => path.posix.basename(file).endsWith('.txt');
export const ecosystemOfLockfile = (file) => LOCKFILE_ECOSYSTEM[path.posix.basename(file)] ?? (isRequirementsFile(file) ? 'PyPI' : null);
export const STACK_PATH = '.security/stack.yml';
const EXACT_VERSION = /^v?(\d+\.\d+\.\d+)$/;
const SAFE_RELATIVE_PATH = /^[A-Za-z0-9_.@/-]+$/;

const KIND_BY_NAME = {
  'package.json': 'package-json', 'composer.json': 'composer-json', '.nvmrc': 'nvmrc', '.node-version': 'node-version',
  'package-lock.json': 'lockfile', 'pnpm-lock.yaml': 'lockfile', 'yarn.lock': 'lockfile', 'composer.lock': 'lockfile',
  'poetry.lock': 'lockfile', 'uv.lock': 'lockfile', 'Pipfile.lock': 'lockfile', 'pdm.lock': 'lockfile',
  'pyproject.toml': 'pyproject', 'Pipfile': 'pipfile', '.python-version': 'python-version',
};

// stack.yml の lockfiles に書かれたパスは外部入力なので、作業ツリーの外を指せないようにする
export function isSafeRelativePath(file) {
  return SAFE_RELATIVE_PATH.test(file) && !file.startsWith('/') && !file.split('/').some((part) => part === '..' || part === '');
}

// lockfile と同じフォルダのマニフェストも検出の手がかりにする（サブフォルダ構成の案件向け）
export const SIBLING_MANIFESTS = ['composer.json', 'package.json', 'pyproject.toml', 'Pipfile', '.python-version'];
export function siblingManifests(lockfiles) {
  const dirs = [...new Set(lockfiles.map((f) => path.posix.dirname(f)).filter((d) => d !== '.'))].sort();
  return dirs.flatMap((dir) => SIBLING_MANIFESTS.map((name) => `${dir}/${name}`));
}

// 検出の手がかりが何もない（lockfile もマニフェスト類もない）インベントリ。照合は「影響なし」にできない
const CLUE_KINDS = new Set([
  'lockfile', 'package-json', 'composer-json', 'nvmrc', 'node-version', 'dockerfile', 'stack',
  'pyproject', 'pipfile', 'python-version', 'requirements-unpinned',
]);
export const hasNoMaterial = (inventory) => inventory.lockfiles.length === 0 && !inventory.files.some((f) => CLUE_KINDS.has(f.kind));

const readText = (root, file) => {
  const full = path.join(root, file);
  return existsSync(full) && statSync(full).isFile() ? readFileSync(full, 'utf8') : null;
};

// constraintOnly: engines / require のように「制約」でしかないものは、完全一致の形でも version にしない
function classify(text, source, constraintOnly = false) {
  const value = String(text ?? '').trim();
  if (!value) return null;
  const exact = constraintOnly ? null : EXACT_VERSION.exec(value);
  return exact ? { version: exact[1], constraint: null, source } : { version: null, constraint: value, source };
}

function dockerfileTag(root, image) {
  const pattern = new RegExp(`^\\s*FROM\\s+(?:--platform=\\S+\\s+)?(?:docker\\.io/)?(?:library/)?${image}:([^\\s]+)`, 'im');
  for (const name of readdirSync(root).filter((n) => /^Dockerfile/.test(n)).sort()) {
    const tag = pattern.exec(readText(root, name) ?? '')?.[1];
    if (!tag || tag.includes('$')) continue;
    const numeric = /^v?(\d+(?:\.\d+){0,2})/.exec(tag)?.[1];
    if (numeric) return { text: numeric, source: name };
  }
  return null;
}

// 最終ステージ（最後の FROM）が python:<タグ> のものだけを手がかりにする（ビルド用ステージの python を本番の版にしない）。
// 戻り値は { text, source, constraintOnly? }。正式版（x.y.z）の完全一致だけ版になり、3.12-slim・rc・b は制約。複数の Dockerfile で食い違えば制約
const PYTHON_FROM = /^\s*FROM\s+(?:--platform=\S+\s+)?(?:docker\.io\/)?(?:library\/)?python:(\S+)/i;
export function dockerfilePythonTag(root) {
  const found = [];
  for (const name of readdirSync(root).filter((n) => /^Dockerfile/.test(n)).sort()) {
    const froms = (readText(root, name) ?? '').split('\n').filter((line) => /^\s*FROM\s/i.test(line));
    const tag = PYTHON_FROM.exec(froms.at(-1) ?? '')?.[1];
    if (!tag || tag.includes('$')) continue;
    const base = tag.split('-')[0];
    if (/^\d+\.\d+\.\d+$/.test(base)) found.push({ text: base, source: name });
    else found.push({ text: /^\d+\.\d+$/.test(base) ? base : tag, source: name, constraintOnly: true });
  }
  const texts = [...new Set(found.map((f) => f.text))];
  if (texts.length > 1) return { text: `複数の Dockerfile で版が異なります（${texts.join('、')}）`, source: found[0].source, constraintOnly: true };
  return found[0] ?? null;
}

function readJson(root, file, problems) {
  const text = readText(root, file);
  if (text === null) return null;
  try { return JSON.parse(text); } catch { problems.push({ kind: 'inventory', target: file, message: 'JSON として解析できません' }); return null; }
}

const firstOf = (candidates) => candidates.map((c) => c && classify(c.text, c.source, c.constraintOnly)).find(Boolean)
  ?? { version: null, constraint: null, source: null };

export function detectStack(root, { lockfileOverride = null } = {}) {
  const problems = [];
  let stack = null;
  const stackText = readText(root, STACK_PATH);
  if (stackText !== null) {
    try {
      const parsed = YAML.parse(stackText) ?? {};
      if (validate('stack', parsed).ok) stack = parsed;
      else problems.push({ kind: 'inventory', target: STACK_PATH, message: 'stack.yml がスキーマに合いません（無視して自動検出で補います）' });
    } catch { problems.push({ kind: 'inventory', target: STACK_PATH, message: 'stack.yml を YAML として解析できません' }); }
  }

  const requested = stack?.lockfiles ?? lockfileOverride ?? DEFAULT_LOCKFILES;
  const explicit = Boolean(stack?.lockfiles ?? lockfileOverride);
  const lockfiles = [];
  const unpinned = []; // 版を固定していない requirements。スキャナには渡さず、files にだけ残す
  for (const file of requested) {
    if (!isSafeRelativePath(file)) { problems.push({ kind: 'lockfile', target: file, message: 'lockfile のパスが不正です（作業ツリー外は指定できません）' }); continue; }
    if (readText(root, file) === null) { if (explicit) problems.push({ kind: 'lockfile', target: file, message: '指定された lockfile が見つかりません' }); continue; }
    // 行番号を伴うエラーは detectProject が出す（中央とローカルで同じ経路にするため problems には積まない）
    if (isRequirementsFile(file) && !checkRequirementsPinned(readText(root, file)).ok) unpinned.push(file);
    else lockfiles.push(file);
  }

  lockfiles.sort();
  unpinned.sort();
  const siblings = siblingManifests(lockfiles);
  const files = [...new Set([
    ...lockfiles, ...unpinned, STACK_PATH, 'package.json', 'composer.json', '.nvmrc', '.node-version', 'pyproject.toml', 'Pipfile', '.python-version', ...siblings,
    ...readdirSync(root).filter((n) => /^Dockerfile/.test(n)),
  ])].filter((file) => readText(root, file) !== null).sort().map((file) => ({
    path: file, sha256: sha256Hex(readFileSync(path.join(root, file))),
    kind: lockfiles.includes(file) ? 'lockfile' : unpinned.includes(file) ? 'requirements-unpinned' : file === STACK_PATH ? 'stack' : file.startsWith('Dockerfile') ? 'dockerfile' : KIND_BY_NAME[path.posix.basename(file)],
  }));

  // 直下を優先し、なければ lockfile のフォルダ順に最初に見つかったものを使う
  const manifest = (name) => [name, ...siblings.filter((f) => f.endsWith(`/${name}`))].find((f) => readText(root, f) !== null) ?? name;
  const packagePath = manifest('package.json');
  const composerPath = manifest('composer.json');
  const packageJson = readJson(root, packagePath, problems);
  const composerJson = readJson(root, composerPath, problems);
  const nodeDocker = dockerfileTag(root, 'node');
  const phpDocker = dockerfileTag(root, 'php');
  const pythonDocker = dockerfilePythonTag(root);
  const pythonFirstLine = readText(root, manifest('.python-version'))?.split('\n')[0];
  const runtimes = {
    node: firstOf([
      stack?.runtimes?.node && { text: stack.runtimes.node, source: STACK_PATH },
      readText(root, '.nvmrc') && { text: readText(root, '.nvmrc').split('\n')[0], source: '.nvmrc' },
      readText(root, '.node-version') && { text: readText(root, '.node-version').split('\n')[0], source: '.node-version' },
      nodeDocker,
      packageJson?.engines?.node && { text: packageJson.engines.node, source: packagePath, constraintOnly: true },
    ]),
    php: firstOf([
      stack?.runtimes?.php && { text: stack.runtimes.php, source: STACK_PATH },
      phpDocker,
      composerJson?.config?.platform?.php && { text: composerJson.config.platform.php, source: composerPath },
      composerJson?.require?.php && { text: composerJson.require.php, source: composerPath, constraintOnly: true },
    ]),
  };
  // Python の手がかりがある案件にだけ python のキーを作る（ない案件の inventory と export の runtimes_detected を変えないため）
  const pythonClue = lockfiles.some((f) => ecosystemOfLockfile(f) === 'PyPI') || unpinned.length > 0 || stack?.runtimes?.python
    || files.some((f) => ['pyproject', 'pipfile', 'python-version'].includes(f.kind)) || pythonDocker;
  if (pythonClue) {
    runtimes.python = firstOf([
      stack?.runtimes?.python && { text: stack.runtimes.python, source: STACK_PATH },
      pythonFirstLine && { text: pythonFirstLine, source: manifest('.python-version') },
      pythonDocker,
    ]);
  }
  return {
    files, lockfiles, runtimes, problems,
    stack: stack ? { monitor_ref: stack.monitor_ref ?? null, exposure: stack.exposure ?? null, os: stack.os ?? null, owner: stack.owner ?? null, kernel: stack.kernel ?? null } : null,
  };
}
