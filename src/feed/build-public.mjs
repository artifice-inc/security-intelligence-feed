import path from 'node:path';
import { cpSync, existsSync, lstatSync, mkdirSync, readdirSync, readFileSync } from 'node:fs';
import { readJsonIfExists, writeJson } from '../publish/central-data.mjs';
import { loadSchedule, loadThresholds } from '../lib/config.mjs';
import { validateFeed } from './validate-feed.mjs';
import { inspectTree, needlesFromPrivateConfig, maskPath, SECRET_PATTERNS } from './inspect-tree.mjs';
import { buildFeedHealth } from './health.mjs';
import { COMMON_DATA_FILES, FEED_FORMAT_VERSION, NEVER_FETCHED_AT, PUBLIC_ADVISORY_SOURCES } from './definition.mjs';

// 公開側の main に載せるもの（許可リスト）。config/ は PRIVATE_CONFIG_FILES 以外
const MAIN_ITEMS = ['src', 'tests', 'schemas', 'plugins', 'package.json', 'package-lock.json', '.nvmrc', '.gitignore', 'config'];
const PRIVATE_CONFIG_FILES = ['projects.yaml', 'central.json', 'feed-code.json'];
const PRIVATE_TESTS_DIR = path.join('tests', 'private');

const isExcluded = (rel) => rel === PRIVATE_TESTS_DIR || rel.startsWith(`${PRIVATE_TESTS_DIR}${path.sep}`)
  || (path.dirname(rel) === 'config' && PRIVATE_CONFIG_FILES.includes(path.basename(rel)));

// コピーの前に lstat でたどり、通常のファイルとディレクトリ以外（シンボリックリンクなど）を返す
function findIrregular(root, rel) {
  const full = path.join(root, rel);
  let stat;
  try { stat = lstatSync(full); } catch { return []; } // 許可リストのうち存在しない項目は飛ばす
  if (stat.isSymbolicLink() || !(stat.isFile() || stat.isDirectory())) return [rel];
  if (!stat.isDirectory()) return [];
  return readdirSync(full).flatMap((name) => findIrregular(root, path.join(rel, name)));
}

const toDisplay = (file, needles) => maskPath(file, needles, Object.values(SECRET_PATTERNS));

// 今の data/ から公開フィードの初期状態を作る。kev・epss-high は空（最初の run-collect で埋まる）
function buildFeedData({ rootDir, feedDataDir, now }) {
  const dataDir = path.join(rootDir, 'data');
  for (const entry of COMMON_DATA_FILES) {
    const from = path.join(dataDir, entry);
    if (!existsSync(from)) continue;
    if (entry === 'advisories/') {
      mkdirSync(path.join(feedDataDir, 'advisories'), { recursive: true });
      for (const name of readdirSync(from).filter((n) => n.endsWith('.json'))) {
        const advisory = JSON.parse(readFileSync(path.join(from, name), 'utf8'));
        if ((advisory.sources ?? []).every((s) => PUBLIC_ADVISORY_SOURCES.includes(s.name))) writeJson(feedDataDir, `advisories/${name}`, advisory);
      }
    } else cpSync(from, path.join(feedDataDir, entry), { recursive: true });
  }
  const previous = readJsonIfExists(path.join(dataDir, 'health.json'));
  const base = buildFeedHealth({ previous, now, startedAt: now, status: previous?.last_run?.status ?? 'partial', schedule: loadSchedule(rootDir) });
  // 実行の記録は今回の run-collect のものではないので、前回の値のまま残す。kev・epss は空の一覧なので旧データの成功の記録を引き継がない
  const { kev: _kev, epss: _epss, ...sources } = base.sources;
  writeJson(feedDataDir, 'health.json', { ...base, sources, last_run: previous?.last_run ?? base.last_run, last_success_at: previous?.last_success_at ?? null });
  writeJson(feedDataDir, 'feed-format.json', { format_version: FEED_FORMAT_VERSION });
  writeJson(feedDataDir, 'kev.json', { fetched_at: NEVER_FETCHED_AT, ok: false, catalog_version: null, records: [] });
  writeJson(feedDataDir, 'epss-high.json', { fetched_at: NEVER_FETCHED_AT, ok: false, model_version: null, score_date: null, threshold: loadThresholds(rootDir).epss_percentile_p1, records: [] });
}

// 公開候補を <outDir>/main と <outDir>/feed/data に作り、検査する。Git の操作はしない。戻り値の problems が空なら通過
export function buildPublic({ rootDir, outDir, projectsConfig, central, now }) {
  if (existsSync(outDir) && readdirSync(outDir).length > 0) return { problems: ['出力先が空のディレクトリではありません'] };
  const needles = needlesFromPrivateConfig({ projectsConfig, central });
  const mainDir = path.join(outDir, 'main');
  const feedDataDir = path.join(outDir, 'feed', 'data');

  const irregular = MAIN_ITEMS.flatMap((item) => findIrregular(rootDir, item));
  const templateRoot = path.join(rootDir, 'templates', 'public');
  irregular.push(...findIrregular(templateRoot, '.'));
  if (irregular.length > 0) return { problems: irregular.map((rel) => `${toDisplay(rel, needles)}: シンボリックリンクなど通常でないファイルがあります`) };

  mkdirSync(mainDir, { recursive: true });
  for (const item of MAIN_ITEMS.filter((i) => existsSync(path.join(rootDir, i)))) {
    cpSync(path.join(rootDir, item), path.join(mainDir, item), { recursive: true, filter: (src) => !isExcluded(path.relative(rootDir, src)) });
  }
  if (existsSync(templateRoot)) cpSync(templateRoot, mainDir, { recursive: true });
  mkdirSync(feedDataDir, { recursive: true });
  buildFeedData({ rootDir, feedDataDir, now });

  const problems = [];
  for (const v of validateFeed(feedDataDir)) problems.push(`feed/data/${toDisplay(v.file, needles)}: ${v.message}`);
  for (const [label, dir] of [['main', mainDir], ['feed', path.join(outDir, 'feed')]]) {
    for (const f of inspectTree({ dir, needles })) problems.push(`${label}/${f.file}: ${f.patternName ?? `案件情報の語（${f.needleIndex + 1}番目）`}に一致`);
  }
  return { problems };
}
