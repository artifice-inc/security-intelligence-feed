import { execFile } from 'node:child_process';
import { createReadStream } from 'node:fs';
import { mkdir, rename, rm, readFile, writeFile, stat } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { promisify } from 'node:util';
import path from 'node:path';
import { createHttp, OSV_HOSTS } from '../lib/http.mjs';
import { loadThresholds } from '../lib/config.mjs';
import { hoursBetween, toIso } from '../lib/time.mjs';

const run = promisify(execFile);
export const OSV_BASE = 'https://osv-vulnerabilities.storage.googleapis.com';
export const ECOSYSTEMS = ['npm', 'Packagist', 'PyPI'];
const ID_PATTERN = /^[A-Za-z0-9._-]+$/;
const MAX_RECORD_BYTES = 20 * 1024 * 1024;

export const osvHttp = (options = {}) => createHttp({ allowedHosts: OSV_HOSTS, ...options });
// 固定版 v2.7.0 が読む構成: {dir}/osv-scalibr/<eco>/all.zip。公式 offline-mode.md の osv-scanner/ は古い記述で、
// 置き場所を誤っても OSV-Scanner はエラーにせず「脆弱性なし」を返すため、版を上げたら test-offline で必ず確かめる
export const zipPathOf = (dest, eco) => path.join(dest, 'osv-scalibr', eco, 'all.zip');

async function sha256OfFile(file) {
  const hash = createHash('sha256');
  for await (const chunk of createReadStream(file)) hash.update(chunk);
  return hash.digest('hex');
}

export async function verifyZip(file) {
  await run('unzip', ['-tq', file], { maxBuffer: 1024 * 1024 });
}

// 引数はエコシステム名と置き場所だけ。lockfile や作業ツリーは受け取らない
export async function fetchOsvDb({ ecosystems, dest, http = osvHttp(), now = new Date() }) {
  await mkdir(dest, { recursive: true });
  const meta = await readMeta(dest);
  const outcomes = {};
  for (const eco of ecosystems) {
    if (!ECOSYSTEMS.includes(eco)) throw new Error(`未対応のエコシステムです: ${eco}`);
    const target = zipPathOf(dest, eco);
    const temp = `${target}.download`;
    try {
      await mkdir(path.dirname(target), { recursive: true });
      await http.download(`${OSV_BASE}/${eco}/all.zip`, temp);
      await verifyZip(temp);
      const sha256 = await sha256OfFile(temp);
      await rename(temp, target); // 同一ファイルシステム内の原子的な置換。失敗時は既存の DB が残る
      meta[eco] = { fetched_at: toIso(now), sha256 };
      outcomes[eco] = { ok: true };
    } catch (error) {
      await rm(temp, { force: true });
      outcomes[eco] = { ok: false, error: { kind: error.kind ?? 'osv_db', message: error.message, http_status: error.http_status ?? null } };
    }
  }
  await writeFile(path.join(dest, 'meta.json'), `${JSON.stringify(meta, null, 2)}\n`);
  return { meta, outcomes };
}

export async function readMeta(dest) {
  try {
    return JSON.parse(await readFile(path.join(dest, 'meta.json'), 'utf8'));
  } catch {
    return {};
  }
}

// ローカルの鮮度判定: 12時間で更新、取得失敗でも72時間以内なら警告付きで使う
export function dbFreshness(entry, now, thresholds = loadThresholds()) {
  if (!entry?.fetched_at) return { state: 'unavailable', needs_refresh: true };
  const age = hoursBetween(entry.fetched_at, now);
  return {
    state: age <= thresholds.osv_db_refresh_hours ? 'fresh' : age <= thresholds.osv_db_max_age_hours ? 'stale_warn' : 'unavailable',
    needs_refresh: age > thresholds.osv_db_refresh_hours,
  };
}

export async function dbFileExists(dest, eco) {
  try { return (await stat(zipPathOf(dest, eco))).isFile(); } catch { return false; }
}

// 照合で見つかった OSV ID のレコードだけを zip から取り出す（§5.1 ②）
export async function readOsvRecord(zipFile, id) {
  if (!ID_PATTERN.test(id)) throw new Error(`OSV ID の形式が不正です: ${id}`);
  try {
    const { stdout } = await run('unzip', ['-p', zipFile, `${id}.json`], { maxBuffer: MAX_RECORD_BYTES });
    return JSON.parse(stdout);
  } catch (error) {
    if (error.code === 11) return null; // unzip: 該当ファイルなし
    throw error;
  }
}
