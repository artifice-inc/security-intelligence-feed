import { execFile, spawn } from 'node:child_process';
import { createReadStream } from 'node:fs';
import { mkdir, rename, rm, readFile, writeFile, stat, open } from 'node:fs/promises';
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

const LOCAL_HEADER = Buffer.from([0x50, 0x4b, 0x03, 0x04]);
const EOCD_SIGNATURE = Buffer.from([0x50, 0x4b, 0x05, 0x06]);
const EOCD_FIXED_BYTES = 22;
const EOCD_SEARCH_BYTES = EOCD_FIXED_BYTES + 0xffff; // コメント長の上限まで

// 末尾から探した終端レコードが、コメント長を含めてちょうどファイルの末尾に収まるか
function endsWithEocd(tail) {
  for (let at = tail.lastIndexOf(EOCD_SIGNATURE); at >= 0; at = at === 0 ? -1 : tail.lastIndexOf(EOCD_SIGNATURE, at - 1)) {
    if (at + EOCD_FIXED_BYTES <= tail.length && at + EOCD_FIXED_BYTES + tail.readUInt16LE(at + 20) === tail.length) return true;
  }
  return false;
}

// 壊れた（途中で切れた）ダウンロードの検出が目的。悪意をもって作られた ZIP は想定しない（中央ディレクトリの中身は調べない）
async function assertZipShape(file) {
  const handle = await open(file, 'r');
  try {
    const { size } = await handle.stat();
    const head = Buffer.alloc(LOCAL_HEADER.length);
    await handle.read(head, 0, head.length, 0);
    const tailLength = Math.min(size, EOCD_SEARCH_BYTES);
    const tail = Buffer.alloc(tailLength);
    await handle.read(tail, 0, tailLength, size - tailLength);
    const found = endsWithEocd(tail);
    if (!head.equals(LOCAL_HEADER) || !found) throw new Error('ZIP ではないか、途中で切れています');
  } finally {
    await handle.close();
  }
}

// Windows は OS 標準の tar.exe（絶対パス。案件のフォルダから探さない）で全エントリを読み、CRC を確かめる
function extractAllWithTar(file, { env, spawnFn }) {
  if (!env.SystemRoot) return Promise.reject(new Error('SystemRoot が未設定のため tar.exe を起動できません'));
  const tar = path.win32.join(env.SystemRoot, 'System32', 'tar.exe');
  return new Promise((resolve, reject) => {
    const child = spawnFn(tar, ['-xOf', file], { stdio: ['ignore', 'ignore', 'pipe'], windowsHide: true });
    let stderr = '';
    child.stderr.on('data', (chunk) => { if (stderr.length < 4096) stderr += chunk; });
    child.on('error', reject);
    child.on('close', (code) => (code === 0 ? resolve() : reject(new Error(`ZIP の検証に失敗しました（tar.exe 終了コード${code}）: ${stderr.trim()}`))));
  });
}

export async function verifyZip(file, { platform = process.platform, env = process.env, spawnFn = spawn } = {}) {
  if (platform !== 'win32') { await run('unzip', ['-tq', file], { maxBuffer: 1024 * 1024 }); return; }
  await assertZipShape(file);
  await extractAllWithTar(file, { env, spawnFn });
}

// 引数はエコシステム名と置き場所だけ。lockfile や作業ツリーは受け取らない
export async function fetchOsvDb({ ecosystems, dest, http = osvHttp(), now = new Date(), verify = verifyZip }) {
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
      await verify(temp);
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
