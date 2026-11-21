import { createWriteStream } from 'node:fs';
import { Readable } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import { loadCentral, loadThresholds } from './config.mjs';

// 収集処理で通信してよいホスト（これ以外は例外にする）
export const COLLECT_HOSTS = [
  'www.cisa.gov', 'epss.empiricalsecurity.com', 'api.github.com', 'raw.githubusercontent.com',
  'nodejs.org', 'www.php.net', 'endoflife.date', 'www.jpcert.or.jp', 'www.ipa.go.jp', 'jvn.jp',
  'packagist.org', 'explore.alas.aws.amazon.com', 'www.python.org',
  'aws.amazon.com',
  'osv-vulnerabilities.storage.googleapis.com', // PSF の OSV の個別の記録（収集器の http で取る。OSV_HOSTS は変えない）
];
// 認証ヘッダーを付けてよい唯一のオリジン（ホスト名だけでなくスキーム・ポートも含めて比べる）
export const AUTH_ORIGIN = 'https://api.github.com';
export const OSV_HOSTS = ['osv-vulnerabilities.storage.googleapis.com'];

const MAX_REDIRECTS = 5;
const RETRY_BASE_MS = 500;
const sleepMs = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

// 外側の signal が中断されたらすぐ抜ける待機（signal を渡さない呼び出しでは使わない）
function sleepAbortable(sleep, ms, signal) {
  if (signal.aborted) return Promise.resolve();
  return new Promise((resolve) => {
    const done = () => { signal.removeEventListener('abort', done); resolve(); };
    signal.addEventListener('abort', done, { once: true });
    sleep(ms).then(done, done);
  });
}

export class HttpError extends Error {
  constructor(kind, message, status = null) {
    super(message);
    this.kind = kind;
    this.http_status = status;
  }
}

function assertAllowed(url, allowedHosts) {
  const parsed = new URL(url);
  if (parsed.protocol !== 'https:') throw new HttpError('forbidden_host', `https 以外は許可しません: ${url}`);
  if (!allowedHosts.includes(parsed.hostname)) {
    throw new HttpError('forbidden_host', `許可リスト外のホストです: ${parsed.hostname}`);
  }
}

// リダイレクト先を含め、オリジンが違う要求からは Authorization を外す（トークンを別のサーバーへ送らない）
function headersFor(url, headers) {
  if (new URL(url).origin === AUTH_ORIGIN) return headers;
  return Object.fromEntries(Object.entries(headers).filter(([name]) => name.toLowerCase() !== 'authorization'));
}

export function createHttp({
  allowedHosts, userAgent, fetchImpl = globalThis.fetch, sleep = sleepMs,
  timeoutMs, retries, downloadTimeoutMs, downloadRetries,
} = {}) {
  const thresholds = loadThresholds();
  const ua = userAgent ?? loadCentral().user_agent;
  const timeout = timeoutMs ?? thresholds.http_timeout_ms;
  const maxRetries = retries ?? thresholds.http_retries;
  // 大きな DB の取得は本体の受信まで含めて長くかかる（回線の遅い端末向け）。通常の API 呼び出しの上限とは分ける
  const longTimeout = downloadTimeoutMs ?? thresholds.download_timeout_ms;
  const longRetries = downloadRetries ?? thresholds.download_retries;
  const isTimeout = (error) => error?.name === 'TimeoutError' || /aborted due to timeout/i.test(error?.message ?? '');

  // リダイレクトも1回ずつ許可リストを検査する（許可外ホストへ誘導されないため）
  async function fetchOnce(url, headers, timeout, signal) {
    let current = url;
    for (let hop = 0; hop <= MAX_REDIRECTS; hop += 1) {
      assertAllowed(current, allowedHosts);
      const response = await fetchImpl(current, {
        method: 'GET', redirect: 'manual', headers: { 'User-Agent': ua, ...headersFor(current, headers) },
        signal: signal ? AbortSignal.any([AbortSignal.timeout(timeout), signal]) : AbortSignal.timeout(timeout),
      });
      if (response.status >= 300 && response.status < 400 && response.headers.get('location')) {
        current = new URL(response.headers.get('location'), current).toString();
        continue;
      }
      return response;
    }
    throw new HttpError('too_many_redirects', `リダイレクトが多すぎます: ${url}`);
  }

  async function request(url, { headers = {}, timeoutMs: requestTimeout = timeout, retries: requestRetries = maxRetries, retryOnTimeout = true, signal } = {}) {
    assertAllowed(url, allowedHosts);
    let lastError;
    for (let attempt = 0; attempt < requestRetries; attempt += 1) {
      if (attempt > 0) await (signal ? sleepAbortable(sleep, RETRY_BASE_MS * 2 ** (attempt - 1), signal) : sleep(RETRY_BASE_MS * 2 ** (attempt - 1)));
      if (signal?.aborted) throw new HttpError('timeout', `中断されました: ${url}`);
      try {
        const response = await fetchOnce(url, headers, requestTimeout, signal);
        if (response.status >= 500 || response.status === 429) {
          lastError = new HttpError('http_status', `HTTP ${response.status}: ${url}`, response.status);
          continue;
        }
        if (!response.ok) throw new HttpError('http_status', `HTTP ${response.status}: ${url}`, response.status);
        return response;
      } catch (error) {
        if (signal?.aborted) throw new HttpError('timeout', `中断されました: ${url}`);
        if (error instanceof HttpError && (error.kind === 'forbidden_host' || (error.http_status !== null && error.http_status < 500))) throw error;
        lastError = error instanceof HttpError ? error : new HttpError(isTimeout(error) ? 'timeout' : 'network', `${error.message}: ${url}`);
        if (!retryOnTimeout && lastError.kind === 'timeout') break; // 遅い回線で上限まで待った後に同じ待ち時間を繰り返さない
      }
    }
    throw lastError;
  }

  return {
    request,
    getText: async (url, options) => (await request(url, options)).text(),
    getJson: async (url, options) => (await request(url, options)).json(),
    // 大きな zip をメモリに載せず、ファイルへ直接書き出す
    // 受信の途中で時間切れになった場合も、呼び出し側が既存のファイルを残して失敗として扱う
    download: async (url, destPath) => {
      const response = await request(url, { timeoutMs: longTimeout, retries: longRetries, retryOnTimeout: false });
      await pipeline(Readable.fromWeb(response.body), createWriteStream(destPath));
    },
    getBuffer: async (url, options) => Buffer.from(await (await request(url, options)).arrayBuffer()),
  };
}
