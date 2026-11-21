const HEARTBEAT_TIMEOUT_MS = 10_000;
const HEARTBEAT_RETRIES = 3;

// 完了通知。送るのは本体が空のリクエストだけで、URL はログにも例外メッセージにも出さない
export async function sendHeartbeat({ url, fetchImpl = globalThis.fetch }) {
  if (!url) return { ok: false, error: 'HEALTHCHECK_PING_URL が未設定です' };
  for (let attempt = 0; attempt < HEARTBEAT_RETRIES; attempt += 1) {
    try {
      const response = await fetchImpl(url, { method: 'GET', signal: AbortSignal.timeout(HEARTBEAT_TIMEOUT_MS) });
      if (response.ok) return { ok: true };
    } catch { /* 再試行する。理由には URL が含まれうるので保持しない */ }
  }
  return { ok: false, error: '完了通知に失敗しました' };
}
