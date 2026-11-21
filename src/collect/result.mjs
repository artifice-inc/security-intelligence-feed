import { AUTH_ORIGIN } from '../lib/http.mjs';
// 収集モジュール共通の結果の組み立て。例外は握りつぶさず ok:false に変換する（指示書 §4）
export const okResult = (records, extra = {}) => ({ ok: true, records, ...extra });

export function failResult(error) {
  return {
    ok: false,
    records: [],
    error: { kind: error.kind ?? 'parse', message: String(error.message ?? error), http_status: error.http_status ?? null },
  };
}

export async function guarded(work) {
  try {
    return await work();
  } catch (error) {
    return failResult(error);
  }
}

export class ParseError extends Error {
  constructor(message) {
    super(message);
    this.kind = 'parse';
  }
}

export function expect(condition, message) {
  if (!condition) throw new ParseError(message);
}

// 認証は url のオリジンが https://api.github.com のときだけ付ける（url がなければ付けない）
export const githubHeaders = (env = {}, url = null) => ({
  Accept: 'application/vnd.github+json',
  ...(env.GITHUB_TOKEN && url && new URL(url).origin === AUTH_ORIGIN ? { Authorization: `Bearer ${env.GITHUB_TOKEN}` } : {}),
});
