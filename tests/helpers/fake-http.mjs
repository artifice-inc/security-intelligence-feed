import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const FIXTURE_DIR = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'fixtures');
export const fixture = (name) => readFileSync(path.join(FIXTURE_DIR, name));
export const fixtureText = (name) => fixture(name).toString('utf8');

// URL → 本文（Buffer / 文字列 / オブジェクト / Error）の対応表から http 互換のフェイクを作る
export function fakeHttp(routes) {
  const requested = [];
  const lookup = (url) => {
    requested.push(url);
    const entry = routes[url] ?? routes[url.split('?')[0]];
    if (entry === undefined) throw Object.assign(new Error(`フェイク未登録の URL: ${url}`), { kind: 'network', http_status: null });
    if (entry instanceof Error) throw entry;
    return entry;
  };
  const toText = (entry) => (Buffer.isBuffer(entry) ? entry.toString('utf8') : typeof entry === 'string' ? entry : JSON.stringify(entry));
  return {
    requested,
    getText: async (url) => toText(lookup(url)),
    getJson: async (url) => JSON.parse(toText(lookup(url))),
    getBuffer: async (url) => Buffer.from(lookup(url)),
    request: async (url) => {
      const entry = lookup(url);
      return { headers: { get: () => entry?.link ?? null }, json: async () => JSON.parse(toText(entry?.body ?? entry)) };
    },
  };
}
