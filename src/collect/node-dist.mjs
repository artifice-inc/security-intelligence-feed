import { guarded, okResult, expect } from './result.mjs';

export const DIST_URL = 'https://nodejs.org/dist/index.json';
const RELEASE_VERSION = /^v\d+\.\d+\.\d+$/;

export const collect = ({ http }) => guarded(async () => {
  const data = await http.getJson(DIST_URL);
  expect(Array.isArray(data) && data.length > 0, 'node-dist: 配列ではありません');
  // 試験版（v27.0.0-alpha.0.0.0 など）は一覧に混ざるので、失敗にせず捨てる。系列の最新版に紛れ込まないようにもなる
  const records = data.filter((r) => RELEASE_VERSION.test(r?.version ?? ''))
    .map((r) => ({ version: r.version, date: r.date ?? null, lts: r.lts || false, security: r.security === true }));
  expect(records.length > 0, 'node-dist: 正式版が1件もありません');
  return okResult(records);
});
