import { guarded, okResult, expect, githubHeaders } from './result.mjs';

export const LIST_URL = 'https://api.github.com/repos/psf/advisory-database/contents/advisories/python';
export const OSV_GIT_BASE = 'https://osv-vulnerabilities.storage.googleapis.com/GIT';
const FILE_PATTERN = /^(PSF-\d{4}-\d+)\.json$/;
// GitHub の contents API は1,000件で切れる
const LISTING_LIMIT = 1000;
const MAX_MISSING_RATIO = 0.05;

// PSF の ID の一覧は GitHub から、影響版は OSV の個別の記録から取る（GitHub の元データには版の一覧がない）。
// 影響タグは GitHub 側の変更なしに増えるので、毎回全件を順に取る。404（OSV への反映待ち）は missing に入れて続ける
export const collect = ({ http, env = {} }) => guarded(async () => {
  const listing = await http.getJson(LIST_URL, { headers: githubHeaders(env, LIST_URL) });
  expect(Array.isArray(listing), 'python-psf: 一覧が配列ではありません');
  expect(listing.length < LISTING_LIMIT, 'python-psf: 一覧が1,000件に達しました（Git Trees API への切り替えが必要です）');
  const ids = listing.filter((f) => f.type === 'file' && FILE_PATTERN.test(f.name)).map((f) => f.name.match(FILE_PATTERN)[1]).sort();
  expect(ids.length > 0, 'python-psf: PSF-*.json が1件もありません');
  const records = [];
  const missing = [];
  for (const id of ids) {
    let raw;
    try {
      raw = await http.getJson(`${OSV_GIT_BASE}/${id}.json`);
    } catch (error) {
      if (error.http_status !== 404) throw error;
      missing.push(id);
      continue;
    }
    expect(raw?.id === id && Array.isArray(raw.affected), `python-psf: ${id} の記録が不正です`);
    records.push(raw);
  }
  expect(missing.length <= ids.length * MAX_MISSING_RATIO, `python-psf: OSV の記録が ${missing.length}/${ids.length} 件で見つかりません（取得元の障害の可能性）`);
  return okResult(records, { missing });
});
