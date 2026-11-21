import { guarded, okResult, expect } from './result.mjs';

export const RELEASES_URL = 'https://www.python.org/api/v2/downloads/release/?is_published=true';
const NAME_PATTERN = /^Python (\d+\.\d+\.\d+)$/;

// 正式版（rc・a・b を除く）の版とリリース日。修正版の算出と、版の実在確認に使う
export const collect = ({ http }) => guarded(async () => {
  const data = await http.getJson(RELEASES_URL);
  expect(Array.isArray(data), 'python-releases: 配列ではありません');
  const records = data
    .filter((r) => r.pre_release === false && NAME_PATTERN.test(r.name ?? ''))
    .map((r) => ({ version: r.name.match(NAME_PATTERN)[1], date: r.release_date ?? null }));
  expect(records.some((r) => r.version.startsWith('3.')), 'python-releases: 3系の正式版が1件もありません');
  return okResult(records);
});
