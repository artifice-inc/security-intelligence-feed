import { guarded, okResult, expect } from './result.mjs';

const BASE_URL = 'https://packagist.org/api/security-advisories/';

// 案件のパッケージ名を送る packages[] は使わない（D5）。updatedSince による取得だけ
export const urlFor = (updatedSince) => `${BASE_URL}?updatedSince=${Number(updatedSince)}`;

export const hasGhsa = (record) =>
  /^GHSA-/.test(record.remoteId ?? '') || (record.sources ?? []).some((s) => /^GHSA-/.test(s.remoteId ?? ''));

// TODO(2026-10-25): 要確認 — 全件取得（updatedSince=0）の上限とページ送りは公式文書に記載がない。応答は1回で受ける
export const collect = ({ http, updatedSince = 0 }) => guarded(async () => {
  const data = await http.getJson(urlFor(updatedSince));
  expect(data && typeof data === 'object', 'packagist: 応答が不正です');
  const grouped = Array.isArray(data.advisories) ? {} : data.advisories ?? {};
  const records = [];
  for (const list of Object.values(grouped)) {
    for (const a of list) {
      expect(a.advisoryId && a.packageName && typeof a.affectedVersions === 'string', `packagist: 形式が不正です: ${a.advisoryId}`);
      records.push({
        advisoryId: a.advisoryId, packageName: a.packageName, affectedVersions: a.affectedVersions,
        cve: a.cve ?? null, title: a.title ?? '', link: a.link ?? null, reportedAt: a.reportedAt ?? null,
        sources: a.sources ?? [], remoteId: a.remoteId ?? null,
      });
    }
  }
  return okResult(records);
});
