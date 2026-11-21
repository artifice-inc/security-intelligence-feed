import { guarded, okResult, expect } from './result.mjs';

export const KEV_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';

export const collect = ({ http }) => guarded(async () => {
  const data = await http.getJson(KEV_URL);
  expect(Array.isArray(data?.vulnerabilities), 'KEV: vulnerabilities が配列ではありません');
  const records = data.vulnerabilities.map((v) => {
    expect(/^CVE-\d{4}-\d+$/.test(v.cveID ?? ''), `KEV: cveID が不正です: ${v.cveID}`);
    return {
      cveID: v.cveID, vendorProject: v.vendorProject ?? '', product: v.product ?? '',
      dateAdded: v.dateAdded ?? null, knownRansomwareCampaignUse: v.knownRansomwareCampaignUse ?? 'Unknown',
    };
  });
  return okResult(records, { meta: { catalogVersion: data.catalogVersion ?? null } });
});

// D3: digest に載せる KEV 新着（PHP / Node.js に関わるもの）
export const isRuntimeRelated = (record) =>
  /\b(php|node\.?js|python)\b/i.test(`${record.vendorProject} ${record.product}`);
