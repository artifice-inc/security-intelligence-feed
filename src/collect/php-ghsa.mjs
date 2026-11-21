import { guarded, okResult, expect, githubHeaders } from './result.mjs';
import { parsePhpRange } from '../lib/versions-php.mjs';

export const FIRST_URL = 'https://api.github.com/repos/php/php-src/security-advisories?per_page=100';
const MAX_PAGES = 20;

const nextLink = (response) => /<([^>]+)>;\s*rel="next"/.exec(response.headers.get('link') ?? '')?.[1] ?? null;

// 範囲を解析できないものは parsed:null にして needs_review に回す
export function toRecord(raw) {
  expect(/^GHSA-/.test(raw.ghsa_id ?? ''), `php-ghsa: ghsa_id が不正です: ${raw.ghsa_id}`);
  expect(Array.isArray(raw.vulnerabilities), `php-ghsa: vulnerabilities がありません: ${raw.ghsa_id}`);
  return {
    ghsa_id: raw.ghsa_id, cve_id: raw.cve_id ?? null, published_at: raw.published_at ?? null,
    updated_at: raw.updated_at ?? null, withdrawn_at: raw.withdrawn_at ?? null, severity: raw.severity ?? null,
    summary: raw.summary ?? '', html_url: raw.html_url ?? null,
    vulnerabilities: raw.vulnerabilities.map((v) => ({
      package: v.package?.name ?? null,
      vulnerable_version_range: v.vulnerable_version_range ?? null,
      patched_versions: v.patched_versions ?? null,
      parsed: parsePhpRange(v.vulnerable_version_range, v.patched_versions),
    })),
  };
}

export const collect = ({ http, env = {} }) => guarded(async () => {
  const records = [];
  let url = FIRST_URL;
  for (let page = 0; url && page < MAX_PAGES; page += 1) {
    const response = await http.request(url, { headers: githubHeaders(env, url) });
    const body = await response.json();
    expect(Array.isArray(body), 'php-ghsa: 配列ではありません');
    records.push(...body.filter((a) => a.state === undefined || a.state === 'published').map(toRecord));
    url = nextLink(response);
  }
  return okResult(records);
});
