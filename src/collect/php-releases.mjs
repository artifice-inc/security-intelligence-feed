import { guarded, okResult, expect } from './result.mjs';
import { parsePhpVersion } from '../lib/versions-php.mjs';

export const RELEASES_URL = 'https://www.php.net/releases/index.php?json&version=8&max=-1';
export const STATES_URL = 'https://www.php.net/releases/states.php';

// security タグは揺れがあるため補助情報として持つだけで、判定には使わない
export const collect = ({ http }) => guarded(async () => {
  const [releases, states] = await Promise.all([http.getJson(RELEASES_URL), http.getJson(STATES_URL)]);
  expect(releases && typeof releases === 'object', 'php-releases: releases が不正です');
  expect(states && typeof states === 'object', 'php-releases: states が不正です');
  const records = [];
  for (const [version, info] of Object.entries(releases)) {
    if (!parsePhpVersion(version)) continue;
    records.push({ type: 'release', version, date: info.date ?? null, security_tag: (info.tags ?? []).includes('security') });
  }
  for (const majors of Object.values(states)) {
    for (const [branch, info] of Object.entries(majors)) {
      records.push({
        type: 'branch', branch, state: info.state ?? null,
        security_support_end: info.security_support_end?.slice(0, 10) ?? null,
        active_support_end: info.active_support_end?.slice(0, 10) ?? null,
      });
    }
  }
  expect(records.some((r) => r.type === 'branch'), 'php-releases: ブランチ情報がありません');
  return okResult(records);
});
