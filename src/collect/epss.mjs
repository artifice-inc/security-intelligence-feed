import { gunzipSync } from 'node:zlib';
import { guarded, okResult, expect } from './result.mjs';

export const EPSS_URL = 'https://epss.empiricalsecurity.com/epss_scores-current.csv.gz';

// 先頭のコメント行: "#model_version:v2026.06.15,score_date:2026-10-24T12:03:08Z"
// minPercentile を渡すと、wantedCves に関係なく百分位がその値以上の行だけを取る
export function parseEpssCsv(text, wantedCves, minPercentile = null) {
  const lines = text.split('\n');
  const header = lines[0].startsWith('#') ? lines.shift() : '';
  const meta = Object.fromEntries(header.replace(/^#/, '').split(',').map((kv) => kv.split(/:(.*)/s).slice(0, 2)));
  expect(lines[0]?.trim() === 'cve,epss,percentile', 'EPSS: ヘッダ行が想定と異なります');
  const records = [];
  for (const line of lines.slice(1)) {
    const [cve, epss, percentile] = line.split(',');
    if (!cve) continue;
    if (minPercentile === null ? !wantedCves.has(cve) : !(Number(percentile) >= minPercentile)) continue;
    records.push({ cve, epss: Number(epss), percentile: Number(percentile), score_date: meta.score_date ?? null });
  }
  return { records, model_version: meta.model_version ?? null, score_date: meta.score_date ?? null };
}

// wantedCves: 保存済みのアドバイザリと KEV 新着の CVE だけを残す（全件は保持しない）
export const collect = ({ http, wantedCves = new Set(), minPercentile = null }) => guarded(async () => {
  const gz = await http.getBuffer(EPSS_URL);
  const { records, model_version: modelVersion, score_date: scoreDate } = parseEpssCsv(gunzipSync(gz).toString('utf8'), wantedCves, minPercentile);
  return okResult(records, { meta: { model_version: modelVersion, score_date: scoreDate } });
});
