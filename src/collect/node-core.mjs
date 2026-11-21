import { guarded, okResult, expect, githubHeaders } from './result.mjs';

export const LIST_URL = 'https://api.github.com/repos/nodejs/security-wg/contents/vuln/core';
const FILE_PATTERN = /^(\d+)\.json$/;

// previousShas: { "<n>": "<前回の blob sha>" }。index.json は更新が遅れているので使わない
export const collect = ({ http, env = {}, previousShas = {} }) => guarded(async () => {
  const listing = await http.getJson(LIST_URL, { headers: githubHeaders(env, LIST_URL) });
  expect(Array.isArray(listing), 'node-core: 一覧が配列ではありません');
  const files = listing.filter((f) => f.type === 'file' && FILE_PATTERN.test(f.name));
  expect(files.length > 0, 'node-core: N.json が1件もありません');
  const records = [];
  const unchanged = [];
  for (const file of files) {
    const id = file.name.match(FILE_PATTERN)[1];
    if (previousShas[id] === file.sha) { unchanged.push(id); continue; }
    expect(file.download_url?.startsWith('https://raw.githubusercontent.com/'), `node-core: download_url が不正です: ${file.name}`);
    const body = await http.getJson(file.download_url);
    expect(Array.isArray(body.cve) && typeof body.vulnerable === 'string' && typeof body.patched === 'string',
      `node-core: ${file.name} の形式が不正です`);
    records.push({
      id, sha: file.sha, cve: body.cve, vulnerable: body.vulnerable, patched: body.patched,
      severity: body.severity ?? null, ref: body.ref ?? null, description: body.description ?? '',
    });
  }
  return okResult(records, { unchanged });
});
