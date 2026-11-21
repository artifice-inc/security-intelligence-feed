#!/usr/bin/env node
// 公開側の定期実行の入口。収集の結果を feed ブランチの data/ へ push する
import { parseArgs } from 'node:util';
import path from 'node:path';
import { ROOT_DIR } from '../lib/config.mjs';
import { createHttp, COLLECT_HOSTS } from '../lib/http.mjs';
import { COLLECTORS, OPTIONAL_COLLECTORS } from '../collect/index.mjs';
import { runCollect } from '../feed/run-collect.mjs';
import { toIso } from '../lib/time.mjs';

const EXIT_PARTIAL = 3;
const { values } = parseArgs({ options: { 'feed-root': { type: 'string' } } });
if (!values['feed-root']) {
  console.error('使い方: node src/cli/run-collect.mjs --feed-root <feed の作業ツリー>');
  process.exit(2);
}

const outcome = await runCollect({
  rootDir: ROOT_DIR, feedRoot: path.resolve(values['feed-root']), now: toIso(new Date()), env: process.env,
  deps: { http: createHttp({ allowedHosts: COLLECT_HOSTS }), collectors: COLLECTORS, optionalCollectors: OPTIONAL_COLLECTORS },
});
console.log(JSON.stringify(outcome, null, 2));
process.exit(outcome.status === 'success' ? 0 : outcome.status === 'partial' ? EXIT_PARTIAL : 1);
