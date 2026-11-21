#!/usr/bin/env node
// 管理者が手元で実行し、公開側の候補（main と feed）を一時ディレクトリに作る。Git の操作はしない
import { parseArgs } from 'node:util';
import path from 'node:path';
import { ROOT_DIR, loadCentral, loadProjects } from '../lib/config.mjs';
import { buildPublic } from '../feed/build-public.mjs';
import { toIso } from '../lib/time.mjs';

const { values } = parseArgs({ options: { out: { type: 'string' } } });
if (!values.out) {
  console.error('使い方: node src/cli/build-public.mjs --out <空のディレクトリ>');
  process.exit(2);
}
const { problems } = buildPublic({
  rootDir: ROOT_DIR, outDir: path.resolve(values.out), projectsConfig: loadProjects(), central: loadCentral(), now: toIso(new Date()),
});
if (problems.length > 0) {
  console.error(`検査に失敗しました（${problems.length}件）`);
  for (const problem of problems) console.error(`- ${problem}`);
  process.exit(1);
}
console.log(`公開候補を作成しました: ${path.resolve(values.out)}（main と feed。検査の違反は0件）`);
