#!/usr/bin/env node
import { parseArgs } from 'node:util';
import { execFileSync } from 'node:child_process';
import path from 'node:path';
import { exportInventory } from '../inventory/export-inventory.mjs';

const { values } = parseArgs({
  options: { 'project-dir': { type: 'string' }, project: { type: 'string' }, out: { type: 'string' }, ref: { type: 'string' } },
});
if (!values['project-dir'] || !values.project) {
  console.error('使い方: export-inventory.mjs --project-dir <dir> --project <名前> [--out <dir>] [--ref <ブランチ>]');
  process.exit(2);
}
const projectDir = path.resolve(values['project-dir']);
const git = (...args) => execFileSync('git', ['-C', projectDir, ...args], { encoding: 'utf8' }).trim();
const out = path.resolve(values.out ?? `./inventory-export/${values.project}`);
let result;
try {
  result = exportInventory({
    projectDir, project: values.project, outDir: out, now: new Date(),
    sourceRef: values.ref ?? git('rev-parse', '--abbrev-ref', 'HEAD'), sourceCommit: git('rev-parse', 'HEAD'),
  });
} catch (error) {
  console.error(error.message);
  if (error.message.includes('認証情報')) console.error('対処: --index-url などの認証情報を環境変数（${PIP_INDEX_URL} など）に移してください。');
  process.exit(1);
}
const { manifest, problems, leftovers } = result;
if (leftovers.length > 0) console.error(`警告: 前回の途中終了の退避フォルダが残っています: ${leftovers.join('、')}（内容を確かめて削除してください）`);
console.log(JSON.stringify({ out, files: manifest.files.map((f) => f.path), problems }, null, 2));
console.log(`\n次の手順: ${out} を 中央リポジトリの data/inventory-export/${values.project}/ に置いて PR を出してください（30日ごとに出し直し）。`);
