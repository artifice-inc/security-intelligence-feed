#!/usr/bin/env node
// 手動確認用: 各情報源を取得して .work/collect/<source>.json に保存する（副作用は .work/ のみ）
import { mkdir, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { COLLECTORS, OPTIONAL_COLLECTORS } from '../collect/index.mjs';
import { createHttp, COLLECT_HOSTS } from '../lib/http.mjs';
import { ROOT_DIR, loadThresholds } from '../lib/config.mjs';

const outDir = path.join(ROOT_DIR, '.work', 'collect');
await mkdir(outDir, { recursive: true });
const http = createHttp({ allowedHosts: COLLECT_HOSTS });
const optionalNames = new Set(Object.keys(OPTIONAL_COLLECTORS));
for (const [name, collect] of Object.entries({ ...COLLECTORS, ...OPTIONAL_COLLECTORS })) {
  const extra = optionalNames.has(name) ? { deadlineMs: loadThresholds().aws_bulletins_deadline_ms } : {};
  const result = await collect({ http, env: process.env, now: new Date(), ...extra });
  await writeFile(path.join(outDir, `${name}.json`), JSON.stringify(result, null, 1));
  console.log(`${name}: ok=${result.ok} records=${result.records.length}${result.error ? ` error=${result.error.message}` : ''}`);
}
