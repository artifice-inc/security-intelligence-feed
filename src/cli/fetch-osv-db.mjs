#!/usr/bin/env node
import { parseArgs } from 'node:util';
import { fetchOsvDb } from '../collect/osv-db.mjs';

// 入力は --eco と --dest だけ（lockfile や作業ツリーを受け取る引数は作らない）
const { values } = parseArgs({ options: { eco: { type: 'string' }, dest: { type: 'string' } }, strict: true });
if (!values.eco || !values.dest) {
  console.error('使い方: fetch-osv-db.mjs --eco npm,Packagist,PyPI --dest <dir>');
  process.exit(2);
}
const { outcomes } = await fetchOsvDb({ ecosystems: values.eco.split(','), dest: values.dest });
console.log(JSON.stringify(outcomes, null, 2));
process.exit(Object.values(outcomes).every((o) => o.ok) ? 0 : 1);
