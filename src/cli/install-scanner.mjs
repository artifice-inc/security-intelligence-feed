#!/usr/bin/env node
// 固定版 OSV-Scanner を GitHub Releases から取得し、sha256 を検証してから配置する（Homebrew は版を固定できないため使わない）
import { parseArgs } from 'node:util';
import { mkdir, writeFile, chmod } from 'node:fs/promises';
import path from 'node:path';
import { loadToolVersions } from '../lib/config.mjs';
import { sha256Hex } from '../lib/hash.mjs';

const { values } = parseArgs({ options: { platform: { type: 'string' }, dest: { type: 'string' } } });
const tool = loadToolVersions()['osv-scanner'];
const asset = tool.assets[values.platform];
if (!asset || !values.dest) {
  console.error(`使い方: install-scanner.mjs --platform ${Object.keys(tool.assets).join('|')} --dest <dir>`);
  process.exit(2);
}
if (!asset.url.startsWith('https://github.com/google/osv-scanner/releases/download/')) throw new Error('取得先が想定外です');
const response = await fetch(asset.url);
if (!response.ok) throw new Error(`取得に失敗しました: HTTP ${response.status}`);
const buffer = Buffer.from(await response.arrayBuffer());
if (sha256Hex(buffer) !== asset.sha256) throw new Error('sha256 が一致しないため配置しません');
await mkdir(values.dest, { recursive: true });
const target = path.join(values.dest, 'osv-scanner');
await writeFile(target, buffer);
await chmod(target, 0o755);
console.log(`osv-scanner ${tool.version} を ${target} に配置しました`);
