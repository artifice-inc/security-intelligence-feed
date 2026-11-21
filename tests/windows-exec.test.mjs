import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { readFileSync } from 'node:fs';
import { scannerFileName } from '../src/cli/install-scanner.mjs';
import { prepareWindowsRun, startWindowsRun, guardScannerExec } from '../src/local/windows-exec.mjs';
import { parseScannerOutput, runOsvScan } from '../src/match/osv-scan.mjs';
import { loadToolVersions, ROOT_DIR } from '../src/lib/config.mjs';
import { sha256Hex } from '../src/lib/hash.mjs';
import { setup } from './helpers/check-feed-setup.mjs';

const toolVersions = loadToolVersions();
const SCANNER_BYTES = Buffer.from('固定版のつもりの中身');
const versionsFor = (bytes) => ({ 'osv-scanner': { assets: { windows_amd64: { sha256: sha256Hex(bytes) } } } });
const WIN_SCANNER = 'C:\\Users\\me\\.local\\bin\\osv-scanner.exe';

test('T1: 配置先の名前は windows_ だけ .exe', () => {
  assert.equal(scannerFileName('windows_amd64'), 'osv-scanner.exe');
  assert.equal(scannerFileName('darwin_arm64'), 'osv-scanner');
  assert.equal(scannerFileName('linux_amd64'), 'osv-scanner');
});

test('T1: 各 asset の URL は取得先の確認を通り、sha256 は64桁の16進。windows_amd64 がある', () => {
  const { assets } = toolVersions['osv-scanner'];
  assert.ok(assets.windows_amd64.url.endsWith('/osv-scanner_windows_amd64.exe'));
  assert.equal(assets.windows_arm64, undefined);
  for (const asset of Object.values(assets)) {
    assert.ok(asset.url.startsWith('https://github.com/google/osv-scanner/releases/download/'));
    assert.match(asset.sha256, /^[0-9a-f]{64}$/);
  }
});

test('prepareWindowsRun: win32 以外は null', async () => {
  for (const platform of ['linux', 'darwin']) assert.equal(await prepareWindowsRun({ platform, scannerPath: undefined, toolVersions, readFile: async () => { throw new Error('呼ばない'); } }), null);
});

test('prepareWindowsRun(win32): 完全修飾の .exe 以外・ファイルなし・sha256 不一致は失敗、一致なら成功', async () => {
  const readFile = async () => SCANNER_BYTES;
  const prepare = (scannerPath, read = readFile, versions = versionsFor(SCANNER_BYTES)) => prepareWindowsRun({ platform: 'win32', scannerPath, toolVersions: versions, readFile: read });
  for (const bad of [undefined, 'bin\\osv-scanner.exe', 'C:\\bin\\osv-scanner', 'C:osv-scanner.exe', '\\bin\\osv-scanner.exe']) {
    const result = await prepare(bad);
    assert.equal(result.ok, false, String(bad));
    assert.match(result.message, /完全なパス/);
  }
  assert.match((await prepare(WIN_SCANNER, async () => { throw new Error('ENOENT'); })).message, /ありません/);
  assert.match((await prepare(WIN_SCANNER, async () => Buffer.concat([SCANNER_BYTES, Buffer.from('x')]))).message, /固定版と一致しない/);
  assert.deepEqual(await prepare(WIN_SCANNER), { ok: true, scannerPath: WIN_SCANNER });
  assert.deepEqual(await prepare('\\\\server\\share\\OSV-SCANNER.EXE'), { ok: true, scannerPath: '\\\\server\\share\\OSV-SCANNER.EXE' });
});

test('CLI の準備(win32 を模す): パス解決 → chdir(codeRoot) → スキャナ検査の順。--scanner は解決しない', async () => {
  const log = [];
  let cwd = 'C:\\work\\app';
  const result = await startWindowsRun({
    platform: 'win32', cwd, codeRoot: 'C:\\code', toolVersions: versionsFor(SCANNER_BYTES),
    values: { 'project-dir': '.', 'feed-dir': '..\\feed', 'osv-db-dir': 'D:\\db', scanner: WIN_SCANNER, project: '/team/app' },
    chdir: (dir) => { log.push(`chdir:${dir}`); cwd = dir; },
    readFile: async () => { log.push(`readFile@${cwd}`); return SCANNER_BYTES; },
  });
  assert.deepEqual(log, ['chdir:C:\\code', 'readFile@C:\\code']);
  assert.equal(result.values['project-dir'], 'C:\\work\\app');
  assert.equal(result.values['feed-dir'], 'C:\\work\\feed');
  assert.equal(result.values['osv-db-dir'], 'D:\\db');
  assert.equal(result.values.scanner, WIN_SCANNER);
  assert.equal(result.values.project, '/team/app');
  assert.equal(result.ok, true);
  assert.equal(await startWindowsRun({ platform: 'linux', values: {}, chdir: () => { throw new Error('呼ばない'); } }), null);
});

test('CLI の準備: git を起動する時点（chdir 後）の現在のディレクトリは codeRoot', async () => {
  const before = process.cwd();
  try {
    let cwdAtScannerCheck;
    await startWindowsRun({
      platform: 'win32', cwd: before, codeRoot: ROOT_DIR, toolVersions: versionsFor(SCANNER_BYTES), values: { scanner: WIN_SCANNER },
      chdir: (dir) => process.chdir(dir), readFile: async () => { cwdAtScannerCheck = process.cwd(); return SCANNER_BYTES; },
    });
    assert.equal(cwdAtScannerCheck, ROOT_DIR);
  } finally { process.chdir(before); }
});

test('CLI（win32 を模す）: スキャナの準備に失敗すると osv は unavailable で、スキャナを起動しない。理由は scan_errors', async () => {
  const s = setup();
  const launched = [];
  const exec = guardScannerExec(async (cmd) => { launched.push(cmd); return { code: 0, stdout: '' }; }, WIN_SCANNER, 'osv-scanner.exe がありません（または読めません）。導入の手順で入れてください');
  const output = await s.run({ deps: { ...s.deps, exec, scannerPath: WIN_SCANNER, scannerVersion: async () => null } });
  assert.deepEqual(launched, []);
  assert.equal(output.dependency_checks.osv, 'unavailable');
  assert.ok(output.scan_errors.some((e) => e.kind === 'scanner' && e.message.includes('osv-scanner.exe がありません')));
});

const inputs = [{ file: 'package-lock.json', scanPath: 'C:\\repo\\package-lock.json' }, { file: 'sub/package-lock.json', scanPath: 'C:\\repo\\sub\\package-lock.json' }];
const outputOf = (...paths) => JSON.stringify({ results: paths.map((p) => ({ source: { path: p }, packages: [] })) });
const parse = (platform, inputList, ...paths) => parseScannerOutput(outputOf(...paths), { root: 'C:\\repo', inputs: inputList, platform });

test('突き合わせ(win32): 区切り・大小だけ違うパスは元の相対パスに戻る', () => {
  const result = parse('win32', inputs, 'C:/repo/SUB/package-lock.json', 'c:\\REPO\\package-lock.json');
  assert.deepEqual(result.missing, []);
});

test('突き合わせ(win32): 大小違いで共存する入力は、どちらにも割り当てず seen にも入れない', () => {
  const both = [{ file: 'sub/package-lock.json', scanPath: 'C:\\repo\\sub\\package-lock.json' }, { file: 'Sub/package-lock.json', scanPath: 'C:\\repo\\Sub\\package-lock.json' }];
  const result = parse('win32', both, 'C:/repo/sub/package-lock.json');
  assert.deepEqual(result.missing.sort(), ['Sub/package-lock.json', 'sub/package-lock.json']);
});

test('突き合わせ(win32): 空・別のドライブ・入力にないパスは割り当てず、検出にも入れない', () => {
  const doc = { results: ['', 'D:\\other\\package-lock.json', 'C:\\repo\\none\\package-lock.json'].map((p) => ({ source: { path: p }, packages: [{ package: { name: 'a', ecosystem: 'npm', version: '1' }, vulnerabilities: [{ id: 'X-1' }] }] })) };
  const result = parseScannerOutput(JSON.stringify(doc), { root: 'C:\\repo', inputs, platform: 'win32' });
  assert.deepEqual(result.detections, []);
  assert.deepEqual(result.missing, ['package-lock.json', 'sub/package-lock.json']);
});

test('突き合わせ(linux): 今と同じ（完全一致 → path.relative）', () => {
  const posix = [{ file: 'sub/package-lock.json', scanPath: '/repo/sub/package-lock.json' }];
  assert.deepEqual(parseScannerOutput(outputOf('/repo/sub/package-lock.json'), { root: '/repo', inputs: posix, platform: 'linux' }).missing, []);
  assert.deepEqual(parseScannerOutput(outputOf('/repo/other/x.json'), { root: '/repo', inputs: posix, platform: 'linux' }).missing, ['sub/package-lock.json']);
});

test('runOsvScan: exec が reason を返したら、実行エラーではなく理由つきの scanner エラー', async () => {
  const result = await runOsvScan({ exec: async () => ({ code: 127, stdout: '', reason: '理由X' }), scannerPath: 's', root: '/r', inputs: [{ file: 'package-lock.json', scanPath: '/r/package-lock.json' }], dbDir: '/d' });
  assert.equal(result.ok, false);
  assert.match(result.errors[0].message, /理由X/);
});
