// tests/windows/smoke.sh が使う確認。使い方: check-output.mjs <full|unavailable|fresh-pypi|broken-zip> <引数...>
import { readFileSync, writeFileSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import assert from 'node:assert/strict';
import { assertValid } from '../../src/lib/schema.mjs';
import { verifyZip } from '../../src/collect/osv-db.mjs';

const [mode, ...args] = process.argv.slice(2);
const readOutput = (file) => JSON.parse(readFileSync(file, 'utf8'));
const NOT_PARSED = '解析結果に含まれていません';

// ID ごとに、検出された lockfile の一覧が期待どおりであること
const EXPECTED = { 'GHSA-wn01-smk1-test': ['package-lock.json'], 'GHSA-wn02-smk2-test': ['sub/package-lock.json'], 'PYSEC-WIN-SMOKE-1': ['requirements.txt'] };

if (mode === 'full') {
  const [file, feedSha, commit] = args;
  const output = readOutput(file);
  assertValid('security-check-output', output);
  for (const [id, lockfiles] of Object.entries(EXPECTED)) {
    const hits = output.results.filter((r) => r.aliases.includes(id));
    assert.equal(hits.length, 1, `${id} が1項目にまとまっていません`);
    assert.deepEqual([...new Set(hits[0].locations.map((l) => l.lockfile))].sort(), lockfiles, id);
  }
  assert.ok(!output.scan_errors.some((e) => e.message.includes(NOT_PARSED)), JSON.stringify(output.scan_errors));
  assert.equal(output.provenance.feed_version, feedSha);
  assert.equal(output.feed_signals.mode, 'latest');
  assert.equal(output.scanner.match, true);
  assert.equal(output.provenance.inventory_commit, commit);
  assert.equal(output.dependency_checks.osv, 'ok');
} else if (mode === 'unavailable') {
  // sha256 の合わないスキャナ: osv は照合不能になり、フィードの照合は続く
  const output = readOutput(args[0]);
  assertValid('security-check-output', output);
  assert.equal(output.dependency_checks.osv, 'unavailable');
  assert.ok(output.scan_errors.some((e) => e.message.includes('固定版と一致しない')), JSON.stringify(output.scan_errors));
  assert.equal(output.feed_signals.mode, 'latest');
  assert.equal(output.results.length, 0);
} else if (mode === 'fresh-pypi') {
  const output = readOutput(args[0]);
  assertValid('security-check-output', output);
  assert.equal(output.osv_db.PyPI.state, 'fresh', JSON.stringify(output.osv_db));
} else if (mode === 'broken-zip') {
  // 正しい ZIP は通り、エントリのデータを1バイト書き換えた ZIP（CRC 不一致）は実物の tar.exe で拒否される
  const good = readFileSync(args[0]);
  await verifyZip(args[0]);
  const broken = Buffer.from(good);
  const dataStart = 30 + broken.readUInt16LE(26) + broken.readUInt16LE(28);
  broken[dataStart] ^= 0xff;
  const brokenFile = path.join(mkdtempSync(path.join(tmpdir(), 'si-broken-')), 'broken.zip');
  writeFileSync(brokenFile, broken);
  await assert.rejects(() => verifyZip(brokenFile), /ZIP|tar\.exe/);
} else {
  throw new Error(`未知のモード: ${mode}`);
}
console.log(`OK: ${mode}`);
