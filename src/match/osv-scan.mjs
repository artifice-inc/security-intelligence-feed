import path from 'node:path';
import { ecosystemOfLockfile, isRequirementsFile } from '../inventory/detect-stack.mjs';

// 固定版 OSV-Scanner を --offline で実行して JSON を解析する。ネットワークにも書き込みにも触れない（exec は注入）
// 終了コード（公式 output.md）: 0=脆弱性なし / 1=脆弱性あり / 127=一般エラー / 128=パッケージなし / それ以外=実行エラー
const EXIT_CLEAN = 0;
const EXIT_FOUND = 1;
const EXIT_NO_PACKAGES = 128;

// --all-packages がないと、脆弱性0件の source は results に載らない（v2.7.0 の実物で確認済み）。載らない lockfile は読めていないとして扱う
// 固定版 v2.7.0 がこの引数を受け付けることは、2026-10-25 に GitHub のランナー（test-offline）で確認済み
// inputs: [{ file（元の相対パス）, scanPath（スキャナに渡す絶対パス）}]
// requirements は名前に requirements を含まないと実行エラーになるため、種類を接頭辞で指定する
export function buildScannerArgs({ inputs }) {
  return ['scan', 'source', '--offline', '--format=json', '--all-packages',
    ...inputs.map(({ file, scanPath }) => `--lockfile=${isRequirementsFile(file) ? 'requirements.txt:' : ''}${scanPath}`)];
}

const fixedVersionsOf = (vuln, pkg) => [...new Set((vuln.affected ?? [])
  .filter((a) => a.package?.name === pkg.name && a.package?.ecosystem === pkg.ecosystem)
  .flatMap((a) => (a.ranges ?? []).flatMap((r) => (r.events ?? []).map((e) => e.fixed).filter(Boolean))))].sort();

export function parseScannerOutput(stdout, { root, inputs }) {
  let doc;
  try { doc = JSON.parse(stdout); } catch { return { ok: false, error: { kind: 'scanner', target: 'osv-scanner', message: 'OSV-Scanner の出力を JSON として解析できません' } }; }
  if (!Array.isArray(doc?.results)) return { ok: false, error: { kind: 'scanner', target: 'osv-scanner', message: 'OSV-Scanner の出力に results がありません' } };
  const fileOfScanPath = new Map(inputs.map(({ file, scanPath }) => [scanPath, file]));
  const seen = new Set();
  const detections = [];
  for (const result of doc.results) {
    const reported = result.source?.path ?? '';
    const lockfile = fileOfScanPath.get(reported) ?? path.relative(root, reported);
    seen.add(lockfile);
    for (const entry of result.packages ?? []) {
      for (const vuln of entry.vulnerabilities ?? []) {
        detections.push({
          lockfile, package: entry.package.name, ecosystem: entry.package.ecosystem, installed_version: entry.package.version,
          judgement: 'affected', osv_id: vuln.id, aliases: [vuln.id, ...(vuln.aliases ?? [])], title: vuln.summary ?? vuln.id,
          severity_hint: vuln.database_specific?.severity?.toString().toLowerCase() ?? null,
          fixed_versions: fixedVersionsOf(vuln, entry.package), record: vuln,
        });
      }
    }
  }
  const missing = inputs.map((i) => i.file).filter((file) => !seen.has(file));
  return { ok: true, detections, missing };
}

// 戻り値: { detections, errors, ok }。実行エラーと「脆弱性あり」の非0終了を取り違えない
export async function runOsvScan({ exec, scannerPath, root, inputs, dbDir }) {
  const targets = inputs.filter((i) => ecosystemOfLockfile(i.file) !== null);
  if (targets.length === 0) return { ok: true, detections: [], errors: [] };
  const outcome = await exec(scannerPath, buildScannerArgs({ inputs: targets }), { env: { OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY: dbDir } });
  if (outcome.code === EXIT_NO_PACKAGES) {
    return { ok: false, detections: [], errors: targets.map((i) => ({ kind: 'lockfile', target: i.file, message: 'パッケージを1件も読み取れませんでした（終了コード128）' })) };
  }
  if (outcome.code !== EXIT_CLEAN && outcome.code !== EXIT_FOUND) {
    return { ok: false, detections: [], errors: [{ kind: 'scanner', target: 'osv-scanner', message: `OSV-Scanner が実行エラーで終了しました（終了コード${outcome.code}）` }] };
  }
  const parsed = parseScannerOutput(outcome.stdout, { root, inputs: targets });
  if (!parsed.ok) return { ok: false, detections: [], errors: [parsed.error] };
  const errors = parsed.missing.map((f) => ({ kind: 'lockfile', target: f, message: 'OSV-Scanner の解析結果に含まれていません' }));
  return { ok: errors.length === 0, detections: parsed.detections, errors };
}
