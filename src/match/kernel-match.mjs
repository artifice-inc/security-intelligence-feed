import { sanitizeInline } from '../lib/sanitize-md.mjs';

// release → ALAS の platform。config ファイルは作らない（指示書 §2.2）
const PLATFORM_OF_RELEASE = { 2: 'amzn2', 2023: 'amzn2023' };
const STACK_PATH = '.security/stack.yml';
const MAX_LISTED_RETRY = 5;
const SEVERITY_HINT = { Critical: 'critical', Important: 'high' };

// 申告のキー（<platform>/<package>[@<repo>]）と、location に出す package 名
export function declaredKernel(kernel) {
  const platform = PLATFORM_OF_RELEASE[kernel.release];
  return {
    key: `${platform}/${kernel.package}${kernel.repo ? `@${kernel.repo}` : ''}`,
    packageLabel: kernel.repo ? `${kernel.package}@${kernel.repo}` : kernel.package,
    installedVersion: `al${kernel.release}`,
  };
}

const evidenceOf = (declared, kernel, pkg) => {
  const target = `Amazon Linux ${kernel.release} の ${declared.packageLabel}`;
  if (pkg.status === 'PendingFix') return { judgement: 'affected', evidence: `${target} は配布元で修正待ち（PendingFix）` };
  if (pkg.status === 'NoFixPlanned') return { judgement: 'affected', evidence: `${target} は配布元が修正しない方針（NoFixPlanned）。カーネルの系統の変更を検討してください` };
  if (pkg.status === 'Fixed') {
    const when = pkg.released ? `（${pkg.released}）` : '';
    return { judgement: 'needs_review', evidence: `配布元が ${pkg.advisory ?? 'ALAS'} で修正済み${when}。稼働中のカーネルに適用し、再起動したかを確認してください。AL2023 でリリースを固定している場合、修正版は dnf --releasever=latest でないと表示されません` };
  }
  return { judgement: 'needs_review', evidence: `配布元の状態 ${sanitizeInline(pkg.status, 40)} を解釈できません。ALAS の原典を確認してください` };
};

// 純粋関数。中央とローカルで共用する。DB・ネットワーク・ファイルには触れない
export function matchKernel({ inventory, kernelData }) {
  if (!inventory.kernel) return { detections: [], errors: [] };
  if (!kernelData || !kernelData.backfill_complete) {
    return { detections: [], errors: [{ kind: 'source', target: 'alas', message: 'Amazon Linux のカーネルの脆弱性データを取り込み中です（完了まで判定できません）' }] };
  }
  const declared = declaredKernel(inventory.kernel);
  if (!kernelData.known_packages.includes(declared.key)) {
    return { detections: [], errors: [{ kind: 'inventory', target: STACK_PATH, message: `kernel の申告 ${declared.key} は ALAS のデータにありません（rpm で確認してください）` }] };
  }
  const detections = [];
  for (const cve of kernelData.cves) {
    const pkg = cve.packages.find((p) => p.key === declared.key);
    if (!pkg) continue;
    const { judgement, evidence } = evidenceOf(declared, inventory.kernel, pkg);
    detections.push({
      advisory_key: cve.cve, aliases: [cve.cve], title: `${cve.cve} Linux カーネル（Amazon Linux の重大度 ${sanitizeInline(cve.severity, 20)}）`, ecosystem: 'os',
      locations: [{ lockfile: STACK_PATH, package: declared.packageLabel, ecosystem: 'os', installed_version: declared.installedVersion }],
      fixed_versions: pkg.status === 'Fixed' && pkg.advisory ? [pkg.advisory] : [],
      source_urls: [cve.url, pkg.advisory_url].filter(Boolean),
      judgement, evidence, severity_hint: SEVERITY_HINT[cve.severity] ?? 'medium', kev_hint: cve.kev === true,
    });
  }
  const errors = [];
  // 取得処理の成功と、照合の完全性は別。未取得の CVE が申告のカーネルに影響するかは分からない
  if (kernelData.retry.length > 0) {
    const listed = kernelData.retry.slice(0, MAX_LISTED_RETRY).map((r) => r.cve).join('、');
    errors.push({ kind: 'source', target: 'alas', message: `ALAS の詳細を取得できていない CVE が ${kernelData.retry.length}件あり、影響を判定しきれません（${listed}）` });
  }
  return { detections, errors };
}
