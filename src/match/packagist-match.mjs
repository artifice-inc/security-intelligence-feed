import { evaluateComposer } from '../lib/composer-constraint.mjs';

// 純粋関数。advisories は data/packagist-advisories.json の「全件の集合」（差分だけを渡してはいけない。§5.7）
export function matchPackagist({ composerLock, lockfile, advisories }) {
  const byPackage = new Map();
  for (const [advisoryId, entry] of Object.entries(advisories)) {
    if (!byPackage.has(entry.packageName)) byPackage.set(entry.packageName, []);
    byPackage.get(entry.packageName).push({ advisoryId, ...entry });
  }
  const detections = [];
  for (const pkg of [...(composerLock.packages ?? []), ...(composerLock['packages-dev'] ?? [])]) {
    // Packagist のパッケージ名は小文字
    for (const advisory of byPackage.get(String(pkg.name).toLowerCase()) ?? []) {
      const result = evaluateComposer(advisory.affectedVersions, pkg.version);
      if (result.judgement === 'not_affected') continue;
      detections.push({
        lockfile, package: pkg.name, ecosystem: 'Packagist', installed_version: pkg.version,
        osv_id: advisory.advisoryId, aliases: [advisory.advisoryId, advisory.cve].filter(Boolean), title: advisory.title,
        severity_hint: null, fixed_versions: result.fixed, source_urls: [advisory.link].filter(Boolean),
        judgement: result.judgement, reason: result.reason, constraint: advisory.affectedVersions,
        packagist: { advisoryId: advisory.advisoryId, entry: advisory },
      });
    }
  }
  return detections;
}
