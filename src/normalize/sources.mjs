import { contentHash } from '../lib/hash.mjs';
import { toIso } from '../lib/time.mjs';
import { pythonAffectedVersions, pythonFixedVersions } from '../lib/versions-python.mjs';

// 情報源のレコードを「情報源レコード」の共通形へ変換する。affected には from_sources を付ける

const SOURCE_RANK = { ghsa: 3, specific: 2 };

const fromSourcesTag = (name, id) => [`${name}:${id}`];
const FIXED_VERSION = /\d+\.\d+\.\d+/g;

// dbEcosystem: 実際に読んだ OSV の DB のエコシステム。affected のない取り下げレコードでも追跡を続けるために保存する
export function fromOsv(raw, { now, dbEcosystem = null }) {
  const ids = [raw.id, ...(raw.aliases ?? [])];
  const cvss = (raw.severity ?? []).find((s) => s.type === 'CVSS_V3')?.score ?? null;
  const cvss4 = (raw.severity ?? []).find((s) => s.type === 'CVSS_V4')?.score ?? null;
  const level = raw.database_specific?.severity?.toString().toLowerCase() ?? null;
  return {
    source: 'osv', id: raw.id, ids, url: `https://osv.dev/vulnerability/${raw.id}`,
    published_at: raw.published ?? null, modified_at: raw.modified ?? null,
    content_hash: contentHash(raw), withdrawn_at: raw.withdrawn ?? null, fetched_at: toIso(now),
    title: raw.summary || raw.details?.split('\n')[0] || raw.id,
    severity: { level, source: raw.id.startsWith('GHSA-') ? 'ghsa' : 'osv', cvss_v3: cvss, cvss_v4: cvss4, rank: raw.id.startsWith('GHSA-') ? SOURCE_RANK.ghsa : SOURCE_RANK.specific },
    affected: (raw.affected ?? []).map((a) => ({
      package: a.package, ranges: a.ranges ?? [], versions: a.versions ?? [], from_sources: fromSourcesTag('osv', raw.id),
    })),
    category: 'dependency', ecosystem: raw.affected?.[0]?.package?.ecosystem ?? 'unknown',
    verification_status: 'source_structured',
    ...(dbEcosystem ? { db_ecosystem: dbEcosystem } : {}),
  };
}

export function fromPhpGhsa(raw, { now }) {
  const ids = [raw.ghsa_id, raw.cve_id].filter(Boolean);
  const unparsed = raw.vulnerabilities.some((v) => !v.parsed || v.parsed.some((r) => r.type === 'UNPARSED'));
  return {
    source: 'php-ghsa', id: raw.ghsa_id, ids, url: raw.html_url ?? `https://github.com/php/php-src/security/advisories/${raw.ghsa_id}`,
    published_at: raw.published_at, modified_at: raw.updated_at, content_hash: contentHash(raw),
    withdrawn_at: raw.withdrawn_at, fetched_at: toIso(now), title: raw.summary,
    severity: { level: raw.severity ?? null, source: 'ghsa', cvss_v3: null, cvss_v4: null, rank: SOURCE_RANK.ghsa },
    affected: raw.vulnerabilities.map((v) => ({
      package: { ecosystem: 'php', name: v.package ?? 'php' },
      ranges: v.parsed ?? [{ type: 'UNPARSED', raw: v.vulnerable_version_range }],
      versions: [], from_sources: fromSourcesTag('php-ghsa', raw.ghsa_id),
    })),
    category: 'runtime', ecosystem: 'php',
    verification_status: unparsed ? 'needs_review' : 'source_structured',
  };
}

export function fromNodeCore(raw, { now }) {
  const id = `NODE-CORE-${raw.id}`;
  return {
    source: 'node-core', id, ids: [id, ...raw.cve], url: raw.ref ?? `https://github.com/nodejs/security-wg/blob/main/vuln/core/${raw.id}.json`,
    published_at: null, modified_at: null, content_hash: raw.sha, withdrawn_at: null, fetched_at: toIso(now),
    title: raw.description || id,
    severity: { level: raw.severity?.toLowerCase() ?? null, source: 'node-core', cvss_v3: null, cvss_v4: null, rank: SOURCE_RANK.specific },
    affected: [{
      package: { ecosystem: 'node', name: 'node' },
      ranges: [{ type: 'NODE_SEMVER', vulnerable: raw.vulnerable, patched: raw.patched, fixed_versions: raw.patched.match(FIXED_VERSION) ?? [] }],
      versions: [], from_sources: fromSourcesTag('node-core', id),
    }],
    category: 'runtime', ecosystem: 'node', verification_status: 'source_structured',
  };
}

// 前回の blob sha（node-core の取得で変更のあったファイルだけ再取得するため）
export function previousNodeCoreShas(advisories) {
  const shas = {};
  for (const advisory of advisories) {
    for (const s of advisory.sources) {
      if (s.name === 'node-core' && s.content_hash) shas[s.id.replace('NODE-CORE-', '')] = s.content_hash;
    }
  }
  return shas;
}

// Packagist（GHSA を持たないレコード）を情報源レコードへ。照合で見つかったものだけ保存する
export function fromPackagist(entry, advisoryId) {
  const ids = [advisoryId, entry.cve].filter(Boolean);
  return {
    source: 'packagist', id: advisoryId, ids, url: entry.link ?? `https://packagist.org/security-advisories/${advisoryId}`,
    published_at: entry.reportedAt ?? null, modified_at: null, content_hash: contentHash(entry), withdrawn_at: null,
    fetched_at: null, title: entry.title,
    severity: { level: null, source: null, cvss_v3: null, cvss_v4: null, rank: 0 },
    affected: [{ package: { ecosystem: 'Packagist', name: entry.packageName }, ranges: [{ type: 'COMPOSER', constraint: entry.affectedVersions }], versions: [], from_sources: fromSourcesTag('packagist', advisoryId) }],
    category: 'dependency', ecosystem: 'Packagist', verification_status: 'source_structured',
  };
}

const NO_TAGS_REASON = 'OSV の記録に正式版の影響タグがありません（補完待ち、または確認待ち）';

// 影響タグが空のときの範囲。人が確認した一覧にあればその判定、なければ UNPARSED で pending に入れる
function rangeWithoutTags(id, noImpact) {
  const entry = noImpact[id];
  if (entry?.decision === 'no_impact') {
    return { range: { type: 'PY_VERSIONS', affected: [], fixed: [], ...(entry.min_version ? { review_below: entry.min_version } : {}) }, pendingReason: null };
  }
  if (entry?.decision === 'manual_review') return { range: { type: 'UNPARSED', raw: entry.reason }, pendingReason: null };
  return { range: { type: 'UNPARSED', raw: NO_TAGS_REASON }, pendingReason: 'no_versions' };
}

// PSF の記録（OSV の GIT/<ID>.json）を情報源レコードへ。戻り値は { record, pendingReason }
// 取り下げは影響タグの判定より先に処理する（affected が空の取り下げで pending に入らないように）
export function fromPythonPsf(raw, { now, releases, noImpact = {}, graceDays }) {
  const withdrawn = raw.withdrawn ?? null;
  const tags = pythonAffectedVersions(raw);
  let built;
  if (withdrawn) built = { range: { type: 'PY_VERSIONS', affected: tags, fixed: [] }, pendingReason: null };
  else if (tags.length > 0) built = { range: { type: 'PY_VERSIONS', affected: tags, fixed: pythonFixedVersions(tags, releases, { now, graceDays }) }, pendingReason: null };
  else built = rangeWithoutTags(raw.id, noImpact);
  const record = {
    source: 'python-psf', id: raw.id, ids: [raw.id, ...(raw.aliases ?? [])], url: `https://osv.dev/vulnerability/${raw.id}`,
    published_at: raw.published ?? null, modified_at: raw.modified ?? null, content_hash: contentHash(raw), withdrawn_at: withdrawn, fetched_at: toIso(now),
    title: raw.summary || raw.details?.split('\n')[0] || raw.id,
    // PSF の記録に重大度はない
    severity: { level: null, source: 'python-psf', cvss_v3: null, cvss_v4: null, rank: SOURCE_RANK.specific },
    affected: [{ package: { ecosystem: 'python', name: 'python' }, ranges: [built.range], versions: [], from_sources: fromSourcesTag('python-psf', raw.id) }],
    category: 'runtime', ecosystem: 'python',
    verification_status: built.range.type === 'UNPARSED' ? 'needs_review' : 'source_structured',
  };
  return { record, pendingReason: built.pendingReason };
}
