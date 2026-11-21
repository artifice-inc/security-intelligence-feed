import { toIso, daysBetween } from '../lib/time.mjs';

const ALAS_BASE = 'https://explore.alas.aws.amazon.com';
const byKey = (a, b) => (a.key < b.key ? -1 : a.key > b.key ? 1 : 0);
const byCve = (a, b) => (a.cve < b.cve ? -1 : a.cve > b.cve ? 1 : 0);

// パッケージのキー: <platform>/<name>、opt_in_repo があれば @<repo> を付ける
export const packageKey = (p) => `${p.platform}/${p.name}${p.opt_in_repo ? `@${p.opt_in_repo}` : ''}`;

// 取得した CVE の JSON を保存形式にする。ALAS の文章（description）は持ち込まない。kev はここでは決めない
export function toStoredCve(raw) {
  const vectors = [...new Set((raw.scores ?? []).map((s) => s.vector).filter(Boolean))].sort();
  const packages = (raw.affected_packages ?? []).filter((p) => p.status !== 'NotAffected').map((p) => {
    // 最初に修正が公開された ALAS を使う
    const first = [...(p.advisories ?? [])].sort((a, b) => (a.release_date < b.release_date ? -1 : a.release_date > b.release_date ? 1 : 0))[0];
    return {
      key: packageKey(p), status: p.status, advisory: first?.id ?? null, advisory_url: first?.url ?? null, released: first?.release_date ?? null,
    };
  }).sort(byKey);
  return {
    cve: raw.cve_id, severity: String(raw.severity ?? ''), cvss_vectors: vectors,
    public_date: raw.public_date ?? null, modified_date: raw.modified_date ?? null,
    url: `${ALAS_BASE}/${raw.cve_id}.html`, packages,
  };
}

const isNetworkNoAuth = (vector) => ['AV:N', 'PR:N', 'UI:N'].every((part) => vector.includes(part));

// 重大な CVE か（保存形式のフィールドだけで判定する。取得した回も、しなかった回も同じ結果にするため）
export const isSevere = (cve) => cve.severity === 'Critical'
  || (cve.severity === 'Important' && cve.cvss_vectors.some(isNetworkNoAuth))
  || cve.kev === true;

// Fixed は公開から日数が経ったら外す。公開日が不明なら安全側で残す。KEV も例外にしない
const keepPackage = (p, now, reviewDays) => p.status !== 'Fixed' || p.released === null || daysBetween(`${p.released}T00:00:00Z`, now) <= reviewDays;

const emptyData = (now) => ({ updated_at: toIso(now), cursor: null, backfill_complete: false, last_success_date: null, retry: [], known_packages: [], cves: [] });

export function buildAmazonLinuxKernel({ previous, result, kevRecords, now, thresholds }) {
  if (!result?.ok) return previous ?? emptyData(now);
  const prior = previous ?? emptyData(now);
  const known = new Set(prior.known_packages);
  for (const raw of result.records) for (const p of raw.affected_packages) known.add(packageKey(p));

  const merged = new Map(prior.cves.map((c) => [c.cve, c]));
  for (const raw of result.records) merged.set(raw.cve_id, toStoredCve(raw));

  const kevIds = kevRecords ? new Set(kevRecords.map((r) => r.cveID)) : null;
  const cves = [...merged.values()]
    .map((c) => ({ ...c, kev: kevIds ? kevIds.has(c.cve) : prior.cves.find((p) => p.cve === c.cve)?.kev === true }))
    .filter(isSevere)
    .map((c) => ({ ...c, packages: c.packages.filter((p) => keepPackage(p, now, thresholds.kernel_fixed_review_days)) }))
    .filter((c) => c.packages.length > 0)
    .map(({ cve, severity, cvss_vectors, public_date, modified_date, kev, url, packages }) => ({ cve, severity, cvss_vectors, public_date, modified_date, kev, url, packages }))
    .sort(byCve);

  const { cursor, backfill_complete, last_success_date, retry } = result.meta;
  const next = { updated_at: prior.updated_at, cursor, backfill_complete, last_success_date, retry, known_packages: [...known].sort(), cves };
  const content = (d) => JSON.stringify({ b: d.backfill_complete, k: d.known_packages, c: d.cves });
  // 取り込みの進み具合（cursor など）だけが動いた回は updated_at を変えない
  if (!previous || content(previous) !== content(next)) next.updated_at = toIso(now);
  return next;
}
