import { fromOsv, fromPhpGhsa, fromNodeCore, fromPythonPsf, previousNodeCoreShas } from '../normalize/sources.mjs';
import { mergeAdvisories } from '../normalize/advisories.mjs';
import { buildAmazonLinuxKernel } from '../normalize/amazon-linux-kernel.mjs';
import { loadThresholds } from '../lib/config.mjs';
import { loadPythonNoReleaseImpact } from '../lib/python-no-release-impact.mjs';
import { buildPhpRuntime, buildNodeRuntime, buildPythonRuntime } from '../normalize/runtimes.mjs';
import { normalizeJpAlerts, newItems } from '../normalize/jp-alerts.mjs';
import { planPackagistFetch, applyPackagist } from '../normalize/packagist.mjs';
import { readOsvRecord, zipPathOf, ECOSYSTEMS } from '../collect/osv-db.mjs';
import { advisoryMapOf } from './central-data.mjs';

const UNATTEMPTED = { ok: false, records: [], error: { kind: 'skipped', message: '実行されませんでした', http_status: null } };

// KEV のうち Linux カーネルの CVE。KEV の取得に失敗した回は、前回保存した kev: true を使う
export function kevLinuxCvesOf(kevResult, previous) {
  if (kevResult?.ok) return new Set(kevResult.records.filter((r) => r.vendorProject === 'Linux' && r.product === 'Kernel').map((r) => r.cveID));
  return new Set((previous?.cves ?? []).filter((c) => c.kev).map((c) => c.cve));
}

// 段2: 情報源ごとに独立して収集する（1つ失敗しても続ける）。EPSS は照合の後に CVE を絞って取得する（stage-match）
export async function collectAll({ collectors, http, env, now, data }) {
  const packagistPlan = planPackagistFetch(data.packagist, now);
  const results = {};
  const thresholds = loadThresholds();
  const options = {
    kev: {}, 'node-core': { previousShas: previousNodeCoreShas(data.advisories) }, 'php-ghsa': { env }, 'python-psf': { env }, packagist: { updatedSince: packagistPlan.updatedSince },
  };
  // alas は kev の結果を使うので、kev を取得したあとで options を作る（COLLECTORS の最後に置いてある）
  const alasOptions = () => ({
    previous: data.amazonLinuxKernel, kevLinuxCves: kevLinuxCvesOf(results.kev, data.amazonLinuxKernel),
    maxPerRun: thresholds.alas_max_per_run, concurrency: thresholds.alas_concurrency,
  });
  for (const [name, collect] of Object.entries(collectors)) {
    if (name === 'epss') continue;
    try { results[name] = await collect({ http, env, now, ...(name === 'alas' ? alasOptions() : options[name] ?? {}) }); } catch (error) {
      results[name] = { ...UNATTEMPTED, error: { kind: 'exception', message: error.message, http_status: null } };
    }
  }
  return { results, packagistPlan };
}

// OSV の情報源を、どの DB から読み直すか。保存した ecosystem → affected の osv 由来の要素 → advisory.ecosystem の順
// （PSF を先に取り込んだ CVE に PyPI の記録が後から統合されると、advisory.ecosystem は python のままになるため）
export function osvSourceEcosystem(advisory, source) {
  if (source.ecosystem) return source.ecosystem;
  const tag = `osv:${source.id}`;
  const fromAffected = new Set(advisory.affected.filter((a) => (a.from_sources ?? []).includes(tag)).map((a) => a.package?.ecosystem));
  return fromAffected.size === 1 ? [...fromAffected][0] : advisory.ecosystem;
}

// 保存済みの OSV 由来のアドバイザリを、その回に取得できた DB から読み直した記録の一覧（run-match も共用する）
export async function refreshOsvAdvisories({ advisories, osvDbDir, osvFetchedThisRun, now }) {
  const records = [];
  for (const advisory of advisories.filter((a) => !a.superseded_by)) {
    for (const source of advisory.sources.filter((s) => s.name === 'osv')) {
      const eco = osvSourceEcosystem(advisory, source);
      if (!ECOSYSTEMS.includes(eco) || !osvFetchedThisRun[eco]) continue;
      const raw = await readOsvRecord(zipPathOf(osvDbDir, eco), source.id).catch(() => null);
      if (raw) records.push(fromOsv(raw, { now, dbEcosystem: eco }));
    }
  }
  return records;
}

// PSF と python.org の両方を取得できた回だけ、CPython のアドバイザリを取り込む（不変条件5）。pending は取り込めなかった回は null
function pythonPsfRecords({ results, now }) {
  if (!results['python-psf']?.ok || !results['python-releases']?.ok) return { records: [], pending: null };
  const releases = results['python-releases'].records;
  const options = { now, releases, noImpact: loadPythonNoReleaseImpact(), graceDays: loadThresholds().python_release_grace_days };
  const converted = results['python-psf'].records.map((raw) => ({ raw, ...fromPythonPsf(raw, options) }));
  const pending = [
    ...converted.filter((c) => c.pendingReason).map((c) => ({ id: c.raw.id, reason: c.pendingReason })),
    ...(results['python-psf'].missing ?? []).map((id) => ({ id, reason: 'osv_missing' })),
  ];
  return { records: converted.map((c) => c.record), pending };
}

// 段3: 正規化。失敗した情報源は前回のデータを残す。OSV 由来のアドバイザリは、保存済みのものを DB から取り直して更新を追跡する
export async function normalizeAll({ results, packagistPlan, data, osvDbDir, osvFetchedThisRun, now }) {
  const records = [];
  if (results['php-ghsa']?.ok) records.push(...results['php-ghsa'].records.map((r) => fromPhpGhsa(r, { now })));
  if (results['node-core']?.ok) records.push(...results['node-core'].records.map((r) => fromNodeCore(r, { now })));
  const python = pythonPsfRecords({ results, now });
  records.push(...python.records);
  records.push(...await refreshOsvAdvisories({ advisories: data.advisories, osvDbDir, osvFetchedThisRun, now }));
  const merged = mergeAdvisories({ previous: data.advisories, records, now });
  const advisories = advisoryMapOf(data.advisories);
  for (const [key, value] of merged) advisories.set(key, value);
  const list = () => [...advisories.values()];

  const okRecords = (name) => (results[name]?.ok ? results[name].records : null);
  const runtimes = {
    php: buildPhpRuntime({ previous: data.runtimes.php, phpReleases: okRecords('php-releases'), endoflife: okRecords('endoflife'), advisories: list(), now }),
    nodejs: buildNodeRuntime({ previous: data.runtimes.nodejs, nodeDist: okRecords('node-dist'), endoflife: okRecords('endoflife'), advisories: list(), now }),
    python: buildPythonRuntime({ previous: data.runtimes.python, pythonReleases: okRecords('python-releases'), endoflife: okRecords('endoflife-python'), advisories: list(), pending: python.pending, now }),
  };
  const jpAlerts = normalizeJpAlerts({ previous: data.jpAlerts, results: { jpcert: results.jpcert ?? UNATTEMPTED, ipa: results.ipa ?? UNATTEMPTED, jvn: results.jvn ?? UNATTEMPTED }, now });
  const packagist = applyPackagist({ previous: data.packagist, plan: packagistPlan, result: results.packagist ?? UNATTEMPTED, now });
  const amazonLinuxKernel = buildAmazonLinuxKernel({
    previous: data.amazonLinuxKernel, result: results.alas ?? UNATTEMPTED, kevRecords: okRecords('kev'), now, thresholds: loadThresholds(),
  });
  return { advisories, runtimes, jpAlerts, packagist, amazonLinuxKernel, jpNew: newItems(data.jpAlerts, jpAlerts) };
}
