import { sharesAlias } from '../lib/aliases.mjs';
import { mergeWithFeed } from './findings-merge-feed.mjs';

// 最重要: 設計書 §6.4 / 指示書 §6.5 の保存規則。純粋関数（入力を書き換えない）
const locationKey = (l) => `${l.lockfile}|${l.package}|${l.installed_version}`;
const locationOrder = (a, b) => a.lockfile.localeCompare(b.lockfile) || a.package.localeCompare(b.package) || String(a.installed_version).localeCompare(String(b.installed_version));
const uniq = (values) => [...new Set(values)].sort();
const clone = (value) => JSON.parse(JSON.stringify(value));

// 項目の last_confirmed_* は「少なくとも1箇所で最後に確認した時点」（全箇所の確認を意味しない）
function withDerivedConfirmation(item) {
  const newest = [...item.locations].sort((a, b) => b.last_confirmed_at.localeCompare(a.last_confirmed_at))[0];
  return { ...item, locations: [...item.locations].sort(locationOrder), last_confirmed_at: newest.last_confirmed_at, last_confirmed_provenance: newest.last_confirmed_provenance };
}

const isMixed = (locations) => locations.some((l) => l.ecosystem === 'runtime') && locations.some((l) => l.ecosystem !== 'runtime');
// 混在 item になったとき、箇所ごとの値がない箇所には、その箇所を持っていた item の値を入れる
const withLocationValues = (location, item) => (location.judgement ? location : { ...location, fixed_versions: item.fixed_versions, judgement: item.judgement });

function mergeItem(before, now) {
  const byKey = new Map(before.locations.map((l) => [locationKey(l), l]));
  const retained = before.locations.some((l) => !now.locations.some((n) => locationKey(n) === locationKey(l)));
  for (const location of now.locations) byKey.set(locationKey(location), location); // 再検出した箇所だけ根拠を更新
  let locations = [...byKey.values()];
  if (isMixed(locations)) {
    const fromNow = new Set(now.locations.map(locationKey));
    locations = locations.map((l) => withLocationValues(l, fromNow.has(locationKey(l)) ? now : before));
  }
  // 前回の箇所を保持したまま、今回の照合で item 全体が要確認・P3 に下がらないようにする（前回 affected・今回 needs_review のときだけ）
  const hold = retained && before.judgement === 'affected' && now.judgement === 'needs_review';
  return withDerivedConfirmation({
    ...now, aliases: uniq([...before.aliases, ...now.aliases]), locations,
    ...(hold ? { judgement: 'affected', priority: before.priority, fixed_versions: uniq([...before.fixed_versions, ...now.fixed_versions]), kev: before.kev === true || now.kev === true } : {}),
    issue_number: before.issue_number ?? now.issue_number ?? null, first_detected_at: before.first_detected_at,
  });
}

const findPrevious = (previousItems, item) => previousItems.find((p) => sharesAlias(p.aliases, item.aliases));

export function mergeFindings({ previous, current, status, signals = null, ctx = null }) {
  const { project, monitor_ref: monitorRef, inventory_status: inventoryStatus, scan_status: scanStatus, scan_errors: scanErrors, provenance, scanned_at: scannedAt, inventory_as_of: inventoryAsOf } = status;
  const previousItems = previous?.items ?? [];
  let items;
  if (signals) {
    items = mergeWithFeed({ previousItems, current, scanStatus, signals, ctx });
  } else if (scanStatus === 'complete') {
    items = current.map((item) => {
      const before = findPrevious(previousItems, item);
      return withDerivedConfirmation({ ...item, issue_number: before?.issue_number ?? item.issue_number ?? null, first_detected_at: before?.first_detected_at ?? item.first_detected_at });
    });
  } else if (scanStatus === 'partial') {
    // 項目も location も削除しない。新しい検出は別名が一致すれば統合し、なければ追加する
    const merged = previousItems.map(clone);
    for (const item of current) {
      const index = merged.findIndex((p) => sharesAlias(p.aliases, item.aliases));
      if (index >= 0) merged[index] = mergeItem(merged[index], item);
      else merged.push(withDerivedConfirmation(item));
    }
    items = merged;
  } else {
    items = previousItems.map(clone);
  }
  return {
    project, monitor_ref: monitorRef, scanned_at: scannedAt,
    // inventory が取得できなかった回は前回の時点を維持する（古い構成が最新に見えないように）
    inventory_as_of: inventoryStatus === 'unavailable' ? (previous?.inventory_as_of ?? inventoryAsOf ?? null) : inventoryAsOf,
    inventory_status: inventoryStatus, scan_status: scanStatus, scan_errors: scanErrors, provenance,
    items: items.sort((a, b) => (a.advisory_key < b.advisory_key ? -1 : 1)),
  };
}
