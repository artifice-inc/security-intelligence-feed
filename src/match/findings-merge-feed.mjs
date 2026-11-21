import { connectedComponents, canonicalKey } from '../lib/aliases.mjs';
import { resolvePriority, maxSeverity } from './priority-inputs.mjs';
import { locationKey, locationOrder, uniq, withValues, dedupeValued, compactValues } from './location-values.mjs';

// 新しい経路（signals あり）の統合。今回と前回の項目を合わせた別名の連結成分ごとに1項目を作り、優先度は自動で下げない
const clone = (value) => JSON.parse(JSON.stringify(value));
const byKey = (a, b) => (a.advisory_key < b.advisory_key ? -1 : a.advisory_key > b.advisory_key ? 1 : 0);
const earliest = (values) => [...values].sort()[0];
const valuedLocations = (item) => item.locations.map((l) => withValues(l, item));

function withDerivedConfirmation(item) {
  const newest = [...item.locations].sort((a, b) => b.last_confirmed_at.localeCompare(a.last_confirmed_at))[0];
  return { ...item, locations: [...item.locations].sort(locationOrder), last_confirmed_at: newest.last_confirmed_at, last_confirmed_provenance: newest.last_confirmed_provenance };
}

// 今回の項目が2つ以上ある成分を1つに束ねる（箇所は1行にまとめ、深刻度は項目ごとの値のうち最も高いものを使う）
function bundleCurrent(items) {
  if (items.length === 1) return items[0];
  const sorted = [...items].sort(byKey);
  const aliases = uniq(sorted.flatMap((i) => [i.advisory_key, ...i.aliases]));
  const locations = compactValues(dedupeValued(sorted.flatMap(valuedLocations)));
  const inputsOf = (i) => i.priority_inputs ?? {};
  return {
    ...sorted[0],
    advisory_key: canonicalKey(aliases), aliases, locations,
    fixed_versions: uniq(sorted.flatMap((i) => i.fixed_versions)),
    source_urls: uniq(sorted.flatMap((i) => i.source_urls ?? [])),
    judgement: sorted.some((i) => i.judgement === 'affected') ? 'affected' : 'needs_review',
    kev: sorted.some((i) => i.kev === true),
    evidence: sorted.map((i) => i.evidence).sort()[0],
    first_detected_at: earliest(sorted.map((i) => i.first_detected_at)),
    priority_inputs: {
      ...inputsOf(sorted[0]), severity: maxSeverity(sorted.map((i) => inputsOf(i).severity)),
      exposure: sorted.map((i) => inputsOf(i).exposure).find(Boolean) ?? null, malicious: sorted.some((i) => inputsOf(i).malicious === true),
    },
  };
}

// 前回の箇所は箇所ごとの値を付けて1つにまとめる。入力は advisory_key の昇順
function collectPreviousLocations(previous) {
  return dedupeValued(previous.flatMap(valuedLocations));
}

function mergePartial(previous, now) {
  const previousLocations = collectPreviousLocations(previous);
  const redetected = new Set(now.locations.map(locationKey));
  const retained = previousLocations.filter((l) => !redetected.has(locationKey(l)));
  const byLocation = new Map(previousLocations.map((l) => [locationKey(l), l]));
  for (const l of valuedLocations(now)) byLocation.set(locationKey(l), l); // 再検出した箇所だけ根拠を更新
  const locations = compactValues([...byLocation.values()].sort(locationOrder));
  const hold = now.judgement === 'needs_review' && retained.some((l) => l.judgement === 'affected');
  return { locations, hold };
}

function mergeComponent({ previous, bundled, scanStatus, signals, ctx }) {
  const aliases = uniq([...bundled.aliases, ...previous.flatMap((p) => p.aliases)]);
  let locations = bundled.locations;
  let hold = false;
  if (scanStatus === 'partial' && previous.length > 0) ({ locations, hold } = mergePartial(previous, bundled));
  else if (locations.some((l) => l.judgement)) locations = compactValues(locations.map((l) => withValues(l, bundled)));
  const judgement = hold ? 'affected' : bundled.judgement;
  const { aliases: unionAliases, ...resolved } = resolvePriority({
    previousItems: previous, current: { ...bundled, aliases, judgement }, signals, ctx, thresholds: signals.thresholds,
  });
  const numbers = previous.map((p) => p.issue_number).filter((n) => typeof n === 'number');
  const { priority_note: note, ...rest } = resolved;
  const { priority_note: staleNote, ...base } = bundled;
  return withDerivedConfirmation({
    ...base, aliases: unionAliases, locations, judgement, kev: resolved.kev, priority: resolved.priority,
    ...(hold ? { fixed_versions: uniq([...previous.flatMap((p) => p.fixed_versions), ...bundled.fixed_versions]) } : {}),
    ...(note ? { priority_note: note } : {}), priority_inputs: rest.priority_inputs,
    issue_number: numbers.length > 0 ? Math.min(...numbers) : bundled.issue_number ?? null,
    first_detected_at: earliest([...previous.map((p) => p.first_detected_at), ...(previous.length === 0 ? [bundled.first_detected_at] : [])]),
  });
}

export function mergeWithFeed({ previousItems, current, scanStatus, signals, ctx }) {
  if (scanStatus !== 'complete' && scanStatus !== 'partial') return previousItems.map(clone);
  const nodes = [...previousItems.map((p) => ({ item: p, isPrevious: true })), ...current.map((c) => ({ item: c, isPrevious: false }))];
  const components = connectedComponents(nodes.map(({ item }) => [item.advisory_key, ...item.aliases]));
  const items = components.flatMap((component) => {
    const members = component.indexes.map((i) => nodes[i]);
    const now = members.filter((m) => !m.isPrevious).map((m) => m.item);
    const previous = members.filter((m) => m.isPrevious).map((m) => clone(m.item)).sort(byKey);
    if (now.length === 0) return scanStatus === 'partial' ? previous : [];
    return [mergeComponent({ previous, bundled: bundleCurrent(now), scanStatus, signals, ctx })];
  });
  return items;
}
