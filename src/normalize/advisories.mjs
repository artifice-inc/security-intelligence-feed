import { connectedComponents, splitAliases, canonicalKey, flatAliases } from '../lib/aliases.mjs';
import { contentHash } from '../lib/hash.mjs';
import { toIso } from '../lib/time.mjs';
import { ECOSYSTEMS } from '../collect/osv-db.mjs';

const sourceTag = (s) => `${s.name}:${s.id}`;
const byTag = (a, b) => (sourceTag(a) < sourceTag(b) ? -1 : 1);

const toStoredSource = (record) => ({
  name: record.source, id: record.id, url: record.url, published_at: record.published_at,
  source_modified_at: record.modified_at, fetched_at: record.fetched_at, content_hash: record.content_hash,
  withdrawn_at: record.withdrawn_at,
  // 実際に読んだ DB のエコシステム。影響範囲が消える取り下げのあとも、同じ DB から読み直せるようにする
  ...(record.source === 'osv' && ECOSYSTEMS.includes(record.db_ecosystem) ? { ecosystem: record.db_ecosystem } : {}),
});

// 同じ名前・IDの情報源は、内容ハッシュが同じなら前回の値（fetched_at を含む）を保つ
function mergeSources(previousSources, records) {
  const merged = new Map(previousSources.map((s) => [sourceTag(s), s]));
  for (const record of records) {
    const stored = toStoredSource(record);
    const before = merged.get(sourceTag(stored));
    if (before && before.content_hash === stored.content_hash) {
      // 内容が同じなら前回の値を保つ。前回に ecosystem がなく今回あるときだけ ecosystem を足す
      merged.set(sourceTag(stored), !before.ecosystem && stored.ecosystem ? { ...before, ecosystem: stored.ecosystem } : before);
    } else {
      // 今回の値がなければ、既知の ecosystem を消さない
      merged.set(sourceTag(stored), !stored.ecosystem && before?.ecosystem ? { ...stored, ecosystem: before.ecosystem } : stored);
    }
  }
  return [...merged.values()].sort(byTag);
}

// 取り下げられていない情報源の影響範囲だけから affected を作り直す（設計書 §5.2）
function rebuildAffected(previousAffected, records, sources) {
  const refreshed = new Set(records.map((r) => `${r.source}:${r.id}`));
  const live = new Set(sources.filter((s) => !s.withdrawn_at).map(sourceTag));
  const kept = previousAffected.filter((a) => (a.from_sources ?? []).every((tag) => !refreshed.has(tag) && live.has(tag)));
  const fresh = records.filter((r) => !r.withdrawn_at).flatMap((r) => r.affected);
  return [...kept, ...fresh].sort((a, b) => (contentHash(a) < contentHash(b) ? -1 : 1));
}

function chooseSeverity(records, previous) {
  const candidates = records.filter((r) => !r.withdrawn_at && r.severity.level);
  candidates.sort((a, b) => b.severity.rank - a.severity.rank || (a.id < b.id ? -1 : 1));
  const best = candidates[0];
  if (!best) return previous?.severity ?? { level: null, cvss_v3: null, cvss_v4: null, source: null };
  const { level, cvss_v3: cvssV3, cvss_v4: cvssV4, source } = best.severity;
  return { level, cvss_v3: cvssV3, cvss_v4: cvssV4, source };
}

function describeChanges(before, after) {
  if (!before) return [];
  const changes = [];
  if (contentHash(before.affected) !== contentHash(after.affected)) changes.push('affected');
  if (before.severity.level !== after.severity.level) changes.push('severity');
  if (before.status !== after.status) changes.push('status');
  const withdrawnOf = (a) => a.sources.filter((s) => s.withdrawn_at).map(sourceTag).join(',');
  if (withdrawnOf(before) !== withdrawnOf(after)) changes.push('withdrawn');
  if (contentHash(before.sources.map((s) => s.content_hash)) !== contentHash(after.sources.map((s) => s.content_hash)) && changes.length === 0) changes.push('source_content');
  return changes;
}

const SIGNIFICANT = new Set(['affected', 'severity', 'status', 'withdrawn']);

function buildAdvisory({ key, ids, base, records, previousMembers, now }) {
  const sources = mergeSources(previousMembers.flatMap((p) => p.sources), records);
  const affected = rebuildAffected(previousMembers.flatMap((p) => p.affected), records, sources);
  const live = sources.filter((s) => !s.withdrawn_at);
  const sourceRecords = records.length ? records : [];
  const first = [...sourceRecords].sort((a, b) => b.severity.rank - a.severity.rank)[0];
  const next = {
    key,
    aliases: splitAliases(ids),
    status: sources.length > 0 && live.length === 0 ? 'withdrawn' : 'active',
    superseded_by: null,
    category: base?.category ?? first?.category ?? 'dependency',
    ecosystem: base?.ecosystem ?? first?.ecosystem ?? 'unknown',
    title: first?.title ?? base?.title ?? key,
    affected,
    severity: chooseSeverity(sourceRecords, base),
    known_exploited: base?.known_exploited ?? { kev: false, date_added: null },
    epss: base?.epss ?? { score: null, percentile: null, date: null },
    jp_alerts: base?.jp_alerts ?? [],
    sources,
    first_seen_at: previousMembers.map((p) => p.first_seen_at).filter(Boolean).sort()[0] ?? toIso(now),
    history: base?.history ?? [],
    verification_status: sourceRecords.some((r) => r.verification_status === 'needs_review') ? 'needs_review'
      : base?.verification_status ?? 'source_structured',
  };
  const changes = describeChanges(base, next);
  if (changes.length > 0) {
    next.history = [...next.history, { at: toIso(now), changes, significant: changes.some((c) => SIGNIFICANT.has(c)) }];
  }
  return next;
}

// previous: 既存のアドバイザリ（ファイルの配列）。records: 今回得た情報源レコード
// 戻り値: { advisories: 変更・新規のあったものだけの Map(key → advisory) }
export function mergeAdvisories({ previous, records, now }) {
  const items = [
    ...previous.map((a) => [a.key, ...flatAliases(a)]),
    ...records.map((r) => r.ids),
  ];
  const result = new Map();
  for (const component of connectedComponents(items)) {
    const members = component.indexes.filter((i) => i < previous.length).map((i) => previous[i]);
    const newRecords = component.indexes.filter((i) => i >= previous.length).map((i) => records[i - previous.length]);
    if (newRecords.length === 0 && members.length <= 1) continue; // 変化なし
    const ids = [...new Set([...component.ids])];
    const key = canonicalKey(ids);
    const existing = members.find((m) => m.key === key) ?? null;
    const current = members.filter((m) => !m.superseded_by || m.key === key);
    // キーが変わる場合は、履歴・KEV・EPSS などを最初の旧ファイルから引き継ぐ
    const next = buildAdvisory({ key, ids, base: existing ?? current[0] ?? null, records: newRecords, previousMembers: current, now });
    if (!existing || contentHash(existing) !== contentHash(next)) result.set(key, next);
    for (const member of current) {
      if (member.key !== key && member.superseded_by !== key) result.set(member.key, { ...member, superseded_by: key });
    }
  }
  return result;
}

// 取り下げ済みでなく、付け替え済みでもない現行のアドバイザリ
export const isCurrent = (advisory) => !advisory.superseded_by;
