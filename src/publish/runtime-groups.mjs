import { priorityRank } from '../match/priority.mjs';

// ランタイムの脆弱性を「ランタイム・版」ごとの1つの issue item にまとめる純粋関数（findings は CVE ごとのまま変えない）
const RUNTIME = 'runtime';
const OS = 'os';
// os（Amazon Linux のカーネル）も同じ仕組みでまとめる。package の @ はマーカーの aliases に入れるため _ にする
export const groupKeyOf = (location) => (location.ecosystem === OS
  ? `KERNEL-${location.installed_version}-${location.package.replace(/@/g, '_')}`
  : `RUNTIME-${location.package}-${location.installed_version}`);

const isGroupable = (item) => item.locations.length > 0 && [RUNTIME, OS].some((eco) => item.locations.every((l) => l.ecosystem === eco)) && !item.advisory_key.startsWith('RUNTIME-UNKNOWN-');
const byPriorityThenKey = (a, b) => priorityRank(a.priority) - priorityRank(b.priority) || (a.advisory_key < b.advisory_key ? -1 : a.advisory_key > b.advisory_key ? 1 : 0);
const earliest = (values) => [...values].sort()[0];
const latest = (values) => [...values].sort().at(-1);

function buildGroup(key, location, entries) {
  const members = entries.map(({ item }) => ({
    advisory_key: item.advisory_key, aliases: item.aliases, priority: item.priority, judgement: item.judgement,
    fixed_versions: item.fixed_versions, kev: Boolean(item.kev), source_urls: item.source_urls,
  })).sort(byPriorityThenKey);
  const isOs = location.ecosystem === OS;
  const label = `${location.package} ${location.installed_version}`;
  const title = isOs ? `Amazon Linux ${location.installed_version.replace(/^al/, '')} のカーネル ${location.package} の脆弱性 ${members.length}件` : `${label} の脆弱性 ${members.length}件`;
  return {
    advisory_key: key, aliases: [key], title, ecosystem: location.ecosystem,
    locations: [{ ...location }], members,
    priority: members[0].priority,
    judgement: members.some((m) => m.judgement === 'affected') ? 'affected' : 'needs_review',
    kev: members.some((m) => m.kev && m.priority === 'P0'),
    kev_members: members.filter((m) => m.kev).map((m) => m.advisory_key),
    fixed_versions: [...new Set(members.flatMap((m) => m.fixed_versions))].sort(),
    source_urls: [],
    evidence: isOs ? `配布元（ALAS）のデータで、このカーネルに影響する重大な脆弱性 ${members.length}件をまとめています` : `${label} に影響する脆弱性 ${members.length}件をまとめています。内訳は表を参照してください`,
    first_detected_at: earliest(entries.map(({ item }) => item.first_detected_at)),
    last_confirmed_at: latest(entries.map(({ location: l }) => l.last_confirmed_at)),
    issue_number: null,
  };
}

// 戻り値: { issueItems, memberKeys }。location が複数ある item は、それぞれの location のまとめの member になる
export function runtimeGroups(items) {
  const passthrough = items.filter((item) => !isGroupable(item));
  const buckets = new Map();
  for (const item of items.filter(isGroupable)) {
    for (const location of item.locations) {
      const key = groupKeyOf(location);
      if (!buckets.has(key)) buckets.set(key, { location, entries: [] });
      buckets.get(key).entries.push({ item, location });
    }
  }
  const groups = [...buckets.entries()].sort(([a], [b]) => (a < b ? -1 : 1)).map(([key, { location, entries }]) => buildGroup(key, location, entries));
  return { issueItems: [...passthrough, ...groups], memberKeys: new Map(groups.map((g) => [g.advisory_key, g.members.map((m) => m.advisory_key)])) };
}

// member の advisory_key → Issue 番号。複数のまとめに入る member は、last_confirmed_at が新しい location のまとめを選ぶ（同じなら番号が小さい方）
export function memberNumbers(items, groupNumbers) {
  const best = new Map();
  for (const item of items.filter(isGroupable)) {
    for (const location of item.locations) {
      const number = groupNumbers.get(groupKeyOf(location));
      if (typeof number !== 'number') continue;
      const current = best.get(item.advisory_key);
      const newer = !current || location.last_confirmed_at > current.at || (location.last_confirmed_at === current.at && number < current.number);
      if (newer) best.set(item.advisory_key, { at: location.last_confirmed_at, number });
    }
  }
  return new Map([...best].map(([key, { number }]) => [key, number]));
}
