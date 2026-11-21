// CPython 関連のテスト用データ（形は実物の PSF / OSV GIT / python.org / endoflife.date。内容は縮めてある）
export const T = '2026-11-19T03:00:00Z';

// OSV の GIT/<PSF-ID>.json。versions は OSV が補った影響タグ
export const psfRecord = (id, versions, overrides = {}) => ({
  id, aliases: ['CVE-2026-2297', 'BIT-python-2026-2297'], published: '2026-03-01T00:00:00Z', modified: '2026-10-09T00:00:00Z',
  summary: 'Example CPython bug', details: 'Example details\nsecond line',
  affected: [{ package: { ecosystem: 'GIT', name: 'https://github.com/python/cpython' }, ranges: [{ type: 'GIT', events: [{ introduced: '0' }, { fixed: 'abc123' }] }], versions }],
  ...overrides,
});

export const TAGS_3_12 = ['v3.12.0', 'v3.12.1', 'v3.12.7', 'v3.12.13', 'v3.12.0rc1', 'v3.13.0a6', 'v3.13.0'];

// python.org の一覧（rc・a・b を含む）
export const pythonOrgRelease = (version, date, pre = false) => ({ name: `Python ${version}`, pre_release: pre, release_date: `${date}T00:00:00Z` });
export const pythonOrgList = (extra = []) => [
  pythonOrgRelease('3.12.0', '2023-10-02'), pythonOrgRelease('3.12.7', '2024-10-01'), pythonOrgRelease('3.12.13', '2026-02-03'),
  pythonOrgRelease('3.12.14', '2026-10-01'), pythonOrgRelease('3.12.16', '2026-10-25'), pythonOrgRelease('3.12.0rc1', '2023-09-01', true),
  pythonOrgRelease('3.13.0', '2024-10-07'), pythonOrgRelease('3.13.0', '2024-10-07'), { name: 'Python 3.14.0 rc1', pre_release: true, release_date: '2025-07-01T00:00:00Z' },
  { name: 'Python 2.7.18', pre_release: false, release_date: '2020-04-20T00:00:00Z' }, ...extra,
];

// collector の出力（python-releases）
export const releaseRecords = [
  { version: '3.12.0', date: '2023-10-02T00:00:00Z' }, { version: '3.12.7', date: '2024-10-01T00:00:00Z' }, { version: '3.12.13', date: '2026-02-03T00:00:00Z' },
  { version: '3.12.14', date: '2026-11-01T00:00:00Z' }, { version: '3.13.0', date: '2024-10-07T00:00:00Z' },
];

export const eolPython = [
  { product: 'python', name: '3.12', isEol: false, eolFrom: '2028-10-31', isLts: false, latest: '3.12.14' },
  { product: 'python', name: '3.8', isEol: true, eolFrom: '2024-10-07', isLts: false, latest: '3.8.20' },
];

export const NO_IMPACT = {
  'PSF-OLD-1': { decision: 'no_impact', min_version: '3.0.0', reason: '原典は Python 2 だけ', checked_at: '2026-11-19' },
  'PSF-ALPHA': { decision: 'no_impact', reason: 'alpha だけ', checked_at: '2026-11-19' },
  'PSF-MANUAL': { decision: 'manual_review', reason: '人が確認する', checked_at: '2026-11-19' },
};
