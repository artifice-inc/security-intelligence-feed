// テスト用の OSV レコード（形式は OSV スキーマ。内容は架空）
export const osvRecord = (overrides = {}) => ({
  id: 'GHSA-aaaa-bbbb-cccc',
  aliases: [],
  modified: '2026-10-01T00:00:00Z',
  published: '2026-09-01T00:00:00Z',
  summary: 'Example vulnerability',
  database_specific: { severity: 'HIGH' },
  affected: [{
    package: { ecosystem: 'npm', name: 'example-package' },
    ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '1.2.3' }] }],
  }],
  ...overrides,
});
