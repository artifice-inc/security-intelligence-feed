import { mkdirSync, writeFileSync, readFileSync, mkdtempSync, cpSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';

const ROOT = path.resolve(import.meta.dirname, '..', '..');
const FIXTURE_DIR = path.join(ROOT, 'tests', 'fixtures', 'feed');
const writeJson = (dir, rel, value) => {
  mkdirSync(path.dirname(path.join(dir, rel)), { recursive: true });
  writeFileSync(path.join(dir, rel), JSON.stringify(value));
};

// 正しい一式のフィード（data/ のルート）を一時ディレクトリに作る。固定の最小データ（tests/fixtures/feed）を土台にする
export function makeValidFeed() {
  const dir = mkdtempSync(path.join(tmpdir(), 'feed-'));
  const slot = '2026-11-21T07:17Z';
  writeJson(dir, 'feed-format.json', { format_version: 1 });
  writeJson(dir, 'health.json', {
    run_slot: slot,
    last_run: { started_at: '2026-11-21T07:20:00Z', finished_at: '2026-11-21T07:25:00Z', status: 'success' },
    last_success_at: '2026-11-21T07:25:00Z',
    sources: { kev: { last_attempt_at: '2026-11-21T07:20:00Z', last_success_at: '2026-11-21T07:20:00Z', last_attempt_slot: slot, last_success_slot: slot, last_attempt_ok: true, last_error: null } },
    packagist_updated_since: null,
  });
  cpSync(FIXTURE_DIR, dir, { recursive: true });
  writeJson(dir, 'kev.json', { fetched_at: '2026-11-21T07:20:00Z', ok: true, catalog_version: '1', records: [{ cveID: 'CVE-2026-1', vendorProject: 'Example', product: 'Example', dateAdded: '2026-11-20', knownRansomwareCampaignUse: 'Unknown' }] });
  writeJson(dir, 'epss-high.json', { fetched_at: '2026-11-21T07:20:00Z', ok: true, model_version: 'v1', score_date: '2026-11-20', threshold: 0.5, records: [{ cve: 'CVE-2026-1', epss: 0.9, percentile: 0.99 }] });
  return dir;
}

export { writeJson };
