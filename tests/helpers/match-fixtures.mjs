import path from 'node:path';

export const PROVENANCE = { scanner_version: '2.7.0', script_version: 'sha-1', osv_db: { npm: { fetched_at: '2026-10-25T00:00:00Z', sha256: 'a'.repeat(64) } }, inventory_commit: 'abc' };
export const NOW = '2026-10-25T00:00:00Z';

export const inventoryOf = (overrides = {}) => ({
  project: 'demo', mode: 'pull', monitor_ref: 'master', source_commit: 'abc', inventory_as_of: NOW,
  files: [{ path: 'package-lock.json', sha256: 'a'.repeat(64), kind: 'lockfile' }, { path: 'package.json', sha256: 'b'.repeat(64), kind: 'package-json' }],
  runtimes: { php: { version: null, constraint: null, source: null }, node: { version: '22.11.0', constraint: null, source: '.nvmrc' } },
  exposure: 'internet', lockfiles: ['package-lock.json'], ...overrides,
});

// OSV-Scanner の JSON 出力（公式 output.md の構造）を模した記録
export const scannerOutput = (root, vulns = [{ id: 'GHSA-aaaa-bbbb-cccc', aliases: ['CVE-2026-1'], severity: 'HIGH', fixed: '1.2.3' }], version = '1.2.0') => JSON.stringify({
  results: [{
    source: { path: path.join(root, 'package-lock.json'), type: 'lockfile' },
    packages: [{
      package: { name: 'example-package', version, ecosystem: 'npm' },
      vulnerabilities: vulns.map((v) => ({
        id: v.id, aliases: v.aliases, summary: `Example ${v.id}`, database_specific: { severity: v.severity },
        affected: [{ package: { ecosystem: 'npm', name: 'example-package' }, ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: v.fixed }] }] }],
      })),
      groups: [{ ids: vulns.map((v) => v.id) }],
    }],
  }],
});

export const stubExec = (code, stdout) => { const calls = []; const exec = async (cmd, args, options) => { calls.push({ cmd, args, options }); return { code, stdout }; }; exec.calls = calls; return exec; };

// runOsvScan の入力: 元の相対パスと、スキャナに渡す絶対パス
export const inputsOf = (root, files) => files.map((file) => ({ file, scanPath: path.join(root, file) }));
