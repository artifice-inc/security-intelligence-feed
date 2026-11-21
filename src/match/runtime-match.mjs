import semver from 'semver';
import { isPhpBranchAffected, phpBranch } from '../lib/versions-php.mjs';
import { loadRuntimeConditions } from '../lib/config.mjs';
import { pythonBranch } from '../lib/versions-python.mjs';
import { releaseOf, pythonRangeJudgement, hasBranchRange } from './python-runtime.mjs';

// 純粋関数。runtimes は inventory.runtimes（{php, node}）、data は data/runtimes/{php,nodejs}.json の内容
const NO_SOURCE = '(未検出)';

// このプロジェクトで対象になるランタイム。依存ファイルやランタイムの手がかりがなければ対象外とする
export function relevantRuntimes(inventory) {
  const kinds = new Set(inventory.files.map((f) => f.path.split('/').pop()));
  const has = (...names) => names.some((n) => kinds.has(n));
  return {
    php: has('composer.json', 'composer.lock') || Boolean(inventory.runtimes.php.version || inventory.runtimes.php.constraint),
    node: has('package.json', 'package-lock.json', 'yarn.lock', 'pnpm-lock.yaml') || Boolean(inventory.runtimes.node.version || inventory.runtimes.node.constraint),
    python: Boolean(inventory.runtimes.python),
  };
}

const location = (runtime, name, version) => ({ lockfile: runtime.source ?? NO_SOURCE, package: name, ecosystem: 'runtime', installed_version: version });

function advisoryJudgement(runtimeName, version, advisory) {
  let unparsed = false;
  const fixed = [];
  let affected = false;
  for (const range of advisory.ranges) {
    // ブランチが分かっている UNPARSED は、そのブランチの版だけを needs_review にする（版が解釈できなければ安全側）
    if (range.type === 'UNPARSED') {
      const otherBranch = range.branch && phpBranch(version) && range.branch !== phpBranch(version);
      if (!otherBranch) unparsed = true;
      continue;
    }
    if (runtimeName === 'python') {
      const result = pythonRangeJudgement(range, version);
      if (result.hit) { affected = true; fixed.push(...result.fixed); } else if (result.review) unparsed = true;
    } else if (runtimeName === 'php') {
      const hit = isPhpBranchAffected(range, version);
      if (hit === null) { unparsed = true; continue; }
      if (hit) { affected = true; fixed.push(range.fixed); }
    } else {
      try {
        if (semver.satisfies(version, range.vulnerable) && !semver.satisfies(version, range.patched)) {
          affected = true;
          fixed.push(...range.fixed_versions.filter((v) => semver.major(v) === semver.major(version)));
        }
      } catch { unparsed = true; }
    }
  }
  if (affected) return { judgement: 'affected', fixed };
  return { judgement: unparsed ? 'needs_review' : 'not_affected', fixed: [] };
}

// OS に条件のあるアドバイザリ（config/runtime-conditions.json）。key か aliases のどれかで引く
const conditionOf = (conditions, name, advisory) => [advisory.key, ...advisory.aliases].map((k) => conditions[name]?.[k]).find(Boolean) ?? null;
const OS_LABEL = { linux: 'Linux', windows: 'Windows' };

// affected の判定に OS の条件を重ねる。os が申告されていなければ affected のまま（案内を足す）。条件外の OS なら needs_review に倒す（not_affected にはしない）
function applyOsCondition({ judgement, evidence }, condition, os) {
  if (judgement !== 'affected' || !condition?.os) return { judgement, evidence };
  if (!os) return { judgement, evidence: `${evidence}（OS の条件あり。.security/stack.yml に os を申告すると判定できます）` };
  if (condition.os.includes(os)) return { judgement, evidence };
  return { judgement: 'needs_review', evidence: `${condition.os.map((o) => OS_LABEL[o]).join('・')} に限られる脆弱性。申告 os=${os} のため影響は低いと考えられるが要確認` };
}

// EOL ブランチの版は、範囲に出てこなくても「修正の対象外」なだけかもしれない。EOL 後に公開され、そのブランチの範囲がなければ判定不能とする（PHP と Python のみ。node には効かせない）
function eolBranchReview(name, advisory, branch, info) {
  if (!info?.is_eol || !advisory.published_at || !info.security_support_end) return null;
  if (hasBranchRange(name, advisory, branch)) return null;
  if (Date.parse(advisory.published_at) <= Date.parse(info.security_support_end)) return null;
  return `EOL のブランチ ${branch} は修正の対象外で、影響の有無を判定できません（公開 ${advisory.published_at.slice(0, 10)}、${branch} のサポート終了 ${info.security_support_end}）`;
}

// reason: 版が分かっていても確定できない理由（python の実在確認）
function unknownItem(name, runtime, reason = null) {
  const detail = reason ?? (runtime.constraint ? `制約 ${runtime.constraint}（${runtime.source}）しか分かりません` : '版を検出できませんでした');
  return {
    advisory_key: `RUNTIME-UNKNOWN-${name}`, aliases: [`RUNTIME-UNKNOWN-${name}`], title: `${name} の版が確定しません`, ecosystem: 'runtime',
    locations: [location(runtime, name, reason ? runtime.version : runtime.constraint)], fixed_versions: [], source_urls: [],
    judgement: 'needs_review', evidence: `${name}: ${detail}。.security/stack.yml の runtimes に本番の版を申告してください`, severity_hint: null,
  };
}

export function matchRuntimes({ inventory, runtimeData, conditions = loadRuntimeConditions() }) {
  const detections = [];
  const relevant = relevantRuntimes(inventory);
  for (const [name, data] of [['php', runtimeData.php], ['node', runtimeData.nodejs], ['python', runtimeData.python]]) {
    if (!relevant[name]) continue;
    const runtime = inventory.runtimes[name];
    if (!runtime.version) { detections.push(unknownItem(name, runtime)); continue; }
    // python は、版が python.org の正式版の一覧に完全一致で載っているときだけ照合する（データより新しい版や誤記を「影響なし」にしない）
    if (name === 'python' && !releaseOf(data, runtime.version)) { detections.push(unknownItem(name, runtime, `版 ${runtime.version} は python.org の正式版の一覧にありません`)); continue; }
    const branch = name === 'python' ? pythonBranch(runtime.version) : (name === 'php' ? runtime.version.split('.').slice(0, 2) : runtime.version.split('.').slice(0, 1)).join('.');
    const info = data?.branches?.find((b) => b.branch === branch);
    for (const advisory of data?.advisories ?? []) {
      const { judgement: ranged, fixed } = advisoryJudgement(name, runtime.version, advisory);
      let judgement = ranged;
      let reviewReason = null;
      if (judgement === 'not_affected' && (name === 'php' || name === 'python')) {
        reviewReason = eolBranchReview(name, advisory, branch, info);
        if (reviewReason) judgement = 'needs_review';
      }
      if (judgement === 'not_affected') continue;
      const base = judgement === 'affected' ? `${name} ${runtime.version} は ${advisory.key} の影響範囲内（${runtime.source}）` : `${name} ${runtime.version} は ${advisory.key} の範囲を解釈できません`;
      const checked = applyOsCondition({ judgement, evidence: reviewReason ?? base }, conditionOf(conditions, name, advisory), inventory.os ?? null);
      detections.push({
        advisory_key: advisory.key, aliases: advisory.aliases, title: advisory.key, ecosystem: 'runtime',
        locations: [location(runtime, name, runtime.version)], fixed_versions: [...new Set(fixed)].sort(),
        source_urls: advisory.source_urls, judgement: checked.judgement, evidence: checked.evidence, severity_hint: null,
      });
    }
    if (info?.is_eol) {
      const key = `EOL-${name}-${branch}`;
      detections.push({
        advisory_key: key, aliases: [key], title: `${name} ${branch} はサポート終了（EOL）です`, ecosystem: 'runtime',
        locations: [location(runtime, name, runtime.version)], fixed_versions: info.latest_version ? [info.latest_version] : [],
        source_urls: [], judgement: 'affected', evidence: `${name} ${runtime.version}（${runtime.source}）のブランチ ${branch} は EOL です`, severity_hint: null,
      });
    }
  }
  return detections;
}
