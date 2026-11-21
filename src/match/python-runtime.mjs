import { comparePython, pythonBranch } from '../lib/versions-python.mjs';
import { loadThresholds } from '../lib/config.mjs';

// CPython の照合の補助（純粋関数）。版の実在確認・猶予期間・照合の完全性を、runtime-match と check-summary で共有する
const MS_PER_DAY = 86_400_000;
const MAX_LISTED_PENDING = 5;

// 版の実在確認は、そのブランチの branches[].versions（python.org の正式版）との完全一致。{ date } か null
export function releaseOf(data, version) {
  const branch = pythonBranch(version);
  return data?.branches?.find((b) => b.branch === branch)?.versions?.find((v) => v.version === version) ?? null;
}

// 猶予期間の基準は照合の now ではなく psf_synced_at（そのデータを取り込んだ時刻）。日付がない・取り込み時刻が null なら猶予中として扱う
export function graceEnd(release, graceDays) {
  return release?.date ? new Date(Date.parse(release.date) + graceDays * MS_PER_DAY) : null;
}
export function inGrace(data, release, graceDays) {
  const end = graceEnd(release, graceDays);
  return !end || !data?.psf_synced_at || Date.parse(data.psf_synced_at) < end.getTime();
}

// affected に版があれば影響あり（修正版は同じブランチのものだけ）。review_below より小さい版は根拠がないので要確認
export function pythonRangeJudgement(range, version) {
  if (range.type !== 'PY_VERSIONS') return { hit: false, review: true };
  if (range.affected.includes(version)) return { hit: true, fixed: (range.fixed ?? []).filter((v) => pythonBranch(v) === pythonBranch(version)) };
  return { hit: false, review: Boolean(range.review_below) && comparePython(version, range.review_below) < 0 };
}

// 「そのブランチの範囲があるか」。php は範囲の branch、python は affected にそのブランチの版があるか
export const hasBranchRange = (name, advisory, branch) => (name === 'python'
  ? advisory.ranges.some((r) => r.type === 'PY_VERSIONS' && r.affected.some((v) => pythonBranch(v) === branch))
  : advisory.ranges.some((r) => r.branch === branch));

// python が対象の案件の照合の完全性。不完全なら中央は partial、ローカルは照合不完全にする（不変条件8）
export function runtimeErrors({ inventory, runtimeData, graceDays = loadThresholds().python_release_grace_days }) {
  const runtime = inventory.runtimes.python;
  if (!runtime) return [];
  const data = runtimeData.python;
  const errors = [];
  const target = runtime.source ?? 'python';
  if (!runtime.version) {
    errors.push({ kind: 'inventory', target, message: 'CPython の版が確定しません（.security/stack.yml の runtimes.python に本番の版を申告してください）' });
  } else {
    const release = releaseOf(data, runtime.version);
    if (!release) {
      errors.push({ kind: 'inventory', target, message: `版 ${runtime.version} を python.org の正式版の一覧で確かめられません（.security/stack.yml の runtimes.python を確認してください）` });
    } else if (inGrace(data, release, graceDays)) {
      const until = graceEnd(release, graceDays)?.toISOString().slice(0, 10) ?? '不明';
      errors.push({ kind: 'source', target: 'python-psf', message: `版 ${runtime.version} はリリースから ${graceDays} 日以内で、OSV の補完を確認できません（${until} 以降に判定します）` });
    }
  }
  const pending = data?.pending ?? [];
  if (!data) errors.push({ kind: 'source', target: 'python-psf', message: 'CPython の脆弱性データがありません' });
  else if (pending.length > 0) {
    const ids = pending.slice(0, MAX_LISTED_PENDING).map((p) => p.id).join('、');
    errors.push({ kind: 'source', target: 'python-psf', message: `CPython の判定が保留の PSF アドバイザリが ${pending.length}件あります（${ids}${pending.length > MAX_LISTED_PENDING ? ' ほか' : ''}）` });
  }
  return errors;
}
