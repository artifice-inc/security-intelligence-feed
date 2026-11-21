import { sharesAlias } from '../lib/aliases.mjs';
import { LABELS } from './issue-body.mjs';

// 旧来の CVE ごとのランタイム Issue をまとめ Issue へ移すための目標の計算（純粋関数。API は呼ばない）

// 旧 Issue の aliases が重なる members を持つまとめのうち、番号が確定しているものの番号（なければ null）。matched: 重なるまとめがあったか
export function migrationDestination(issue, groupItems, groupNumbers) {
  const hits = groupItems.filter((g) => g.members.some((m) => sharesAlias(issue.marker.aliases, m.aliases)));
  const number = hits.map((g) => groupNumbers.get(g.advisory_key)).find((n) => typeof n === 'number') ?? null;
  return { matched: hits.length > 0, number };
}

// 対応する item がなくなったまとめ Issue（mk あり）の member が、まとめ以外の item（混在 item など）に移っていないか。
// matched: 移った member がある。number: 移り先の Issue 番号のうち最小のもの（まだ番号のない item があれば null＝その回は何もしない）
export function movedMembers(issue, issueItems, numbers) {
  const hits = issueItems.filter((item) => !item.members && sharesAlias(issue.marker.mk ?? [], item.aliases));
  if (hits.length === 0) return { matched: false, number: null };
  const found = hits.map((item) => numbers.get(item.advisory_key));
  return { matched: true, number: found.every((n) => typeof n === 'number') ? Math.min(...found) : null };
}

// カーネル（OS）のまとめ Issue か。サーバーの稼働状態を見ていないので、解消（fixed-in-repo）を付けない
export const isKernelGroupIssue = (issue) => (issue.marker?.aliases ?? []).some((a) => a.startsWith('KERNEL-'));

// 移行済み（sb あり）の Issue の目標。superseded を付け続け、fixed-in-repo は付けない。取り下げは移行と無関係に知らせる
export function migratedTarget(issue, { isWithdrawnAliases }) {
  const labels = new Set(issue.labels);
  const notices = [];
  labels.add(LABELS.superseded);
  labels.delete(LABELS.fixed);
  if (isWithdrawnAliases(issue.marker.aliases) && !labels.has(LABELS.withdrawn)) { labels.add(LABELS.withdrawn); notices.push(['withdrawn']); }
  return { labels, notices };
}

// 対応する item がなくなったまとめ Issue（mk あり）の目標。mk: 保存済みの members の advisory_key
// 全て取り下げ → advisory-withdrawn（mk は残す）。一部取り下げ → member_withdrawn 通知と解消。それ以外は通常の解消
export function vanishedGroupTarget(issue, { isWithdrawnAliases, scanComplete }) {
  const labels = new Set(issue.labels);
  const notices = [];
  const stored = issue.marker.mk ?? [];
  const withdrawn = stored.filter((key) => isWithdrawnAliases([key]));
  if (stored.length > 0 && withdrawn.length === stored.length) {
    if (!labels.has(LABELS.withdrawn)) { labels.add(LABELS.withdrawn); notices.push(['withdrawn']); }
    return { labels, notices, mk: stored };
  }
  if (withdrawn.length > 0) notices.push(['member_withdrawn', withdrawn.join(',')]);
  if (scanComplete && !isKernelGroupIssue(issue)) labels.add(LABELS.fixed); // コメントはしない（U1）
  return { labels, notices, mk: [] };
}

// 前回の mk にあって今回の members にない advisory_key のうち、取り下げ済みのもの
export function withdrawnMembers(previousKeys, currentKeys, { isWithdrawnAliases }) {
  const current = new Set(currentKeys);
  return previousKeys.filter((key) => !current.has(key) && isWithdrawnAliases([key]));
}
