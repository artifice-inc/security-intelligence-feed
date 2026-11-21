import { randomUUID } from 'node:crypto';

// 通知コメントの確実な送信（D8）。`fixed` は新規には作らない（U1）が、マーカーに残った未送信分を送れるよう残す。コメントの最終行に <!-- si-notice:<ID> --> を入れ、送信済みかを次回にも判定する
export const NOTICE_KINDS = ['fixed', 'recurrence', 'risk_reopen', 'misclose', 'withdrawn', 'member_withdrawn', 'member_added', 'duplicate'];
const REASON_TEXT = { expired: '受容の期限（90日）を過ぎた', kev: 'CISA KEV に掲載された', priority_up: '優先度が受容時より上がった', unknown_date: 'リスク受容の付与日時を確認できなかった（安全側）' };

export const newNoticeId = (kind, generate = randomUUID) => `${kind}-${generate()}`;
export const noticeMarker = (id) => `<!-- si-notice:${id} -->`;
const NOTICE_ID = /<!-- si-notice:([A-Za-z0-9_-]+) -->/g;

const plainKey = (key) => `\`${key.replace(/[^A-Za-z0-9._-]/g, '')}\``; // 外部由来の文字列なので記号を落とす（メンション・マーカー偽装の防止）
const mention = (owners) => owners.map((o) => `@${o}`).join(' ');

export function noticeText({ kind, reason }, owners) {
  switch (kind) {
    case 'fixed': return `${mention(owners)} リポジトリ上では解消を確認しました。本番への反映を確認してクローズしてください。`;
    case 'recurrence': return `再発: 解消済みとしていた脆弱性が、再び検出されました。`;
    case 'risk_reopen': return `${mention(owners)} リスク受容を解除して再オープンしました。理由: ${reason.split(',').map((r) => REASON_TEXT[r] ?? r).join('、')}。`;
    case 'misclose': return `${mention(owners)} 解消前にクローズされていたため、誤クローズとみなして再オープンしました。リスクを受け入れる場合は \`risk-accepted\` ラベルを付けてからクローズしてください。`;
    case 'withdrawn': return `有効な情報源のレコードがすべて取り下げられました。担当者が内容を確認して判断してください（自動ではクローズしません）。`;
    case 'member_withdrawn': return `まとめに含まれていた脆弱性のうち、次の項目の情報源のレコードがすべて取り下げられたため、表から外しました：${reason.split(',').map((key) => plainKey(key)).join('、')}`;
    case 'member_added': return `まとめに新しい重大な脆弱性が加わりました：${reason.split(',').map((entry) => { const [key, priority] = entry.split(':'); return `${plainKey(key)}（${priority?.replace(/[^P0-3]/g, '') ?? ''}）`; }).join('、')}`;
    case 'duplicate': return `同じ脆弱性の Issue が複数あります（重複候補）。番号の小さい Issue を正としてください。自動ではクローズしません。`;
    default: throw new Error(`未知の通知の種類です: ${kind}`);
  }
}

export const noticeBody = (notice, owners) => `${noticeText(notice, owners)}\n\n${noticeMarker(notice.id)}`;

// bot が書いたコメントの si-notice だけを送信済みとみなす（人の書いたマーカーは偽装として無視）
export function sentNoticeIds(comments, botLogin) {
  const ids = new Set();
  for (const comment of comments.filter((c) => c.author === botLogin)) {
    for (const match of comment.body.matchAll(NOTICE_ID)) ids.add(match[1]);
  }
  return ids;
}
