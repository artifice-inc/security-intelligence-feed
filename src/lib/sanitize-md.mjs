import { loadThresholds } from './config.mjs';

const ZERO_WIDTH_SPACE = '​';
const MARKER_PATTERN = /<!--\s*si(?:-notice)?:/gi;

// マーカーの偽装を防ぐため、マーカー行と同じ形の文字列を除去する
export const stripMarkers = (text) => String(text).replace(MARKER_PATTERN, '');

// 外部の文字列を Markdown に載せられる1行へ無害化する（指示書 §10.5）
export function sanitizeInline(text, maxChars = loadThresholds().sanitize_max_chars) {
  let value = stripMarkers(text ?? '');
  value = value.replace(/[\r\n]+/g, ' ');
  value = value.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  value = value.replace(/@/g, `@${ZERO_WIDTH_SPACE}`).replace(/#(?=\d)/g, `#${ZERO_WIDTH_SPACE}`);
  value = [...value].slice(0, maxChars).join('');
  return value.replace(/[\\`*_[\]]/g, (c) => `\\${c}`).trim();
}

// 引用ブロックに隔離する（本文中の命令らしき文字列を指示として読ませないため）
export const quoteBlock = (text) => `> ${sanitizeInline(text)}`;
