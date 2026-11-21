import { loadThresholds } from '../lib/config.mjs';

const HIGH_LEVELS = new Set(['critical', 'high']);

// 設計書 §6.6。P0: 影響あり+KEV / P1: 影響あり+(Critical/High か EPSS 上位)+internet / P2: その他の影響あり・EOL / P3: needs_review
export function computePriority({ judgement, kev, severity, epssPercentile, exposure, malicious = false }, thresholds = loadThresholds()) {
  if (judgement === 'needs_review') return 'P3';
  if (judgement !== 'affected') return null;
  if (malicious) return 'P0'; // 悪性パッケージは、入っていれば乗っ取られている可能性がある（KEV の判定より前）
  if (kev) return 'P0';
  const high = HIGH_LEVELS.has(String(severity ?? '').toLowerCase()) || (epssPercentile ?? 0) >= thresholds.epss_percentile_p1;
  if (high && exposure === 'internet') return 'P1';
  return 'P2';
}

export const PRIORITY_ORDER = ['P0', 'P1', 'P2', 'P3'];
export const priorityRank = (priority) => PRIORITY_ORDER.indexOf(priority);
export const isHigherPriority = (left, right) => priorityRank(left) < priorityRank(right);
