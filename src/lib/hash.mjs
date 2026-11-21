import { createHash } from 'node:crypto';

export const sha256Hex = (input) => createHash('sha256').update(input).digest('hex');

// キー順を固定して直列化する（ハッシュと差分判定を実行順に依存させないため）
export function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (value && typeof value === 'object') {
    const keys = Object.keys(value).filter((k) => value[k] !== undefined).sort();
    return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalJson(value[k])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

export const contentHash = (value) => sha256Hex(canonicalJson(value));
