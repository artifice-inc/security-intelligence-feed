import { readFileSync } from 'node:fs';
import path from 'node:path';
import { ROOT_DIR } from './config.mjs';
import { assertValid } from './schema.mjs';

// 人が根拠を確かめた PSF の記録の一覧。スキーマに合わなければ例外にする（黙って無視しない）
// config.mjs と schema.mjs は循環するため、config.mjs ではなくここに置く
export const loadPythonNoReleaseImpact = () => assertValid(
  'python-no-release-impact', JSON.parse(readFileSync(path.join(ROOT_DIR, 'config', 'python-no-release-impact.json'), 'utf8')),
);
