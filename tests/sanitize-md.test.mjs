import test from 'node:test';
import assert from 'node:assert/strict';
import { sanitizeInline, quoteBlock, stripMarkers } from '../src/lib/sanitize-md.mjs';

test('@user と #123 の後ろにゼロ幅スペースが入る', () => {
  const out = sanitizeInline('cc @octocat fixes #123');
  assert.ok(out.includes('@​octocat'));
  assert.ok(out.includes('#​123'));
});

test('HTML タグはエスケープされる', () => {
  assert.ok(!sanitizeInline('<script>alert(1)</script>').includes('<script>'));
});

test('マーカーの偽装は除去される', () => {
  const out = sanitizeInline('x <!-- si:{"v":1} --> <!-- si-notice:abc -->');
  assert.ok(!/si:|si-notice:/.test(out.replace(/&lt;!--/g, '')));
  assert.ok(!stripMarkers('<!-- SI:{} -->').includes('si:'));
});

test('改行を除き200文字で切り、引用ブロックに入る', () => {
  const out = sanitizeInline(`a\nb${'x'.repeat(300)}`);
  assert.ok(!out.includes('\n'));
  assert.ok([...out].length <= 200 + 0);
  assert.ok(quoteBlock('hi').startsWith('> '));
});
