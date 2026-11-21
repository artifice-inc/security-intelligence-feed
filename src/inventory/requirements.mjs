// requirements 形式のファイルを読む純粋関数。ネットワークにもファイルにも触れない
const MAX_REPORTED_LINES = 20;
const ALLOWED_OPTIONS = new Set([
  '--index-url', '-i', '--extra-index-url', '--trusted-host', '--find-links', '-f', '--no-index',
  '--no-binary', '--only-binary', '--prefer-binary', '--require-hashes', '--pre',
]);
const PINNED_REQUIREMENT = /^[A-Za-z0-9][A-Za-z0-9._-]*(\[[A-Za-z0-9._,\s-]*\])?\s*===?\s*[A-Za-z0-9][A-Za-z0-9._+!-]*$/;
const ENV_ONLY_USERINFO = /^\$\{[A-Za-z_][A-Za-z0-9_]*\}(:\$\{[A-Za-z_][A-Za-z0-9_]*\})?$/;
// 認証部分は最初の / ? # までの範囲にあり、最後の @ までを userinfo とみなす
const URL_USERINFO = /https?:\/\/([^\s/?#]*)@/gi;

// 行末の \ で折り返された行をつなぐ。行番号はつないだ最初の行のもの（1始まり）
function logicalLines(text) {
  const physical = text.split(/\r?\n/);
  const result = [];
  for (let i = 0; i < physical.length; i += 1) {
    let joined = physical[i];
    const start = i + 1;
    while (joined.endsWith('\\') && i + 1 < physical.length) { i += 1; joined = `${joined.slice(0, -1)} ${physical[i]}`; }
    result.push({ number: start, text: joined.endsWith('\\') ? joined.slice(0, -1) : joined });
  }
  return result;
}

const stripComment = (line) => line.replace(/(^|\s)#.*$/, '');

function isPinnedLine(line) {
  if (line.startsWith('-')) return ALLOWED_OPTIONS.has(line.split(/[\s=]/)[0]);
  const requirement = line.replace(/--hash=\S+/g, ' ').split(';')[0].trim();
  return PINNED_REQUIREMENT.test(requirement);
}

// 全行が == で固定されているときだけ ok。固定されていない行の行番号（昇順、最大20件）を返す。行の中身は返さない
export function checkRequirementsPinned(text) {
  const unpinned = [];
  for (const { number, text: raw } of logicalLines(String(text))) {
    const line = stripComment(raw).trim();
    if (line !== '' && !isPinnedLine(line)) unpinned.push(number);
  }
  return { ok: unpinned.length === 0, lines: unpinned.slice(0, MAX_REPORTED_LINES) };
}

// https?:// の URL に認証情報（user@・user:pass@）がある行の行番号。${NAME} だけの参照は認証情報とみなさない
export function findUrlCredentials(text) {
  const found = [];
  String(text).split(/\r?\n/).forEach((line, index) => {
    const hit = [...line.matchAll(URL_USERINFO)].some((match) => !ENV_ONLY_USERINFO.test(match[1]));
    if (hit) found.push(index + 1);
  });
  return found;
}
