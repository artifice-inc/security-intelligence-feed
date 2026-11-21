import { failResult } from '../collect/result.mjs';
import { normalizeAwsBulletins } from '../normalize/aws-bulletins.mjs';
import { validate } from '../lib/schema.mjs';
import { writeJsonAtomic } from './central-data.mjs';

const AWS = 'aws-bulletins';
const UNFINISHED_MESSAGE = '照合の完了までに取得が終わらなかったため見送りました';

// 任意の情報源を開始する。待たない（完了したら settled に入れるだけ）。reject は必ず failResult にする
export function startOptional({ collectors = {}, http, now, thresholds }) {
  return Object.entries(collectors).map(([name, collect]) => {
    const controller = new AbortController();
    const task = { name, controller, settled: null };
    Promise.resolve()
      .then(() => collect({ http, now, deadlineMs: thresholds.aws_bulletins_deadline_ms, signal: controller.signal }))
      .catch((error) => failResult(error))
      .then((result) => { if (!task.abandoned) task.settled = result; });
    return task;
  });
}

// 締め切り: 完了していれば結果を使い、未完了なら通信を中断して見送る（中断した処理の完了は待たない）
export function settleOptional(tasks) {
  return Object.fromEntries(tasks.map((task) => {
    if (task.settled) return [task.name, task.settled];
    task.abandoned = true;
    task.controller.abort();
    return [task.name, failResult({ kind: 'unfinished', message: UNFINISHED_MESSAGE })];
  }));
}

// 正規化 → 検証 → 一時ファイル経由で置き換え。失敗しても例外は投げず、前回のファイルを残して失敗の結果を返す
export function applyAwsBulletins({ result, previous, outDataDir, now, overrides = {} }) {
  if (!result?.ok) return { result, data: previous };
  const normalize = overrides.normalize ?? normalizeAwsBulletins;
  const check = overrides.validate ?? validate;
  const write = overrides.writeJsonAtomic ?? writeJsonAtomic;
  let next;
  try {
    next = normalize({ previous, records: result.records, now });
    if (!check(AWS, next).ok) return { result: failResult({ kind: 'schema', message: 'aws-bulletins がスキーマに合いません' }), data: previous };
  } catch (error) {
    return { result: failResult({ kind: 'normalize', message: String(error.message ?? error) }), data: previous };
  }
  try {
    write(outDataDir, `${AWS}.json`, next);
  } catch (error) {
    return { result: failResult({ kind: 'write', message: String(error.message ?? error) }), data: previous };
  }
  return { result, data: next };
}
