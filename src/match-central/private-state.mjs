import { existsSync, readdirSync, statSync } from 'node:fs';
import path from 'node:path';
import { SOURCE_NAMES } from '../collect/index.mjs';
import { COMMON_DATA_FILES } from '../feed/definition.mjs';

const EMPTY_SOURCE = { last_attempt_at: null, last_success_at: null, last_error: null };

// ファイル、または1つでもファイルを含むディレクトリがあるか（Git は空のディレクトリを持たないが、同じ作業ツリーには空のディレクトリが残りうる）
const hasFiles = (target) => existsSync(target) && (!statSync(target).isDirectory() || readdirSync(target).some((name) => hasFiles(path.join(target, name))));

// 切り替えの最初の回か。保存済みのデータだけで決める（M3 の最初の回、または切り戻し後に旧処理が共通の生成物を書いた再切り替えの最初の回）。
// advisories/ は非公開側も照合由来の記録を持つので判定に使わない
export function isFirstMatchRun(dataDir) {
  if (!existsSync(path.join(dataDir, 'feed-state.json'))) return true;
  return COMMON_DATA_FILES.filter((entry) => entry !== 'advisories/').some((entry) => hasFiles(path.join(dataDir, entry)));
}

export const jpKey = (item) => `${item.source}|${item.id}`;

// 前回の digest の時点より後にフィードへ入った国内の注意喚起。同じフィードを2回使っても重複せず、飛ばした回の分も拾う
export const newJpItems = (jpAlerts, previousState) => {
  const seen = new Set(previousState?.digest_jp?.keys ?? []);
  return (jpAlerts?.items ?? []).filter((item) => !seen.has(jpKey(item)));
};

// 非公開側の feed-state.json。mode は常に match。cutover_data_commit は最初の回だけ置き換える
export function nextFeedState({ previous, feed, feedHealth, jpAlerts, now, firstRun, cutoverCommit }) {
  const validated = feed.mode === 'latest' ? { sha: feed.sha, run_slot: feedHealth.run_slot, validated_at: now } : previous?.last_validated ?? null;
  const digestJp = feed.mode === 'degraded' ? previous?.digest_jp ?? null : { feed_sha: feed.sha, keys: (jpAlerts?.items ?? []).map(jpKey).sort() };
  return { mode: 'match', last_validated: validated, digest_jp: digestJp, cutover_data_commit: firstRun ? cutoverCommit ?? null : previous?.cutover_data_commit ?? null };
}

// 公開側の情報源の欄を非公開側の形（health.schema）に写す。縮退の回は前回の非公開側の値を保つ
export function mapFeedSources({ previous, feedHealth }) {
  return Object.fromEntries(SOURCE_NAMES.map((name) => {
    const entry = feedHealth?.sources?.[name];
    if (!feedHealth) return [name, previous?.sources?.[name] ?? EMPTY_SOURCE];
    return [name, entry ? { last_attempt_at: entry.last_attempt_at, last_success_at: entry.last_success_at, last_error: entry.last_error ?? null } : EMPTY_SOURCE];
  }));
}

// 任意の情報源（AWS）。first_attempt_at は非公開側の前回の値を保ち、前回になければ公開側の最初に見た試行で初期化する
export function mapFeedOptionalSources({ previous, feedHealth }) {
  if (!feedHealth) return previous?.optional_sources ?? {};
  const result = { ...previous?.optional_sources };
  for (const [name, entry] of Object.entries(feedHealth.optional_sources ?? {})) {
    result[name] = {
      first_attempt_at: previous?.optional_sources?.[name]?.first_attempt_at ?? entry.last_attempt_at, last_attempt_at: entry.last_attempt_at,
      last_success_at: entry.last_success_at, last_error: entry.last_error ?? null,
    };
  }
  return result;
}
