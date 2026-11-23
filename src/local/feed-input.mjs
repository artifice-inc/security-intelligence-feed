import { readFileSync, readdirSync, existsSync } from 'node:fs';
import path from 'node:path';
import { validateFeed } from '../feed/validate-feed.mjs';
import { judgeSlots } from '../match-central/slot-judgement.mjs';
import { requiredSources } from '../match/scan-status.mjs';
import { feedSignals, kevConfirmed } from '../match/priority-inputs.mjs';
import { slotOf, requiredSlot } from '../lib/schedule.mjs';

export const DEGRADED_REASON = '公開フィードを使えないため照合が不完全です';
export const readJson = (file) => (existsSync(file) ? JSON.parse(readFileSync(file, 'utf8')) : null);
export const readJsonDir = (dir) => (existsSync(dir) ? readdirSync(dir).filter((n) => n.endsWith('.json')).map((n) => readJson(path.join(dir, n))) : []);

// 旧キャッシュの data/（--feed-dir がないときの今の読み方）
export function readCentralData(dataDir) {
  const packagist = readJson(path.join(dataDir, 'packagist-advisories.json'));
  return {
    advisories: readJsonDir(path.join(dataDir, 'advisories')),
    runtimeData: { php: readJson(path.join(dataDir, 'runtimes/php.json')), nodejs: readJson(path.join(dataDir, 'runtimes/nodejs.json')), python: readJson(path.join(dataDir, 'runtimes/python.json')) },
    kernelData: readJson(path.join(dataDir, 'os/amazon-linux-kernel.json')), // ローカルでは ALAS を取得しない
    packagist: packagist?.full_sync_at ? packagist : null, // 全件取得が一度も成功していなければ照合不能
    health: readJson(path.join(dataDir, 'health.json')),
  };
}

const degraded = (reason) => ({
  mode: 'degraded', reason, health: null, kev: null, epssHigh: null, advisories: [], packagist: null, kernelData: null, runtimeData: { php: null, nodejs: null, python: null },
});

// 違反の中身（ファイル名など）は出さず、種類だけを理由にする
const violationReason = (violations) => (violations.some((v) => v.kind === 'unsupported_format') ? 'フィードの版が読めません（コードの更新が必要です）' : `フィードの検証に外れました（${violations.length}件）`);

// 検証に通ったフィードだけを読む。外れる・例外のときは中身を一切使わない縮退（不変条件4）
export function loadLocalFeed({ feedDir, noFeed }) {
  if (noFeed || !feedDir) return degraded('公開フィードを取得できませんでした');
  try {
    const violations = validateFeed(feedDir);
    if (violations.length > 0) return degraded(violationReason(violations));
    return { mode: 'latest', kev: readJson(path.join(feedDir, 'kev.json')), epssHigh: readJson(path.join(feedDir, 'epss-high.json')), ...readCentralData(feedDir) };
  } catch {
    return degraded('フィードを読み取れませんでした');
  }
}

// 優先度の入力（signals）・照合が不完全な理由（scan_errors）・出力に載せる KEV/EPSS の状態を決める。slot-judgement と同じ判定
export function judgeLocalFeed({ feed, inventory, thresholds, schedule, nowIso }) {
  if (feed.mode === 'degraded') {
    const base = feedSignals({ kev: null, epssHigh: null, feedMode: 'degraded', targetSlot: requiredSlot(schedule, nowIso), latestSlot: slotOf(schedule, nowIso), feedHealth: null, now: nowIso, thresholds, schedule });
    return {
      signals: { ...base, isKev: () => null }, // 縮退では KEV を確かめられない
      errors: [{ kind: 'feed', target: 'feed', message: feed.reason }], reasons: [DEGRADED_REASON],
      state: { mode: 'degraded', kev: { confirmed: false, fetched_at: null }, epss: { state: base.epssState, fetched_at: null } },
    };
  }
  const judged = judgeSlots({ feedMode: 'latest', feedHealth: feed.health, kev: feed.kev, epssHigh: feed.epssHigh, now: nowIso, thresholds, schedule });
  const { targetSlot, latestSlot } = judged;
  const context = { feedMode: 'latest', targetSlot, latestSlot, feedHealth: feed.health, schedule };
  const signals = feedSignals({ kev: feed.kev, epssHigh: feed.epssHigh, ...context, now: nowIso, thresholds });
  const errors = [...judged.extraErrors];
  for (const name of requiredSources(inventory)) {
    const verdict = judged.verdicts[name];
    if (!verdict?.ok) errors.push({ kind: 'source', target: name, message: `情報源 ${name} を確認できません（${verdict?.reason ?? '記録なし'}）` });
  }
  return {
    signals, errors, reasons: errors.map((e) => e.message),
    state: { mode: 'latest', kev: { confirmed: kevConfirmed({ kev: feed.kev, ...context }), fetched_at: feed.kev?.fetched_at ?? null }, epss: { state: signals.epssState, fetched_at: feed.epssHigh?.fetched_at ?? null } },
  };
}
