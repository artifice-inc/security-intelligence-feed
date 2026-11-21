import { LABELS } from './issue-body.mjs';

// reconcile の結果から digest に載せる情報を集める（issues-reconcile.mjs から分けた）
export const emptyDigestInfo = () => ({ fixedInRepo: [], riskAccepted: [], transitions: [], superseded: [] });

export async function collectDigestInfo({ api, snapshot, digestInfo, now, thresholds, errors }) {
  for (const entry of snapshot) {
    if (entry.state === 'open' && typeof entry.superseded_by === 'number') digestInfo.superseded.push({ issue_number: entry.issue_number, project: entry.project, superseded_by: entry.superseded_by });
    const wanted = entry.state === 'open' && entry.labels.includes(LABELS.fixed) ? LABELS.fixed : entry.state === 'closed' && entry.labels.includes(LABELS.accepted) ? LABELS.accepted : null;
    if (!wanted) continue;
    let since = null;
    try {
      const events = await api.listIssueEvents(entry.issue_number);
      since = events.filter((e) => e.event === 'labeled' && e.label?.name === wanted).map((e) => e.created_at).sort().at(-1) ?? null;
    } catch (error) { errors.push({ target: `events:#${entry.issue_number}`, message: error.message }); }
    if (wanted === LABELS.fixed) digestInfo.fixedInRepo.push({ issue_number: entry.issue_number, project: entry.project, since });
    else digestInfo.riskAccepted.push({ issue_number: entry.issue_number, project: entry.project, accepted_at: since, expires_after_days: thresholds.risk_accepted_days });
  }
  void now;
}
