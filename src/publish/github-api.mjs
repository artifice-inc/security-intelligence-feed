import { loadCentral } from '../lib/config.mjs';

const API_HOST = 'api.github.com';
const PAGE_SIZE = 100;
const MAX_PAGES = 100;
const RETRIES = 3;
const RETRY_BASE_MS = 1000;
const sleepMs = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

export class GitHubApiError extends Error {
  constructor(message, status) { super(message); this.kind = 'github_api'; this.http_status = status; }
}

// Octokit は使わず fetch で直接呼ぶ（指示書 §0.1）。repo は "<org>/<name>"
export function createGitHubApi({ repo, token, fetchImpl = globalThis.fetch, sleep = sleepMs, botLogin = loadCentral().bot_login, userAgent }) {
  async function call(method, route, body) {
    let lastError;
    for (let attempt = 0; attempt < RETRIES; attempt += 1) {
      if (attempt > 0) await sleep(RETRY_BASE_MS * 2 ** (attempt - 1));
      try {
        const response = await fetchImpl(`https://${API_HOST}${route}`, {
          method, headers: { Accept: 'application/vnd.github+json', Authorization: `Bearer ${token}`, 'X-GitHub-Api-Version': '2022-11-28', 'Content-Type': 'application/json', 'User-Agent': userAgent ?? loadCentral().user_agent },
          body: body === undefined ? undefined : JSON.stringify(body),
        });
        if (response.status >= 500) { lastError = new GitHubApiError(`${method} ${route}: HTTP ${response.status}`, response.status); continue; }
        if (!response.ok) throw new GitHubApiError(`${method} ${route}: HTTP ${response.status}`, response.status);
        return response.status === 204 ? null : response.json();
      } catch (error) {
        if (error instanceof GitHubApiError && error.http_status < 500) throw error;
        lastError = error instanceof GitHubApiError ? error : new GitHubApiError(`${method} ${route}: ${error.message}`, null);
      }
    }
    throw lastError;
  }

  async function paged(route) {
    const all = [];
    const separator = route.includes('?') ? '&' : '?';
    for (let page = 1; page <= MAX_PAGES; page += 1) {
      const rows = await call('GET', `${route}${separator}per_page=${PAGE_SIZE}&page=${page}`);
      all.push(...rows);
      if (rows.length < PAGE_SIZE) break;
    }
    return all;
  }

  const normalizeIssue = (i) => ({
    number: i.number, state: i.state, title: i.title, body: i.body ?? '', labels: i.labels.map((l) => (typeof l === 'string' ? l : l.name)),
    assignees: (i.assignees ?? []).map((a) => a.login),
  });

  return {
    botLogin,
    listLabels: async () => (await paged(`/repos/${repo}/labels`)).map((l) => l.name),
    createLabel: (name, color, description) => call('POST', `/repos/${repo}/labels`, { name, color, description }),
    // 順序を固定しないとページ境目で抜け・重複が出る。念のため番号で重複も除く
    listIssues: async ({ label }) => [...new Map((await paged(`/repos/${repo}/issues?state=all&sort=created&direction=asc&labels=${encodeURIComponent(label)}`))
      .filter((i) => !i.pull_request).map((i) => [i.number, normalizeIssue(i)])).values()],
    // 作成直後の Issue は一覧に出るのが遅れることがある。番号での取得は即時に反映される
    getIssue: async (number) => normalizeIssue(await call('GET', `/repos/${repo}/issues/${number}`)),
    listIssueEvents: (number) => paged(`/repos/${repo}/issues/${number}/events`),
    listComments: async (number) => (await paged(`/repos/${repo}/issues/${number}/comments`)).map((c) => ({ id: c.id, body: c.body ?? '', author: c.user?.login ?? '' })),
    createIssue: async (data) => normalizeIssue(await call('POST', `/repos/${repo}/issues`, data)),
    // 脆弱性の Issue を閉じる経路はここに存在させない（再オープンは許可）
    updateIssue: (number, patch) => {
      if (patch.state === 'closed') throw new Error('脆弱性の Issue をクローズする操作は禁止です（closeHealthIssue を使えるのは health Issue だけ）');
      return call('PATCH', `/repos/${repo}/issues/${number}`, patch);
    },
    createComment: (number, body) => call('POST', `/repos/${repo}/issues/${number}/comments`, { body }),
    closeHealthIssue: (number) => call('PATCH', `/repos/${repo}/issues/${number}`, { state: 'closed', state_reason: 'completed' }),
  };
}
