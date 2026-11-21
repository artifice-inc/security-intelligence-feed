// GitHub API のフェイク。書き込み回数の記録と、操作ごとの失敗の注入ができる
export class FakeGitHub {
  constructor({ botLogin = 'github-actions[bot]', clock = () => '2026-10-25T00:00:00Z' } = {}) {
    this.botLogin = botLogin;
    this.clock = clock;
    this.issues = new Map();
    this.comments = new Map();
    this.events = new Map();
    this.labels = new Set();
    this.writes = [];
    this.nextNumber = 1;
    this.failures = []; // { op, when(args)=>bool, times }
    this.closeCalls = [];
  }

  failNext(op, when = () => true, times = 1) { this.failures.push({ op, when, times }); }

  #maybeFail(op, args) {
    const failure = this.failures.find((f) => f.op === op && f.times > 0 && f.when(args));
    if (failure) { failure.times -= 1; throw new Error(`注入された失敗: ${op}`); }
  }

  #write(op, number) { this.writes.push({ op, number }); }

  async listLabels() { return [...this.labels]; }
  async createLabel(name) { this.#maybeFail('createLabel', [name]); this.#write('createLabel'); this.labels.add(name); }

  async listIssues({ label }) {
    this.#maybeFail('listIssues', [label]);
    return [...this.issues.values()].filter((i) => i.labels.includes(label)).map((i) => ({ ...i, labels: [...i.labels], assignees: [...i.assignees] }));
  }

  async getIssue(number) {
    this.#maybeFail('getIssue', [number]);
    const issue = this.issues.get(number);
    if (!issue) { const error = new Error('Not Found'); error.http_status = 404; throw error; }
    return { ...issue, labels: [...issue.labels], assignees: [...issue.assignees] };
  }

  async listIssueEvents(number) { this.#maybeFail('listIssueEvents', [number]); return [...(this.events.get(number) ?? [])]; }
  async listComments(number) { this.#maybeFail('listComments', [number]); return [...(this.comments.get(number) ?? [])]; }

  async createIssue(data) {
    this.#maybeFail('createIssue', [data]);
    const number = this.nextNumber++;
    this.issues.set(number, { number, state: 'open', title: data.title, body: data.body, labels: [...data.labels], assignees: [...(data.assignees ?? [])] });
    this.#record(number, [], data.labels);
    this.#write('createIssue', number);
    return { ...this.issues.get(number) };
  }

  async updateIssue(number, patch) {
    this.#maybeFail('updateIssue', [number, patch]);
    if (patch.state === 'closed') throw new Error('脆弱性の Issue をクローズする操作は禁止です');
    const issue = this.issues.get(number);
    this.#write('updateIssue', number);
    if (patch.labels) { this.#record(number, issue.labels, patch.labels); issue.labels = [...patch.labels]; }
    for (const key of ['state', 'title', 'body']) if (patch[key] !== undefined) issue[key] = patch[key];
    return { ...issue };
  }

  async createComment(number, body) {
    this.#maybeFail('createComment', [number, body]);
    this.#write('createComment', number);
    const list = this.comments.get(number) ?? [];
    list.push({ id: list.length + 1, body, author: this.botLogin });
    this.comments.set(number, list);
  }

  async closeHealthIssue(number) {
    this.closeCalls.push(number);
    this.#write('closeHealthIssue', number);
    this.issues.get(number).state = 'closed';
  }

  #record(number, before, after) {
    const list = this.events.get(number) ?? [];
    for (const name of after.filter((l) => !before.includes(l))) list.push({ event: 'labeled', label: { name }, created_at: this.clock() });
    this.events.set(number, list);
  }

  // 人の操作
  humanClose(number) { this.issues.get(number).state = 'closed'; }
  humanLabel(number, name, at) { const issue = this.issues.get(number); issue.labels.push(name); const list = this.events.get(number) ?? []; list.push({ event: 'labeled', label: { name }, created_at: at }); this.events.set(number, list); }
  humanComment(number, body, author = 'someone') { const list = this.comments.get(number) ?? []; list.push({ id: list.length + 100, body, author }); this.comments.set(number, list); }
  resetWrites() { this.writes = []; }
  get writeCount() { return this.writes.length; }
}
