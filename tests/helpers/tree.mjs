import { mkdtempSync, mkdirSync, writeFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import path from 'node:path';

export const makeTree = (files) => {
  const root = mkdtempSync(path.join(tmpdir(), 'si-tree-'));
  for (const [name, content] of Object.entries(files)) {
    mkdirSync(path.dirname(path.join(root, name)), { recursive: true });
    writeFileSync(path.join(root, name), content);
  }
  return root;
};

const gitIn = (cwd, ...args) => execFileSync('git', ['-c', 'user.name=t', '-c', 'user.email=t@example.com', ...args], { cwd, encoding: 'utf8' });

// フィルタ付きクローンを受け付ける試験用のローカルリポジトリ（branches: { ブランチ名: ファイル群 }）
export function makeRepo(branches) {
  const root = mkdtempSync(path.join(tmpdir(), 'si-repo-'));
  gitIn(root, 'init', '-q', '-b', 'main');
  gitIn(root, 'config', 'uploadpack.allowFilter', 'true');
  gitIn(root, 'config', 'uploadpack.allowAnySHA1InWant', 'true');
  let first = true;
  for (const [branch, files] of Object.entries(branches)) {
    if (first) { first = false; gitIn(root, 'checkout', '-q', '-B', branch); } else gitIn(root, 'checkout', '-q', '-B', branch, 'main');
    for (const [name, content] of Object.entries(files)) {
      mkdirSync(path.dirname(path.join(root, name)), { recursive: true });
      writeFileSync(path.join(root, name), content);
    }
    gitIn(root, 'add', '-A');
    gitIn(root, 'commit', '-q', '-m', `files for ${branch}`);
  }
  return { url: `file://${root}`, root, head: () => gitIn(root, 'rev-parse', 'HEAD').trim() };
}

// 既存のリポジトリにファイルを追加・更新してコミットする（案件側の変更を再現する）
export function updateRepo(repo, files, branch = 'main') {
  gitIn(repo.root, 'checkout', '-q', branch);
  for (const [name, content] of Object.entries(files)) {
    mkdirSync(path.dirname(path.join(repo.root, name)), { recursive: true });
    writeFileSync(path.join(repo.root, name), content);
  }
  gitIn(repo.root, 'add', '-A');
  gitIn(repo.root, 'commit', '-q', '-m', 'update');
}

// 中央リポジトリ（bare のリモート付き）。.work/ は無視する
export function makeCentralRepo() {
  const remote = mkdtempSync(path.join(tmpdir(), 'si-remote-'));
  execFileSync('git', ['init', '-q', '--bare', '-b', 'main'], { cwd: remote });
  const root = mkdtempSync(path.join(tmpdir(), 'si-central-'));
  gitIn(root, 'init', '-q', '-b', 'main');
  gitIn(root, 'remote', 'add', 'origin', remote);
  writeFileSync(path.join(root, '.gitignore'), '.work/\n');
  mkdirSync(path.join(root, 'data'), { recursive: true });
  writeFileSync(path.join(root, 'data', '.gitkeep'), '');
  gitIn(root, 'add', '-A');
  gitIn(root, 'commit', '-q', '-m', 'init');
  gitIn(root, 'push', '-q', '-u', 'origin', 'main');
  return { root, remote, commitCount: () => Number(gitIn(root, 'rev-list', '--count', 'HEAD').trim()), remoteCount: () => Number(execFileSync('git', ['rev-list', '--count', 'main'], { cwd: remote, encoding: 'utf8' }).trim()), git: (...args) => gitIn(root, ...args) };
}
