import { execFileSync } from 'node:child_process';
import { cpSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { makeValidFeed } from './feed-fixture.mjs';

const IDENTITY = ['-c', 'user.name=test', '-c', 'user.email=test@example.invalid'];
export const git = (cwd, ...args) => execFileSync('git', [...IDENTITY, ...args], { cwd, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
const tmp = (prefix) => mkdtempSync(path.join(tmpdir(), prefix));

// bare の remote（feed ブランチに data/ と README だけを置いた状態）を作る。実際のリモートには触れない
export function makeFeedRemote() {
  const remote = tmp('feed-remote-');
  git(remote, 'init', '-q', '--bare', '-b', 'feed');
  const seed = tmp('feed-seed-');
  git(seed, 'init', '-q', '-b', 'feed');
  cpSync(makeValidFeed(), path.join(seed, 'data'), { recursive: true });
  writeFileSync(path.join(seed, 'README.md'), 'feed branch\n');
  git(seed, 'add', '-A');
  git(seed, 'commit', '-q', '-m', 'seed');
  git(seed, 'remote', 'add', 'origin', remote);
  git(seed, 'push', '-q', 'origin', 'feed');
  return remote;
}

export function cloneFeed(remote) {
  const dir = tmp('feed-clone-');
  git(dir, 'clone', '-q', '-b', 'feed', remote, '.');
  return dir;
}

export const makeRoot = () => tmp('feed-root-');
