# 配布先の導入手順

公開側（`security-intelligence-feed`）の導入手順です。`/security-check` の使い方と、手元でのコードの取得先（`main` の最新）は、
プラグインの `SKILL.md` に従ってください。

- データの場所: `feed` ブランチの `data/`（1日2回、07:17・16:17 JST に更新）
- 連絡先: support@artifice-inc.com

## 前提

- Node.js（このリポジトリの `.nvmrc` の版）
- `git`
- Claude Code

## 1. OSV-Scanner（固定版）

固定版は `config/tool-versions.json` にあります。公開側のコードを一時ディレクトリに展開し、`install-scanner.mjs` で sha256 を検証してから `~/.local/bin` に置きます。Apple Silicon は `darwin_arm64`、Intel Mac は `darwin_amd64`、Linux は `linux_amd64` を `--platform` に指定します。

```bash
CODE_DIR="$(mktemp -d)" && git clone --bare --quiet https://github.com/artifice-inc/security-intelligence-feed "$HOME/.cache/security-intelligence-feed.git" && git --git-dir "$HOME/.cache/security-intelligence-feed.git" archive refs/heads/main | tar -x -C "$CODE_DIR" && mkdir -p "$HOME/.local/bin" && node "$CODE_DIR/src/cli/install-scanner.mjs" --platform darwin_arm64 --dest "$HOME/.local/bin" && "$HOME/.local/bin/osv-scanner" --version && rm -rf "$CODE_DIR"
```

`~/.cache/security-intelligence-feed.git` がすでにある場合は、`git clone` の部分を省いてください。`which osv-scanner` が `~/.local/bin` を指すようにします。

## 2. プラグイン

```bash
claude plugin marketplace add artifice-inc/security-intelligence-feed && claude plugin install security-check@security-intelligence-feed && claude plugin list
```

`security-check@security-intelligence-feed` が `enabled` と表示されれば成功です。起動中の Claude Code は再起動してください。

## 3. 使い方

案件のフォルダで Claude Code を起動し、`/security-check` を実行します。キャッシュ（コードとフィード）は `SKILL.md` の手順が自動で用意・更新します。
