# 配布先の導入手順

公開側（`security-intelligence-feed`）の導入手順です。`/security-check` の使い方と、手元でのコードの取得先（`main` の最新）は、
プラグインの `SKILL.md` に従ってください。

- データの場所: `feed` ブランチの `data/`（1日2回、07:17・16:17 JST に更新）
- 連絡先: support@artifice-inc.com

## 前提

- Node.js（このリポジトリの `.nvmrc` の版）
- `git`
- Claude Code
- Windows の場合：Git for Windows、Node.js 24 以上（Windows 版）、Claude Code（Windows 版）。前提は「Claude Code の Bash ツールで Git for Windows の Bash が使えること」です。Claude Code が Git Bash を見つけられないときは、環境変数 `CLAUDE_CODE_GIT_BASH_PATH` に `bash.exe` のパスを設定してください。

## 1. OSV-Scanner（固定版）

固定版は `config/tool-versions.json` にあります。公開側のコードを一時ディレクトリに展開し、`install-scanner.mjs` で sha256 を検証してから `~/.local/bin` に置きます。Apple Silicon は `darwin_arm64`、Intel Mac は `darwin_amd64`、Linux は `linux_amd64` を `--platform` に指定します。

```bash
CODE_DIR="$(mktemp -d)" && git clone --bare --quiet https://github.com/artifice-inc/security-intelligence-feed "$HOME/.cache/security-intelligence-feed.git" && git --git-dir "$HOME/.cache/security-intelligence-feed.git" archive refs/heads/main | tar -x -C "$CODE_DIR" && (cd "$CODE_DIR" && npm ci --ignore-scripts --silent) && mkdir -p "$HOME/.local/bin" && node "$CODE_DIR/src/cli/install-scanner.mjs" --platform darwin_arm64 --dest "$HOME/.local/bin" && "$HOME/.local/bin/osv-scanner" --version && rm -rf "$CODE_DIR"
```

`~/.cache/security-intelligence-feed.git` がすでにある場合は、`git clone` の部分を省いてください。`which osv-scanner` が `~/.local/bin` を指すようにします。

### Windows（x86_64・Git Bash）

Claude Code の **Bash ツール**で実行します（PowerShell・コマンドプロンプトの手順はありません）。`--platform windows_amd64` を指定し、配置先は `~/.local/bin/osv-scanner.exe` です。Node に渡すスクリプトのパスと `--dest` は `cygpath -am` で変換し、引用符で囲みます。`unzip` は要りません。**PATH の設定も要りません**（`/security-check` が `~/.local/bin/osv-scanner.exe` を直接使います）。

```bash
CODE_DIR="$(mktemp -d)" && git clone --bare --quiet https://github.com/artifice-inc/security-intelligence-feed "$HOME/.cache/security-intelligence-feed.git" && git -c core.autocrlf=false -c core.eol=lf --git-dir "$HOME/.cache/security-intelligence-feed.git" archive refs/heads/main | tar -x -C "$CODE_DIR" && (cd "$CODE_DIR" && npm ci --ignore-scripts --silent) && mkdir -p "$HOME/.local/bin" && MSYS2_ARG_CONV_EXCL='*' node "$(cygpath -am "$CODE_DIR/src/cli/install-scanner.mjs")" --platform windows_amd64 --dest "$(cygpath -am "$HOME/.local/bin")" && sha256sum "$HOME/.local/bin/osv-scanner.exe" && "$HOME/.local/bin/osv-scanner.exe" --version; rm -rf "$CODE_DIR"
```

導入済みかの判定と完了の確認は、**起動する前に** `sha256sum "$HOME/.local/bin/osv-scanner.exe"` の値を `config/tool-versions.json` の `windows_amd64` の `sha256` と比べます。一致してから `--version` を見ます。一致しなければ入れ直してください。

## 2. プラグイン

```bash
CLAUDE="$(command -v claude || ls "$HOME/.local/bin/claude.exe" "$HOME/.local/bin/claude" 2>/dev/null | head -n 1)" && "$CLAUDE" plugin marketplace add artifice-inc/security-intelligence-feed && "$CLAUDE" plugin install security-check@security-intelligence-feed && "$CLAUDE" plugin list
```

`security-check@security-intelligence-feed` が `enabled` と表示されれば成功です。起動中の Claude Code は再起動してください。

導入済みの環境の更新は、`docs/install-with-claude-code.md` の「導入済みの環境を更新する」を参照してください。

## 3. 使い方

案件のフォルダで Claude Code を起動し、`/security-check` を実行します。キャッシュ（コードとフィード）は `SKILL.md` の手順が自動で用意・更新します。

## 定期実行の遅れについて

- 収集は 07:17・16:17 JST の予定ですが、GitHub の都合で数時間（実測で最大10時間程度）遅れることがあります。これは不具合ではありません。
- 止まっていると判断する基準は `/security-check` と同じです。`health.json` の `last_success_at` が未記録、または「予定時刻＋`grace_minutes`（12時間）を過ぎた直近の予定時刻」より前であることです。収集の開始が猶予の中でも、成功したフィードの公開が猶予を過ぎれば、その間は警告が出ます。
- `run_slot` は失敗した回でも進みます。「収集が実行されたか」の確認には使えますが、「成功しているか」の判定には使えません。
- 自前で監視する場合も、予定時刻の直後に判定しないでください。
