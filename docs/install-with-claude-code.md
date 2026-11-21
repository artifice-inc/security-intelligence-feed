# security-check の導入手順（Claude Code 向け）

この文書は、Claude Code が読んで導入を進めるための手順書です。

**導入する方へ**：案件のフォルダとは別の場所で Claude Code を起動し、次のように頼んでください。

> https://github.com/artifice-inc/security-intelligence-feed/blob/main/docs/install-with-claude-code.md を読んで、security-check を導入して

---

## Claude Code へ：守ること

- 各ステップの前に、何をするかをユーザーに日本語で一言説明する。ソフトウェアの導入・設定ファイルの変更・PATH の変更は、**ユーザーの了承を得てから**行う。
- `sudo` は使わない。管理者権限が要る作業（Node.js や git の導入など）は、ユーザーに手順を示して任せる。
- 既にあるファイルやフォルダは消さない・上書きしない。この文書の「既にあれば」の指示に従う。**例外**：Windows の `~/.local/bin/osv-scanner.exe` が固定版の sha256 と一致しないときに限り、対象のパスを示してユーザーの了承を得てから入れ直してよい。入れ直す前と後に sha256 を確かめる。
- **`~/.config/security-intelligence/staff` は作らない。** これは提供元の社内用の目印で、作ると社内用の手順に切り替わり、動かなくなる。
- 案件のソースコードや依存関係の一覧を、外部へ送らない。この導入と `/security-check` が通信する先は、github.com（とダウンロードの転送先の `*.githubusercontent.com`）・registry.npmjs.org・osv-vulnerabilities.storage.googleapis.com だけ。
- 失敗したら、先へ進まずに止まる。実行したコマンドとエラーの全文をユーザーに示す。
- 最後に、下の「完了の判定」をすべて確かめてから、結果を報告する。

## 対応している環境

| OS | CPU | OSV-Scanner の `--platform` |
|---|---|---|
| macOS | Apple Silicon（arm64） | `darwin_arm64` |
| macOS | Intel（x86_64） | `darwin_amd64` |
| Linux | x86_64 | `linux_amd64` |
| Windows（Git Bash） | x86_64 | `windows_amd64`（Git for Windows の Bash から実行する） |
| WSL2 | x86_64 | WSL2 の Linux でも動く（`linux_amd64`） |

macOS の CPU は `sysctl -in hw.optional.arm64` で見分ける。`1` なら Apple Silicon（`darwin_arm64`）、何も出なければ Intel（`darwin_amd64`）。Apple Silicon でも、Rosetta で動くシェルでは `uname -m` が `x86_64` と出るため、`uname` だけで決めない。

Windows では、Claude Code の **Bash ツール**（Git for Windows の Bash）で手順を実行する。Claude Code が Git Bash を見つけられないときは、環境変数 `CLAUDE_CODE_GIT_BASH_PATH` に `bash.exe` のパスを設定するようユーザーに頼む。

上の表にない環境（Linux の arm64 など）は対応していない。その場合はユーザーにそう伝え、下の問い合わせ先を案内して止める。

## ステップ 0：環境を確かめる

次を実行し、結果をユーザーに表で示す。

```bash
uname -sm; sysctl -in hw.optional.arm64 2>/dev/null; node --version; git --version; CLAUDE="$(command -v claude || ls "$HOME/.local/bin/claude.exe" "$HOME/.local/bin/claude" 2>/dev/null | head -n 1)"; echo "claude: ${CLAUDE:-見つからない}"; [ -n "$CLAUDE" ] && "$CLAUDE" --version; echo "$PATH" | tr ':' '\n' | grep -x "$HOME/.local/bin" || echo "~/.local/bin は PATH にない"
```

| 確かめること | 条件 | 満たさないとき |
|---|---|---|
| `uname -sm` | 対応表にある組み合わせ（Windows では `MINGW64_NT-...` と出る） | 対応外として止める。Windows で Git for Windows がなければ、ユーザーに導入を頼む |
| `node --version` | v24 以上 | ユーザーに Node.js 24 以上の導入を頼む（nvm・Volta・公式インストーラのどれか、ユーザーが普段使うもの）。導入後にこのステップをやり直す |
| `git --version` | 表示される | ユーザーに git の導入を頼む |
| `claude`（Claude Code の CLI） | 見つかって版が表示される。PATH に無くても、`~/.local/bin/claude`（Windows は `claude.exe`）にあればよい（デスクトップアプリでは PATH に入っていないことが多い） | どちらにも無ければ止めて、ユーザーに Claude Code の CLI を公式の手順（https://code.claude.com/docs/en/setup ）で入れてもらう。ステップ 2 のプラグインの導入に使う |
| `~/.local/bin` | PATH にある（Windows では不要） | macOS・Linux だけ：ステップ 1 の後に、ユーザーの了承を得てシェルの設定ファイル（`~/.zshrc` か `~/.bashrc`）に `export PATH="$HOME/.local/bin:$PATH"` を 1 行足す |

## ステップ 1：OSV-Scanner（固定版）を入れる

OSV-Scanner は、依存関係を脆弱性のデータベースと照合するツール。版は提供元が固定しており（`config/tool-versions.json`）、導入スクリプトが sha256 を検証してから `~/.local/bin` に置く。

既に `~/.local/bin/osv-scanner` があり、`~/.local/bin/osv-scanner --version` の版が `config/tool-versions.json` の版と同じなら、このステップは飛ばす。

**Windows**：`~/.local/bin/osv-scanner.exe` について、**起動する前に** `sha256sum` の値を `config/tool-versions.json` の `windows_amd64` の `sha256` と比べる。一致してから `--version` を見て、同じ版なら飛ばす。一致しなければ入れ直す（共通のルールの例外）。コマンドは `docs/setup.md` の「Windows（x86_64・Git Bash）」の節のとおり（`cygpath -am` で変換し、引用符で囲む。`unzip` も PATH の設定も要らない）。

`<PLATFORM>` は対応表の値に置き換える。`~/.cache/security-intelligence-feed.git` が既にあれば、`git clone` の部分（最初の `&&` まで）を `git --git-dir "$HOME/.cache/security-intelligence-feed.git" fetch --quiet origin +refs/heads/main:refs/heads/main` に置き換える。

```bash
CODE_DIR="$(mktemp -d)" && git clone --bare --quiet https://github.com/artifice-inc/security-intelligence-feed "$HOME/.cache/security-intelligence-feed.git" && git --git-dir "$HOME/.cache/security-intelligence-feed.git" archive refs/heads/main | tar -x -C "$CODE_DIR" && (cd "$CODE_DIR" && npm ci --ignore-scripts --silent) && mkdir -p "$HOME/.local/bin" && node "$CODE_DIR/src/cli/install-scanner.mjs" --platform <PLATFORM> --dest "$HOME/.local/bin" && "$HOME/.local/bin/osv-scanner" --version && rm -rf "$CODE_DIR"
```

`npm ci` は、導入スクリプトが使う依存（`yaml` など）を一時フォルダに入れるためのもの。`--ignore-scripts` で、パッケージのスクリプトは実行しない。

`osv-scanner version: ...` が表示されれば成功。sha256 の不一致で止まったら、ファイルを使わずに止まり、ユーザーに報告する。

## ステップ 2：プラグインを入れる

ステップ 0 で見つけた `claude` を使う。PATH に無い場合はフルパスのまま使い、PATH は変えない。

```bash
CLAUDE="$(command -v claude || ls "$HOME/.local/bin/claude.exe" "$HOME/.local/bin/claude" 2>/dev/null | head -n 1)" && "$CLAUDE" plugin marketplace add artifice-inc/security-intelligence-feed && "$CLAUDE" plugin install security-check@security-intelligence-feed && "$CLAUDE" plugin list
```

`security-check@security-intelligence-feed` が `enabled` と表示されれば成功。

## ステップ 3：再起動と動作確認

1. ユーザーに、Claude Code を終了し、**照合したい案件のフォルダ**で起動し直すよう頼む。新しいプラグインは、再起動するまで読み込まれない。
2. 起動し直した Claude Code で、ユーザーが `/security-check` を実行する。
3. 初回は、公開側のコードとフィードの取得、OSV のデータベースの取得で、数分かかる。

正しく動けば、日本語のレポートが出る。最初の節は「案件全体」で、ロックファイルとランタイムごとの件数が並ぶ。

## 完了の判定

次をすべて満たせば、導入は完了。

- [ ] `~/.local/bin/osv-scanner --version` が固定版の版を表示する
- [ ] `command -v osv-scanner` が `~/.local/bin/osv-scanner` を指す（新しいシェルで。Windows では PATH の確認の代わりに、`~/.local/bin/osv-scanner.exe` の sha256 が固定版と一致し、そのうえで `--version` が固定版の版を表示すること）
- [ ] `claude plugin list`（PATH に無ければ `"$HOME/.local/bin/claude" plugin list`）に `security-check@security-intelligence-feed` が `enabled` で出る
- [ ] `~/.config/security-intelligence/staff` が**ない**

## うまくいかないとき

| 症状 | 考えられる原因と対処 |
|---|---|
| `marketplace add` が失敗する | github.com に接続できない。プロキシやファイアウォールの設定をユーザーに確かめてもらう |
| `install-scanner.mjs` が sha256 の不一致で止まる | ダウンロードが壊れたか、途中で書き換えられた。もう一度だけ実行し、同じなら止めて問い合わせる |
| `/security-check` で「版不一致」と出る | PATH 上の別の osv-scanner が先に見つかっている。`command -v osv-scanner` を確かめ、`~/.local/bin` を PATH の前に置く |
| `/security-check` で「社内用」「非公開側」に関するエラーで止まる | `~/.config/security-intelligence/staff` がある。ユーザーの了承を得て消す |
| レポートでランタイム・カーネル・Packagist が「照合不能」になる | 公開フィードを取得できていない。github.com への接続を確かめ、もう一度実行する |
| `--export` が使えない | 提供元の社内向けの機能で、配布版では使えない（仕様） |

## 導入で作られるもの・削除の方法

| 場所 | 中身 |
|---|---|
| `~/.local/bin/osv-scanner` | OSV-Scanner（固定版） |
| `~/.cache/security-intelligence-feed.git` | 公開側のコードのキャッシュ |
| `~/.cache/security-intelligence-feed-data` | 公開の脆弱性情報（フィード）のキャッシュ |
| `~/.cache/security-intelligence-osv-db` | OSV のデータベースのキャッシュ |
| Claude Code の設定 | マーケットプレイス `security-intelligence-feed` と、プラグイン `security-check` |

削除するときは、（ステップ 0 の `claude` を使って）`claude plugin uninstall security-check@security-intelligence-feed` と `claude plugin marketplace remove security-intelligence-feed` を実行し、上の表のファイルとフォルダを消す。

## このツールについて

- 案件の lockfile（npm・Composer・PyPI）とランタイム（PHP・Node.js・Python）の版を、手元で公開の脆弱性情報と照合し、日本語でレポートする。
- 案件の情報は手元から出ない。取得するのは公開の情報（このリポジトリのコードと `feed` ブランチ、OSV のデータベース）だけ。
- 依存関係の更新・コミット・push はしない。修正はユーザーが判断して行う。

問い合わせ先：support@artifice-inc.com
