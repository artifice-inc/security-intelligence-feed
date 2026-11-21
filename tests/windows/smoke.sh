#!/usr/bin/env bash
# Windows（Git Bash）で /security-check の手順をなぞり、実物の osv-scanner.exe まで通ることを確かめる。CI の windows ジョブ専用。
# 使い方: bash tests/windows/smoke.sh   （作業コピーで npm ci --ignore-scripts 済み。github.com にアクセスする）
set -euo pipefail
[ -n "${CI:-}" ] || { echo "CI 専用です（git config --global を書き換えるため）"; exit 1; }

repo="$(cd "$(dirname "$0")/../.." && pwd)"
checks="$(cygpath -am "$repo/tests/windows/check-output.mjs")"
# 空白を含む名前で、コード・フィード・案件・DB もすべてこの下に置く
base="${RUNNER_TEMP:-$(mktemp -d)}/si smoke"
rm -rf "$base" && mkdir -p "$base"
win() { cygpath -am "$1"; }
# SKILL.md と同じく、Node（と powershell）を起動するコマンドだけ引数の変換を止める
nodex() { MSYS2_ARG_CONV_EXCL='*' node "$@"; }
step() { echo "=== $*"; }

# 1. 公開側のコード: HEAD から bare を作り、Windows の git archive で LF のまま展開する
step "1. コードの展開"
git config --global core.autocrlf true
bare="$base/code.git"; code="$base/code"
git init --quiet --bare "$bare"
git --git-dir "$bare" fetch --quiet "$(win "$repo")" HEAD:refs/heads/main # 浅い checkout からでも取れる
code_sha="$(git --git-dir "$bare" rev-parse refs/heads/main)"
mkdir -p "$code"
git -c core.autocrlf=false -c core.eol=lf --git-dir "$bare" archive "$code_sha" | tar -x -C "$code"
(cd "$code" && npm ci --ignore-scripts --silent)
node -e 'if (require("fs").readFileSync(process.argv[1]).includes(13)) { console.error("package.json に CR が混ざっています"); process.exit(1); }' "$(win "$code/package.json")"

# 2. フィード: feed ブランチを clone し、同じ形で data を展開する
step "2. フィードの展開"
feed_cache="$base/feed-cache"; feed="$base/feed"
git clone --quiet --branch feed --depth 1 "https://github.com/${GITHUB_REPOSITORY:-artifice-inc/security-intelligence-feed}" "$feed_cache"
feed_sha="$(git -C "$feed_cache" rev-parse HEAD)"
mkdir -p "$feed"
git -c core.autocrlf=false -c core.eol=lf -C "$feed_cache" archive "$feed_sha" data | tar -x -C "$feed"

# 3. 試験用の案件: Git リポジトリ。npm の2つは別名を共有しない ID、PyPI は PYSEC-WIN-SMOKE-1
step "3. 案件の作成"
proj="$base/project"
mkdir -p "$proj/sub" "$proj/.security"
npm_lock() { # $1=パッケージ名
  printf '{"name":"t","lockfileVersion":3,"requires":true,"packages":{"":{"name":"t","dependencies":{"%s":"1.0.0"}},"node_modules/%s":{"version":"1.0.0","resolved":"https://registry.npmjs.org/%s/-/%s-1.0.0.tgz"}}}\n' "$1" "$1" "$1" "$1"
}
npm_lock smoke-root-pkg > "$proj/package-lock.json"
npm_lock smoke-sub-pkg > "$proj/sub/package-lock.json"
printf 'smoke-py-pkg==1.0.0\n' > "$proj/requirements.txt"
printf 'lockfiles:\n  - package-lock.json\n  - sub/package-lock.json\n  - requirements.txt\n' > "$proj/.security/stack.yml"
git -C "$proj" init --quiet
git -C "$proj" add -A
git -C "$proj" -c user.name=smoke -c user.email=smoke@example.invalid commit --quiet -m "試験用"
proj_sha="$(git -C "$proj" rev-parse HEAD)"

# 4. 試験用の DB（osv-scalibr/<eco>/all.zip と meta.json）
step "4. DB の作成"
db="$base/db"
osv_record() { # $1=ID $2=ecosystem $3=パッケージ名 $4=範囲の種類
  printf '{"schema_version":"1.6.0","id":"%s","modified":"2026-01-01T00:00:00Z","summary":"windows smoke","affected":[{"package":{"ecosystem":"%s","name":"%s"},"ranges":[{"type":"%s","events":[{"introduced":"0"},{"fixed":"2.0.0"}]}]}]}\n' "$1" "$2" "$3" "$4"
}
make_zip() { # $1=元のフォルダ $2=ZIP
  mkdir -p "$(dirname "$2")"
  MSYS2_ARG_CONV_EXCL='*' powershell -NoProfile -Command "Compress-Archive -Path '$(win "$1")/*' -DestinationPath '$(win "$2")'"
}
mkdir -p "$base/src-npm" "$base/src-pypi"
osv_record GHSA-wn01-smk1-test npm smoke-root-pkg SEMVER > "$base/src-npm/GHSA-wn01-smk1-test.json"
osv_record GHSA-wn02-smk2-test npm smoke-sub-pkg SEMVER > "$base/src-npm/GHSA-wn02-smk2-test.json"
osv_record PYSEC-WIN-SMOKE-1 PyPI smoke-py-pkg ECOSYSTEM > "$base/src-pypi/PYSEC-WIN-SMOKE-1.json"
make_zip "$base/src-npm" "$db/osv-scalibr/npm/all.zip"
make_zip "$base/src-pypi" "$db/osv-scalibr/PyPI/all.zip"
fetched_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
npm_sha="$(sha256sum "$db/osv-scalibr/npm/all.zip" | cut -d' ' -f1)"
pypi_sha="$(sha256sum "$db/osv-scalibr/PyPI/all.zip" | cut -d' ' -f1)"
printf '{"npm":{"fetched_at":"%s","sha256":"%s"},"PyPI":{"fetched_at":"%s","sha256":"%s"}}\n' "$fetched_at" "$npm_sha" "$fetched_at" "$pypi_sha" > "$db/meta.json"

# 5. 固定版のスキャナを導入する
step "5. osv-scanner.exe の導入"
nodex "$(win "$code/src/cli/install-scanner.mjs")" --platform windows_amd64 --dest "$(win "$base/bin")"
scanner="$(win "$base/bin/osv-scanner.exe")"

# 6. 起動。check_cli は SKILL.md の形（案件の絶対パスを先に確定し、サブシェルの中で展開先へ cd して起動）
check_cli() { # $1=出力ファイル、残りは --project など追加の引数
  local out="$1"; shift
  local project_win; project_win="$(win "$proj")"
  ( cd "$code" && MSYS2_ARG_CONV_EXCL='*' node "$(win "$code/src/cli/security-check.mjs")" --project-dir "$project_win" --feed-dir "$(win "$feed/data")" --feed-sha "$feed_sha" --code-sha "$code_sha" \
      --osv-db-dir "$(win "$db")" --scanner "$scanner" "$@" --json ) > "$out"
}

step "6a. SKILL.md の手順どおり（--project /team/app）"
check_cli "$base/out-a.json" --project /team/app
nodex "$checks" full "$(win "$base/out-a.json")" "$feed_sha" "$proj_sha"

# 引数の変換: 止めれば /team/app のまま届く。止めない場合は書き換わるかを記録する（対照）
[ "$(nodex -p 'process.argv[1]' /team/app)" = "/team/app" ] || { echo "MSYS2_ARG_CONV_EXCL='*' でも引数が書き換わりました"; exit 1; }
echo "対照（変換を止めない）: $(node -p 'process.argv[1]' /team/app)"

step "6b. 案件のフォルダが現在のディレクトリ（偽の git.exe があっても起動されない）"
marker_dir="$base/marker"; mkdir -p "$marker_dir"
marker="$marker_dir/git-ran.txt"
# 偽の git.exe: PowerShell の Add-Type で作る小さな実行ファイル。起動されたら目印を作る（追加のツールが要らず、実物の PE になる）
MSYS2_ARG_CONV_EXCL='*' powershell -NoProfile -Command "Add-Type -OutputType ConsoleApplication -OutputAssembly '$(win "$proj/git.exe")' -TypeDefinition 'public class P { public static void Main() { System.IO.File.WriteAllText(\"$(win "$marker")\", \"ran\"); } }'"
# 対照: 同じ実行環境で、案件のフォルダから Node が git を名前で起動すると偽物が動くか
(cd "$proj" && node -e 'try { require("child_process").execFileSync("git", ["--version"], { stdio: "ignore" }); } catch {}')
check_effective=0
if [ -f "$marker" ]; then check_effective=1; rm -f "$marker"; else echo "この環境では案件のフォルダの git.exe が優先されないため、(b) の目印の確認を飛ばします"; fi
[ ! -f "$marker" ] || { echo "対照の目印が消えていません"; exit 1; }
( cd "$proj" && MSYS2_ARG_CONV_EXCL='*' node "$(win "$code/src/cli/security-check.mjs")" --project-dir . --feed-dir ../feed/data --feed-sha "$feed_sha" --code-sha "$code_sha" \
    --osv-db-dir ../db --scanner "$scanner" --json ) > "$base/out-b.json"
nodex "$checks" full "$(win "$base/out-b.json")" "$feed_sha" "$proj_sha"
if [ "$check_effective" = 1 ] && [ -f "$marker" ]; then echo "偽の git.exe が起動されました（案件のフォルダから探している）"; exit 1; fi
rm -f "$proj/git.exe"

step "6c. 失敗系: sha256 の合わないスキャナ"
cp "$base/bin/osv-scanner.exe" "$base/bin/bad-osv-scanner.exe"
printf 'x' >> "$base/bin/bad-osv-scanner.exe"
bad_scanner="$(win "$base/bin/bad-osv-scanner.exe")"
( cd "$code" && MSYS2_ARG_CONV_EXCL='*' node "$(win "$code/src/cli/security-check.mjs")" --project-dir "$(win "$proj")" --feed-dir "$(win "$feed/data")" --feed-sha "$feed_sha" --code-sha "$code_sha" \
    --osv-db-dir "$(win "$db")" --scanner "$bad_scanner" --json ) > "$base/out-bad.json"
nodex "$checks" unavailable "$(win "$base/out-bad.json")"

step "7. 壊れた ZIP の拒否（実物の tar.exe）"
nodex "$checks" broken-zip "$(win "$db/osv-scalibr/PyPI/all.zip")"

step "8. 空の DB から取得（PyPI だけの案件。ネットワークを使う）"
py_proj="$base/project-py"; mkdir -p "$py_proj"
printf 'smoke-py-pkg==1.0.0\n' > "$py_proj/requirements.txt"
( cd "$code" && MSYS2_ARG_CONV_EXCL='*' node "$(win "$code/src/cli/security-check.mjs")" --project-dir "$(win "$py_proj")" --feed-dir "$(win "$feed/data")" --feed-sha "$feed_sha" --code-sha "$code_sha" \
    --osv-db-dir "$(win "$base/db-empty")" --scanner "$scanner" --json ) > "$base/out-empty.json"
nodex "$checks" fresh-pypi "$(win "$base/out-empty.json")"

# すべての起動が終わってから、サブシェルの外で展開先を消せることを確かめる
step "9. 展開先の削除"
rm -rf "$code" "$feed" "$feed_cache"
[ ! -e "$code" ] || { echo "コードの展開先を消せませんでした"; exit 1; }
echo "windows smoke OK"
