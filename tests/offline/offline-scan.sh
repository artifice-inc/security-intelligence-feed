#!/usr/bin/env bash
# 試験1c: ネットワークを遮断（unshare -n）した状態で、実物の固定版 OSV-Scanner による照合が最後まで完了することを確認する。
# 使い方: tests/offline/offline-scan.sh <osv-scanner のパス>   （Linux 専用。CI の test-offline ジョブから呼ぶ）
set -euo pipefail
scanner="$1"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

mkdir -p "$work/db/osv-scalibr/npm" "$work/db/osv-scalibr/PyPI" "$work/project" "$work/osv" "$work/osv-py"
cat > "$work/osv/GHSA-test-test-test.json" <<'JSON'
{"schema_version":"1.6.0","id":"GHSA-test-test-test","modified":"2026-01-01T00:00:00Z","summary":"offline test",
 "affected":[{"package":{"ecosystem":"npm","name":"offline-test-pkg"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"2.0.0"}]}]}]}
JSON
(cd "$work/osv" && zip -q "$work/db/osv-scalibr/npm/all.zip" GHSA-test-test-test.json)
# PyPI の DB。①名前に requirements を含まない prod.txt（requirements.txt: の接頭辞で種類を指定）と ②poetry.lock の両方を照合する
cat > "$work/osv-py/PYSEC-test-1.json" <<'JSON'
{"schema_version":"1.6.0","id":"PYSEC-test-1","modified":"2026-01-01T00:00:00Z","summary":"offline pypi test",
 "affected":[{"package":{"ecosystem":"PyPI","name":"offline-test-py"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"2.0.0"}]}]}]}
JSON
(cd "$work/osv-py" && zip -q "$work/db/osv-scalibr/PyPI/all.zip" PYSEC-test-1.json)
printf 'offline-test-py==1.0.0\n' > "$work/project/prod.txt"
cat > "$work/project/poetry.lock" <<'TOML'
[[package]]
name = "offline-test-py"
version = "1.0.0"
description = ""
optional = false
python-versions = "*"

[metadata]
lock-version = "2.0"
python-versions = "*"
content-hash = "0"
TOML
# resolved がない依存はローカルのパッケージ（?source=LOCAL）とみなされ、照合の対象外になる
cat > "$work/project/package-lock.json" <<'JSON'
{"name":"t","lockfileVersion":3,"requires":true,"packages":{"":{"name":"t","dependencies":{"offline-test-pkg":"1.0.0"}},
 "node_modules/offline-test-pkg":{"version":"1.0.0","resolved":"https://registry.npmjs.org/offline-test-pkg/-/offline-test-pkg-1.0.0.tgz"}}}
JSON

# GitHub のランナーでは一般ユーザーの unshare が禁止されているため sudo で実行する。
# 遮断できなかったのに照合が成功したように見えないよう、先に遮断そのものを確かめる
sudo unshare -n true || { echo "unshare -n を実行できません（ネットワークを遮断できない）"; exit 1; }
if sudo unshare -n getent hosts osv-vulnerabilities.storage.googleapis.com > /dev/null 2>&1; then
  echo "unshare -n の中で名前解決できてしまいます（遮断されていない）"; exit 1
fi

set +e
sudo unshare -n env OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY="$work/db" "$scanner" scan source --offline --format=json --all-packages \
  --lockfile="$work/project/package-lock.json" > "$work/out.json" 2> "$work/err.txt"
code=$?
set -e
cat "$work/err.txt" >&2
# 脆弱性ありは終了コード1。実行エラー（127 など）は失敗として扱う
[ "$code" -eq 1 ] || { echo "想定外の終了コード: $code"; exit 1; }
grep -q 'GHSA-test-test-test' "$work/out.json" || { echo "検出結果に GHSA-test-test-test がありません"; exit 1; }
echo "1c OK: ネットワーク遮断下で照合が完了しました"

# PyPI: 種類の接頭辞つきの prod.txt と poetry.lock が、どちらも検出される
set +e
sudo unshare -n env OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY="$work/db" "$scanner" scan source --offline --format=json --all-packages \
  --lockfile="requirements.txt:$work/project/prod.txt" --lockfile="$work/project/poetry.lock" > "$work/out-py.json" 2> "$work/err-py.txt"
code=$?
set -e
cat "$work/err-py.txt" >&2
[ "$code" -eq 1 ] || { echo "PyPI: 想定外の終了コード: $code"; exit 1; }
for source in "$work/project/prod.txt" "$work/project/poetry.lock"; do
  node -e '
    const doc = JSON.parse(require("fs").readFileSync(process.argv[1], "utf8"));
    const hit = doc.results.find((r) => r.source.path === process.argv[2]);
    const ids = (hit?.packages ?? []).flatMap((p) => (p.vulnerabilities ?? []).map((v) => v.id));
    if (!ids.includes("PYSEC-test-1")) { console.error("PyPI: 検出されません: " + process.argv[2] + " " + JSON.stringify(doc.results.map((r) => r.source.path))); process.exit(1); }
  ' "$work/out-py.json" "$source"
done
echo "1c OK: PyPI（prod.txt の requirements.txt: 指定と poetry.lock）も検出されました"
