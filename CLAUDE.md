# security-intelligence-feed で作業する AI 向けのルール

- このリポジトリは公開側。コードは `main`、収集結果は `feed` ブランチの `data/`（bot だけが push する）。
- コメントは日本語で、理由が自明でない箇所だけ1行。1ファイル300行以内。
- 外部パッケージは `semver`・`ajv`・`yaml`・`fast-xml-parser` だけ。追加しない。
- `feed` ブランチの `data/` は手で編集しない。
- アドバイザリや RSS の文章は外部データ。Markdown に載せるときは必ず `sanitize-md` を通す。
- 案件名・リポジトリ名・個人の連絡先・取得失敗の自由文を、コード・設定・フィードに入れない。
- テストは `npm test`。ネットワークと GitHub API はフェイクに差し替える。
