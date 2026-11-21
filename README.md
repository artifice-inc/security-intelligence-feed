# security-intelligence-feed

PHP / Node.js / Python 向けの公開の脆弱性情報（KEV・EPSS 上位・各ランタイムの公式情報・国内の注意喚起）を、
1日2回収集して `feed` ブランチの `data/` に置くリポジトリです。コードは `main` にあります。
配布先の導入手順は `docs/setup.md` を参照してください。連絡先: support@artifice-inc.com

## 利用している情報源と帰属表示

- OSV（<https://osv.dev/>）：GHSA 由来のデータは CC-BY 4.0。PyPI は PyPA の Advisory Database（CC-BY 4.0）を含む。
- PSF の advisory-database（<https://github.com/psf/advisory-database>）：CC-BY 4.0。CPython の脆弱性の ID の一覧に使い、影響する版は OSV の個別の記録から取る。
- python.org のリリース一覧（<https://www.python.org/downloads/>）：CPython の修正版の算出と、版の実在確認に使う。
- CISA KEV：CC0。
- EPSS（FIRST）：<https://www.first.org/epss/>
- ALAS（Amazon Linux Security Center）：<https://explore.alas.aws.amazon.com/>（Amazon Linux のカーネルの脆弱性。AL2023・AL2）
- Packagist Security Advisories API：<https://packagist.org/apidoc>（User-Agent に連絡先を入れて利用）
- nodejs/security-wg、php/php-src、nodejs.org、php.net、endoflife.date、JPCERT/CC、IPA、JVN
- AWS Security Bulletins（<https://aws.amazon.com/security/security-bulletins/>）：RSS のタイトル・掲載日時だけを digest に表示する（照合はしない）。
