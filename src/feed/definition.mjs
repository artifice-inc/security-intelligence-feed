export const FEED_FORMAT_VERSION = 1;
export const SUPPORTED_FEED_FORMATS = [1];

export const REQUIRED_FEED_FILES = [
  'feed-format.json', 'health.json', 'runtimes/php.json', 'runtimes/nodejs.json', 'runtimes/python.json',
  'packagist-advisories.json', 'os/amazon-linux-kernel.json', 'jp-alerts.json', 'kev.json', 'epss-high.json',
];

// パスの正規表現 → スキーマ名。ここにないパスはフィードに置けない
export const FEED_RULES = [
  [/^feed-format\.json$/, 'feed-format'],
  [/^health\.json$/, 'feed-health'],
  [/^runtimes\/(php|nodejs|python)\.json$/, 'runtimes'],
  [/^packagist-advisories\.json$/, 'packagist-advisories'],
  [/^os\/amazon-linux-kernel\.json$/, 'amazon-linux-kernel'],
  [/^jp-alerts\.json$/, 'jp-alerts'],
  [/^kev\.json$/, 'kev'],
  [/^epss-high\.json$/, 'epss-high'],
  [/^advisories\/[A-Za-z0-9-]+\.json$/, 'advisory'],
  [/^aws-bulletins\.json$/, 'aws-bulletins'],
];

export const PUBLIC_ADVISORY_SOURCES = ['node-core', 'php-ghsa', 'python-psf'];

// フィードと旧 data/ に共通する収集の生成物（ディレクトリは末尾 /）
export const COMMON_DATA_FILES = [
  'advisories/', 'runtimes/', 'packagist-advisories.json', 'os/', 'jp-alerts.json', 'aws-bulletins.json',
];

// 取得の記録がない KEV・EPSS の fetched_at に入れる値（空のフィードの初期値と、前回なしで失敗した回）
export const NEVER_FETCHED_AT = '1970-01-01T00:00:00Z';
