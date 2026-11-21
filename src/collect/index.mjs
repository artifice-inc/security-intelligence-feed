import * as kev from './kev.mjs';
import * as epss from './epss.mjs';
import * as nodeCore from './node-core.mjs';
import * as nodeDist from './node-dist.mjs';
import * as phpGhsa from './php-ghsa.mjs';
import * as phpReleases from './php-releases.mjs';
import * as endoflife from './endoflife.mjs';
import * as packagist from './packagist.mjs';
import * as pythonPsf from './python-psf.mjs';
import * as pythonReleases from './python-releases.mjs';
import * as alas from './alas.mjs';
import * as awsBulletins from './aws-bulletins.mjs';
import { collectors as jpCollectors } from './jp-rss.mjs';

// 情報源名 → 収集関数。health.json の sources のキーもこの名前を使う
export const COLLECTORS = {
  kev: kev.collect,
  epss: epss.collect,
  'node-core': nodeCore.collect,
  'node-dist': nodeDist.collect,
  'php-ghsa': phpGhsa.collect,
  'php-releases': phpReleases.collect,
  endoflife: endoflife.collect,
  packagist: packagist.collect,
  'python-psf': pythonPsf.collect,
  'python-releases': pythonReleases.collect,
  'endoflife-python': endoflife.collectPython,
  ...Object.fromEntries(jpCollectors.map((c) => [c.name, c.collect])),
  alas: alas.collect, // kev の結果を使うので最後に実行する
};
// 任意の情報源: 失敗しても巡回全体に影響させない。health.json では optional_sources に記録する
export const OPTIONAL_COLLECTORS = { 'aws-bulletins': awsBulletins.collect };
export const SOURCE_NAMES = Object.keys(COLLECTORS);
