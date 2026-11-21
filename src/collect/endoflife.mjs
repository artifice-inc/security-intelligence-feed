import { guarded, okResult, expect } from './result.mjs';

export const PRODUCTS = ['php', 'nodejs'];
const urlOf = (product) => `https://endoflife.date/api/v1/products/${product}`;

// 製品の一覧ごとに収集器を作る。Python の取得失敗で php・nodejs（全案件の必須の情報源）を失敗にしないため、別の収集器にする
export const collectProducts = (products) => ({ http }) => guarded(async () => {
  const records = [];
  for (const product of products) {
    const data = await http.getJson(urlOf(product));
    expect(Array.isArray(data?.result?.releases), `endoflife: ${product} の releases が不正です`);
    for (const r of data.result.releases) {
      records.push({
        product, name: String(r.name), isEol: r.isEol === true, eolFrom: r.eolFrom ?? null,
        isLts: r.isLts === true, latest: r.latest?.name ?? null,
      });
    }
  }
  return okResult(records);
});

export const collect = collectProducts(PRODUCTS);
export const collectPython = collectProducts(['python']);
