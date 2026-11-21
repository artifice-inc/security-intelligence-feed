import { readFileSync, readdirSync } from 'node:fs';
import path from 'node:path';
import Ajv from 'ajv';
import { ROOT_DIR } from './config.mjs';

const SCHEMA_DIR = path.join(ROOT_DIR, 'schemas');
let ajvInstance;

function getAjv() {
  if (ajvInstance) return ajvInstance;
  ajvInstance = new Ajv({ allErrors: true, strict: false });
  for (const file of readdirSync(SCHEMA_DIR).filter((f) => f.endsWith('.schema.json'))) {
    ajvInstance.addSchema(JSON.parse(readFileSync(path.join(SCHEMA_DIR, file), 'utf8')), file.replace('.schema.json', ''));
  }
  return ajvInstance;
}

export class SchemaError extends Error {
  constructor(name, errors) {
    super(`スキーマ違反 (${name}): ${errors.slice(0, 5).map((e) => `${e.instancePath || '/'} ${e.message}`).join('; ')}`);
    this.schema = name;
    this.errors = errors;
  }
}

export function validate(name, data) {
  const check = getAjv().getSchema(name);
  if (!check) throw new Error(`未定義のスキーマです: ${name}`);
  return check(data) ? { ok: true, errors: [] } : { ok: false, errors: check.errors };
}

export function assertValid(name, data) {
  const result = validate(name, data);
  if (!result.ok) throw new SchemaError(name, result.errors);
  return data;
}
