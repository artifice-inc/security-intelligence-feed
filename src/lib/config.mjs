import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import YAML from 'yaml';

export const ROOT_DIR = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');

const readJson = (name, root) => JSON.parse(readFileSync(path.join(root, 'config', name), 'utf8'));

export const loadCentral = (root = ROOT_DIR) => readJson('central.json', root);
export const loadSchedule = (root = ROOT_DIR) => readJson('schedule.json', root);
export const loadThresholds = (root = ROOT_DIR) => readJson('thresholds.json', root);
export const loadRuntimeConditions = (root = ROOT_DIR) => readJson('runtime-conditions.json', root);
export const loadToolVersions = (root = ROOT_DIR) => readJson('tool-versions.json', root);
export const loadProjects = (root = ROOT_DIR) =>
  YAML.parse(readFileSync(path.join(root, 'config', 'projects.yaml'), 'utf8'));
