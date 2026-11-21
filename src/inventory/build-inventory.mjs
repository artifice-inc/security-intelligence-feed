import { detectStack } from './detect-stack.mjs';

// 作業ツリーから §5.3 のインベントリを作る。lockfile の中身や依存の一覧は含めない（D6）
export function buildInventory({ root, project, mode, monitorRef, sourceCommit, inventoryAsOf, exposure, lockfileOverride }) {
  const detected = detectStack(root, { lockfileOverride });
  return {
    inventory: {
      project, mode, monitor_ref: monitorRef, source_commit: sourceCommit, inventory_as_of: inventoryAsOf,
      files: detected.files, runtimes: detected.runtimes,
      exposure: detected.stack?.exposure ?? exposure ?? null, os: detected.stack?.os ?? null, lockfiles: detected.lockfiles,
      // 申告のない案件の inventory を変えないため、あるときだけ足す
      ...(detected.stack?.kernel ? { kernel: detected.stack.kernel } : {}),
    },
    problems: detected.problems,
    stack: detected.stack,
  };
}
