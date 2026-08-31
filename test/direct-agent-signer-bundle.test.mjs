import assert from "node:assert/strict";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import {
  auditDirectAgentSignerBundle,
  buildDirectAgentSignerBundle,
} from "../scripts/build-direct-agent-signer.mjs";

test("builds one separate local direct signer bundle with no dynamic or external non-node imports", async (t) => {
  const workDir = await mkdtemp(join(tmpdir(), "clockchain-direct-bundle-"));
  t.after(() => rm(workDir, { force: true, recursive: true }));
  const outfile = join(workDir, "clockchain-direct-agent-signer.cjs");

  const metafile = await buildDirectAgentSignerBundle({ outfile });
  const audit = auditDirectAgentSignerBundle(metafile);
  const bytes = await readFile(outfile);

  assert.equal(audit.entryPoints, 1);
  assert.equal(audit.dynamicImports, 0);
  assert.deepEqual(audit.externalImports, []);
  assert.ok(audit.inputs.some((input) => input.endsWith("bin/clockchain-direct-agent-signer.mjs")));
  assert.ok(audit.inputs.some((input) => input.endsWith("src/direct-agent-signer/adapter.mjs")));
  assert.ok(audit.inputs.some((input) => input.endsWith("src/direct-agent-signer/checkpoint.mjs")));
  assert.ok(audit.inputs.some((input) => input.endsWith("src/agent-cli/policy.mjs")));
  assert.ok(audit.inputs.some((input) => input.endsWith("src/core/wallet-bridge.mjs")));
  assert.ok(bytes.length > 0);
});
