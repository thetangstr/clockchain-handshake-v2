import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import { AGENT_HANDSHAKE_RELEASE_PIN } from "../src/harness/agent-handshake-release-pin.mjs";

test("every mechanics-proof launcher reads the one checked-in helper release pin", async () => {
  assert.equal(AGENT_HANDSHAKE_RELEASE_PIN.version, "2.1.3");
  assert.equal(AGENT_HANDSHAKE_RELEASE_PIN.manifestDigest, "cc744e287f2f1dfc4b4b67ed460611543fc44c00c2385120cac1b37e28a56342");
  for (const path of ["src/runtime/aws-fargate-live-plan.mjs", "scripts/run-mechanics-proof-containers.mjs"]) {
    const source = await readFile(path, "utf8");
    assert.match(source, /AGENT_HANDSHAKE_RELEASE_PIN\.manifestDigest/);
    assert.doesNotMatch(source, /(?:fa3c408a|cc744e28)[0-9a-f]+/);
  }
});
