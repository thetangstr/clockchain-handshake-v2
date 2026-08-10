import assert from "node:assert/strict";
import { lstat, mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import {
  commitAgentPolicy,
  readAgentPolicy,
} from "../src/agent-cli/policy.mjs";
import { buildAgentCliFixture } from "./support/agent-cli-fixture.mjs";

test("commits one exact local policy in private state and returns only its digest", async (t) => {
  const stateDir = await mkdtemp(join(tmpdir(), "clockchain-agent-policy-"));
  await rm(stateDir, { recursive: true });
  t.after(() => rm(stateDir, { force: true, recursive: true }));
  const { policy } = await buildAgentCliFixture();
  const committed = await commitAgentPolicy({ stateDir, policy, platform: "darwin" });
  assert.deepEqual(Object.keys(committed), ["policyDigest"]);
  assert.match(committed.policyDigest, /^[0-9a-f]{64}$/);
  assert.equal((await lstat(stateDir)).mode & 0o777, 0o700);
  assert.equal((await lstat(join(stateDir, "policy.json"))).mode & 0o777, 0o600);
  assert.deepEqual(await readAgentPolicy({ stateDir, platform: "darwin" }), {
    policy,
    policyDigest: committed.policyDigest,
  });
  await assert.rejects(() => commitAgentPolicy({ stateDir, policy, platform: "darwin" }));
});

test("rejects policy drift instead of normalizing intent", async () => {
  const { policy } = await buildAgentCliFixture();
  for (const changed of [
    { ...policy, maxValidForSeconds: "91" },
    { ...policy, externalBusinessActionsAllowed: true },
    { ...policy, mcpOrigin: "https://example.invalid" },
    { ...policy, extra: true },
  ]) {
    await assert.rejects(() => commitAgentPolicy({ stateDir: "/tmp", policy: changed }));
  }
});
