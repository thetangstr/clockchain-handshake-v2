import assert from "node:assert/strict";
import test from "node:test";

import { createAcpCodexHarnessAdapter } from "../src/harness/acp-codex-adapter.mjs";
import { ACP_VERSION_PINS } from "../src/harness/version-pins.mjs";
import { retainedAction, runAcpAdapterBehavior } from "./harness-acp-fixtures.mjs";

test("Codex ACP adapter exposes exact official version pin and executable", async () => {
  const adapter = createAcpCodexHarnessAdapter({
    retainedActions: [],
    transport: {},
    trustedAdapterPublicKeys: [retainedAction().adapterPublicKey],
  });
  assert.deepEqual(await adapter.inspectCapabilities(), {
    schema: "clockchain.harness-capabilities/v1",
    harness: "codex",
    retainedLocalActions: true,
    rawPayloadTransport: false,
  });
  assert.equal(ACP_VERSION_PINS.codex.packageName, "@agentclientprotocol/codex-acp");
  assert.equal(ACP_VERSION_PINS.codex.version, "1.1.14");
  assert.equal(ACP_VERSION_PINS.codex.integrity, "sha512-6JKLbGYH0/Gcz788U6KnljwSdNvUnXOyjJDOgsWsbwmXbxn/BXH+urF5AciACdgq13+KgAP9O96Kp6h33BgyKg==");
  assert.equal(ACP_VERSION_PINS.codex.executableName, "codex-acp");
});

test("Codex ACP adapter satisfies retained-action harness conformance", async () => {
  await runAcpAdapterBehavior({
    createAdapter: createAcpCodexHarnessAdapter,
    harness: "codex",
    pin: ACP_VERSION_PINS.codex,
    role: "initiator",
  });
});
