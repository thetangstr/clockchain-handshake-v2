import assert from "node:assert/strict";
import test from "node:test";

import { createAcpClaudeHarnessAdapter } from "../src/harness/acp-claude-adapter.mjs";
import { ACP_VERSION_PINS } from "../src/harness/version-pins.mjs";
import { retainedAction, runAcpAdapterBehavior } from "./harness-acp-fixtures.mjs";

test("Claude ACP adapter exposes exact official version pin and executable", async () => {
  const adapter = createAcpClaudeHarnessAdapter({
    retainedActions: [],
    transport: {},
    trustedAdapterPublicKeys: [retainedAction().adapterPublicKey],
  });
  assert.deepEqual(await adapter.inspectCapabilities(), {
    schema: "clockchain.harness-capabilities/v1",
    harness: "claude",
    retainedLocalActions: true,
    rawPayloadTransport: false,
  });
  assert.equal(ACP_VERSION_PINS.claude.packageName, "@agentclientprotocol/claude-agent-acp");
  assert.equal(ACP_VERSION_PINS.claude.version, "0.66.0");
  assert.equal(ACP_VERSION_PINS.claude.integrity, "sha512-BwalxKsxZzHZGEs+X9hV3biErLE7PHWoao2hmyP3QBWXxvMHbc1F1tzDE95ZA47Fle+KBYf2gKpgy1MJ+ZmVlw==");
  assert.equal(ACP_VERSION_PINS.claude.executableName, "claude-agent-acp");
});

test("Claude ACP adapter satisfies retained-action harness conformance", async () => {
  await runAcpAdapterBehavior({
    createAdapter: createAcpClaudeHarnessAdapter,
    harness: "claude",
    pin: ACP_VERSION_PINS.claude,
    role: "responder",
  });
});
