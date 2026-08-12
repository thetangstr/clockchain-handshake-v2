import assert from "node:assert/strict";
import test from "node:test";

import { createAcpProcessTransport } from "../src/harness/acp-process-transport.mjs";
import { ACP_VERSION_PINS } from "../src/harness/version-pins.mjs";
import { DIGEST, MCP_ENDPOINT, SESSION, a2aConfig } from "./harness-acp-fixtures.mjs";

function fakeSpawn(calls) {
  return (command, args, options) => {
    calls.push({ command, args, options });
    return {
      pid: 4242,
      stdin: {},
      stdout: {},
      stderr: {},
      kill(signal) {
        calls.push({ kill: signal });
      },
    };
  };
}

test("ACP process transport launches exact pinned stdio executable with isolated env and redacted evidence", async () => {
  const calls = [];
  const transport = createAcpProcessTransport({
    harness: "codex",
    pin: ACP_VERSION_PINS.codex,
    spawn: fakeSpawn(calls),
    workspace: "/workspace/initiator",
    home: "/workspace/initiator/home",
    mcpBearerEnvName: "CLOCKCHAIN_MCP_BEARER",
    env: {
      CLOCKCHAIN_MCP_BEARER: "cc_secret_token_should_not_leak",
      HTTP_PROXY: "http://proxy.local:8080",
    },
    sessionEvidence: {
      terminalStatus: "completed",
      usage: { inputTokens: "3", outputTokens: "5" },
    },
  });
  const launched = await transport.launch({
    acp: ACP_VERSION_PINS.codex,
    runtime: { runtimeId: "runtime-initiator", sessionId: SESSION, role: "initiator", harness: "codex" },
    mandate: { reference: "NS-1847" },
    mcpEndpoint: MCP_ENDPOINT,
    a2aConfig: a2aConfig("initiator"),
  });

  assert.equal(launched.sessionId, SESSION);
  assert.equal(calls[0].command, "codex-acp");
  assert.deepEqual(calls[0].args, []);
  assert.equal(calls[0].options.cwd, "/workspace/initiator");
  assert.equal(calls[0].options.env.HOME, "/workspace/initiator/home");
  assert.equal(calls[0].options.env.CLOCKCHAIN_MCP_URL, MCP_ENDPOINT);
  assert.equal(calls[0].options.env.CLOCKCHAIN_MCP_AUTH_HEADER, "Authorization: Bearer ${CLOCKCHAIN_MCP_BEARER}");
  assert.equal(calls[0].options.env.CLOCKCHAIN_MCP_BEARER, "cc_secret_token_should_not_leak");
  assert.equal(calls[0].options.stdio.length, 3);
  const events = await transport.streamEvents({ sessionId: SESSION });
  assert.equal(events[0].schema, "clockchain.harness-event/v1");
  assert.doesNotMatch(JSON.stringify(events), /cc_secret|transcript|reasoning|\/workspace\/initiator/i);
  const evidence = await transport.collectEvidence({ sessionId: SESSION });
  assert.equal(evidence.terminalStatus, "failed-closed");
  assert.equal(evidence.teardown.completed, true);
  assert.equal(evidence.usage.inputTokens, "0");
  assert.doesNotMatch(JSON.stringify(evidence), /cc_secret|CLOCKCHAIN_MCP_BEARER|\/workspace|transcript|reasoning/i);
});

test("ACP process transport rejects opaque proxy/accessor inputs and caller-completed evidence claims", async () => {
  let traps = 0;
  const proxy = new Proxy({}, {
    get() {
      traps += 1;
      return "secret-canary /Users/alice/secret";
    },
    ownKeys() {
      traps += 1;
      return [];
    },
  });
  assert.throws(
    () => createAcpProcessTransport(proxy),
    (error) => {
      assert.match(error.message, /ACP process transport validation failed safely/);
      assert.doesNotMatch(error.message, /secret-canary|\/Users\/alice\/secret/);
      return true;
    },
  );
  assert.equal(traps, 0);
  assert.throws(
    () => createAcpProcessTransport({ get harness() { throw new Error("secret-canary /Users/alice/secret"); } }),
    (error) => {
      assert.match(error.message, /ACP process transport validation failed safely/);
      assert.doesNotMatch(error.message, /secret-canary|\/Users\/alice\/secret/);
      return true;
    },
  );
  const transport = createAcpProcessTransport({
    harness: "codex",
    pin: ACP_VERSION_PINS.codex,
    spawn: fakeSpawn([]),
    workspace: "/workspace/initiator",
    home: "/workspace/initiator/home",
    mcpBearerEnvName: "CLOCKCHAIN_MCP_BEARER",
    env: { CLOCKCHAIN_MCP_BEARER: "token" },
    sessionEvidence: { terminalStatus: "completed", usage: { inputTokens: "999", outputTokens: "999" } },
  });
  await transport.launch({
    acp: ACP_VERSION_PINS.codex,
    runtime: { runtimeId: "runtime-initiator", sessionId: SESSION, role: "initiator", harness: "codex" },
    mandate: { reference: "NS-1847" },
    mcpEndpoint: MCP_ENDPOINT,
    a2aConfig: a2aConfig("initiator"),
  });
  const evidence = await transport.collectEvidence({ sessionId: SESSION });
  assert.equal(evidence.terminalStatus, "failed-closed");
  assert.equal(evidence.usage.inputTokens, "0");
  await assert.rejects(
    () => transport.launch(proxy),
    (error) => {
      assert.match(error.message, /ACP process transport validation failed safely/);
      assert.doesNotMatch(error.message, /secret-canary|\/Users\/alice\/secret/);
      return true;
    },
  );
  assert.equal(traps, 0);
});

test("ACP process transport rejects authority, endpoint, pin, and secret leakage", async () => {
  assert.throws(() => createAcpProcessTransport({
    harness: "codex",
    pin: ACP_VERSION_PINS.codex,
    spawn: fakeSpawn([]),
    workspace: "/workspace/initiator",
    home: "/workspace/initiator/home",
    mcpBearerEnvName: "CLOCKCHAIN_MCP_BEARER",
    env: { CLOCKCHAIN_MCP_BEARER: "token" },
    privateKey: "0x1234",
  }));
  const transport = createAcpProcessTransport({
    harness: "claude",
    pin: ACP_VERSION_PINS.claude,
    spawn: fakeSpawn([]),
    workspace: "/workspace/responder",
    home: "/workspace/responder/home",
    mcpBearerEnvName: "CLOCKCHAIN_MCP_BEARER",
    env: { CLOCKCHAIN_MCP_BEARER: "token" },
    sessionEvidence: { terminalStatus: "completed", usage: { inputTokens: "1", outputTokens: "1" } },
  });
  await assert.rejects(() => transport.launch({
    acp: ACP_VERSION_PINS.codex,
    runtime: { runtimeId: "runtime-responder", sessionId: SESSION, role: "responder", harness: "claude" },
    mandate: { reference: "NS-1847" },
    mcpEndpoint: MCP_ENDPOINT,
    a2aConfig: a2aConfig("responder"),
  }));
  await assert.rejects(() => transport.launch({
    acp: ACP_VERSION_PINS.claude,
    runtime: { runtimeId: "runtime-responder", sessionId: SESSION, role: "responder", harness: "claude" },
    mandate: { reference: "NS-1847", transcript: "private" },
    mcpEndpoint: MCP_ENDPOINT,
    a2aConfig: a2aConfig("responder"),
  }));
  await assert.rejects(() => transport.launch({
    acp: ACP_VERSION_PINS.claude,
    runtime: { runtimeId: "runtime-responder", sessionId: SESSION, role: "responder", harness: "claude" },
    mandate: { reference: "NS-1847" },
    mcpEndpoint: "https://mcp.clockchain.network/mcp",
    a2aConfig: a2aConfig("responder"),
  }));
  await transport.launch({
    acp: ACP_VERSION_PINS.claude,
    runtime: { runtimeId: "runtime-responder", sessionId: SESSION, role: "responder", harness: "claude" },
    mandate: { reference: "NS-1847" },
    mcpEndpoint: MCP_ENDPOINT,
    a2aConfig: a2aConfig("responder"),
  });
  assert.deepEqual(await transport.executeRetainedAction({ sessionId: SESSION, role: "responder", actionId: "action-1" }), {
    executed: false,
    actionId: "action-1",
    delegatedToAdapter: true,
  });
  await assert.rejects(() => transport.streamEvents({ sessionId: "other" }));
  assert.equal(DIGEST.length, 64);
});
