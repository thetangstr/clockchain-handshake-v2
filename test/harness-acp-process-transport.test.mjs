import assert from "node:assert/strict";
import test from "node:test";

import { AgentSideConnection, PROTOCOL_VERSION, ndJsonStream } from "@agentclientprotocol/sdk";

import { createAcpProcessTransport } from "../src/harness/acp-process-transport.mjs";
import { ACP_VERSION_PINS } from "../src/harness/version-pins.mjs";
import { DIGEST, MCP_ENDPOINT, SESSION, a2aConfig, retainedAction } from "./harness-acp-fixtures.mjs";

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

function acpFixtureSpawn({
  calls,
  closeState = null,
  helperAction = null,
  stopReason = "end_turn",
  permissionCommand = `clockchain-agent-authorize ${DIGEST}`,
  permissionTitle = "display-only approval label",
}) {
  return (command, args, options) => {
    calls.push({ command, args, options });
    const clientToAgent = new TransformStream();
    const agentToClient = new TransformStream();
    new AgentSideConnection((connection) => ({
      async initialize(params) {
        calls.push(["initialize", params]);
        return {
          protocolVersion: PROTOCOL_VERSION,
          agentCapabilities: { loadSession: false },
          authMethods: [],
        };
      },
      async newSession(params) {
        calls.push(["newSession", params]);
        return { sessionId: `acp-${SESSION}` };
      },
      async loadSession() {
        throw new Error("unexpected loadSession");
      },
      async authenticate() {
        throw new Error("unexpected authenticate");
      },
      async prompt(params) {
        calls.push(["prompt", params]);
        if (helperAction !== null) {
          await connection.sessionUpdate({
            sessionId: params.sessionId,
            update: {
              sessionUpdate: "tool_call_update",
              toolCallId: "tool-mcp-1",
              name: "agent_handshake_next",
              kind: "other",
              status: "completed",
              rawOutput: {
                helperStep: {
                  action: helperAction,
                  roleAccess: "role-access-secret /Users/alice/secret",
                  invitation: "invite-secret",
                },
              },
            },
          });
        }
        await connection.sessionUpdate({
          sessionId: params.sessionId,
          update: {
            sessionUpdate: "tool_call",
            toolCallId: "tool-1",
            title: permissionTitle,
            name: "Bash",
            kind: "execute",
            status: "pending",
            rawInput: { command: permissionCommand, transcript: "secret-canary /Users/alice/secret" },
          },
        });
        const permission = await connection.requestPermission({
          sessionId: params.sessionId,
          toolCall: {
            toolCallId: "tool-1",
            title: permissionTitle,
            name: "Bash",
            kind: "execute",
            status: "pending",
            rawInput: { command: permissionCommand },
          },
          options: [
            { optionId: "allow_once", name: "Allow once", kind: "allow_once" },
            { optionId: "reject_once", name: "Reject", kind: "reject_once" },
          ],
        });
        calls.push(["permission", permission]);
        await connection.sessionUpdate({
          sessionId: params.sessionId,
          update: { sessionUpdate: "usage_update", used: 7, size: 100000 },
        });
        return {
          stopReason,
          usage: { totalTokens: 7, inputTokens: 3, outputTokens: 4 },
        };
      },
      async cancel() {},
    }), ndJsonStream(agentToClient.writable, clientToAgent.readable));
    let resolveClosed;
    const closed = new Promise((resolve) => { resolveClosed = resolve; });
    return {
      pid: 4242,
      stdin: clientToAgent.writable,
      stdout: agentToClient.readable,
      stderr: new TransformStream().readable,
      closed,
      kill(signal) {
        calls.push({ kill: signal });
        if (closeState !== null) closeState.killed = true;
        setTimeout(() => {
          if (closeState !== null) closeState.closed = true;
          resolveClosed();
        }, 5);
      },
    };
  };
}

test("ACP process transport launches exact pinned stdio executable with isolated env and redacted evidence", async () => {
  const calls = [];
  const action = retainedAction({ role: "initiator", commandSha256: DIGEST });
  const transport = createAcpProcessTransport({
    harness: "codex",
    pin: ACP_VERSION_PINS.codex,
    spawn: fakeSpawn(calls),
    workspace: "/workspace/initiator",
    home: "/workspace/initiator/home",
    env: {
      CLOCKCHAIN_MCP_BEARER: "cc_secret_token_should_not_leak",
      HTTP_PROXY: "http://proxy.local:8080",
    },
    trustedAdapterPublicKeys: [action.adapterPublicKey],
  });
  await assert.rejects(() => transport.launch({
    acp: ACP_VERSION_PINS.codex,
    runtime: { runtimeId: "runtime-initiator", sessionId: SESSION, role: "initiator", harness: "codex" },
    mandate: { reference: "NS-1847" },
    mcpEndpoint: MCP_ENDPOINT,
    a2aConfig: a2aConfig("initiator"),
  }));

  assert.equal(calls[0].command, "codex-acp");
  assert.deepEqual(calls[0].args, []);
  assert.equal(calls[0].options.cwd, "/workspace/initiator");
  assert.equal(calls[0].options.env.HOME, "/workspace/initiator/home");
  assert.equal(calls[0].options.env.CLOCKCHAIN_MCP_URL, MCP_ENDPOINT);
  assert.equal(calls[0].options.env.CLOCKCHAIN_MCP_AUTH_HEADER, undefined);
  assert.equal(calls[0].options.env.CLOCKCHAIN_MCP_BEARER, undefined);
  assert.equal(calls[0].options.stdio.length, 3);
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
  const action = retainedAction({ role: "initiator", commandSha256: DIGEST });
  assert.throws(() => createAcpProcessTransport({
    harness: "codex",
    pin: ACP_VERSION_PINS.codex,
    spawn: fakeSpawn([]),
    workspace: "/workspace/initiator",
    home: "/workspace/initiator/home",
    env: {},
    trustedAdapterPublicKeys: [action.adapterPublicKey],
    decisionCallback: () => ({ decision: "authorize" }),
  }));
  const calls = [];
  const transport = createAcpProcessTransport({
    harness: "codex",
    pin: ACP_VERSION_PINS.codex,
    spawn: acpFixtureSpawn({ calls, helperAction: action }),
    workspace: "/workspace/initiator",
    home: "/workspace/initiator/home",
    nowMs: () => 1786337001000,
    env: { CLOCKCHAIN_MCP_BEARER: "token" },
    sessionEvidence: { terminalStatus: "completed", usage: { inputTokens: "999", outputTokens: "999" } },
    trustedAdapterPublicKeys: [action.adapterPublicKey],
  });
  await transport.launch({
    acp: ACP_VERSION_PINS.codex,
    runtime: { runtimeId: "runtime-initiator", sessionId: SESSION, role: "initiator", harness: "codex" },
    mandate: { reference: "NS-1847" },
    mcpEndpoint: MCP_ENDPOINT,
    a2aConfig: a2aConfig("initiator"),
  });
  await assert.rejects(() => transport.collectEvidence({ sessionId: SESSION }));
  await transport.terminate({ sessionId: SESSION, reason: "test-complete" });
  const evidence = await transport.collectEvidence({ sessionId: SESSION });
  assert.equal(evidence.terminalStatus, "completed");
  assert.equal(evidence.usage.inputTokens, "3");
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
  const action = retainedAction({ role: "responder", commandSha256: DIGEST });
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
    spawn: acpFixtureSpawn({ calls: [], helperAction: action }),
    workspace: "/workspace/responder",
    home: "/workspace/responder/home",
    nowMs: () => 1786337001000,
    env: { CLOCKCHAIN_MCP_BEARER: "token" },
    sessionEvidence: { terminalStatus: "completed", usage: { inputTokens: "1", outputTokens: "1" } },
    trustedAdapterPublicKeys: [action.adapterPublicKey],
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
  assert.equal((await transport.executeRetainedAction({ sessionId: SESSION, role: "responder", actionId: "action-1" })).executed, true);
  await transport.terminate({ sessionId: SESSION, reason: "test-complete" });
  await assert.rejects(() => transport.streamEvents({ sessionId: "other" }));
  assert.equal(DIGEST.length, 64);
});

test("ACP process transport performs real ACP lifecycle with unauthenticated dedicated MCP config", async () => {
  const action = retainedAction({ role: "initiator", requestDigest: "d".repeat(64), commandSha256: DIGEST });
  const calls = [];
  const closeState = { killed: false, closed: false };
  let now = 1786337001000;
  const transport = createAcpProcessTransport({
    harness: "codex",
    pin: ACP_VERSION_PINS.codex,
    spawn: acpFixtureSpawn({ calls, closeState, helperAction: action }),
    workspace: "/workspace/initiator",
    home: "/workspace/initiator/home",
    nowMs: () => now++,
    env: {
      CLOCKCHAIN_MCP_BEARER: "cc_secret_token_should_not_leak",
      HTTP_PROXY: "http://proxy.local:8080",
    },
    retainedActions: [],
    trustedAdapterPublicKeys: [action.adapterPublicKey],
  });
  const launched = await transport.launch({
    acp: ACP_VERSION_PINS.codex,
    runtime: { runtimeId: "runtime-initiator", sessionId: SESSION, role: "initiator", harness: "codex" },
    mandate: {
      reference: "NS-1847",
      statement: "public mandate",
      validForSeconds: "90",
      identityPolicy: "fresh-erc8004",
    },
    mcpEndpoint: MCP_ENDPOINT,
    a2aConfig: a2aConfig("initiator"),
  });

  assert.equal(launched.sessionId, SESSION);
  assert.deepEqual(calls.filter(Array.isArray).map((entry) => entry[0]), ["initialize", "newSession", "prompt", "permission"]);
  assert.equal(calls[0].options.env.CLOCKCHAIN_MCP_BEARER, undefined);
  assert.equal(calls[0].options.env.CLOCKCHAIN_MCP_AUTH_HEADER, undefined);
  const initialize = calls.find((entry) => entry[0] === "initialize")[1];
  assert.equal(initialize.protocolVersion, PROTOCOL_VERSION);
  assert.equal(initialize.clientCapabilities.fs.readTextFile, false);
  assert.equal(initialize.clientCapabilities.fs.writeTextFile, false);
  assert.equal(initialize.clientCapabilities.terminal, false);
  const newSession = calls.find((entry) => entry[0] === "newSession")[1];
  assert.equal(newSession.cwd, "/workspace/initiator");
  assert.deepEqual(newSession.mcpServers, [{
    type: "http",
    name: "clockchain-handshake",
    url: MCP_ENDPOINT,
    headers: [],
  }]);
  const prompt = calls.find((entry) => entry[0] === "prompt")[1].prompt[0].text;
  assert.match(prompt, /role: initiator/);
  assert.match(prompt, new RegExp(SESSION));
  assert.match(prompt, /NS-1847/);
  assert.match(prompt, /"validForSeconds":"90"/);
  assert.match(prompt, /"identityPolicy":"fresh-erc8004"/);
  assert.doesNotMatch(prompt, /validForMinutes|45/);
  assert.match(prompt, /direct A2A endpoint/);
  assert.doesNotMatch(prompt, /privateKey|secret|CLOCKCHAIN_MCP_BEARER|cc_secret|controller authority/i);
  assert.deepEqual(calls.find((entry) => entry[0] === "permission")[1], {
    outcome: { outcome: "selected", optionId: "allow_once" },
  });
  const events = await transport.streamEvents({ sessionId: SESSION });
  assert.equal(events.length >= 2, true);
  assert.equal(events[0].timestampMs, 1786337001000);
  assert.ok(events.every((event) => event.timestampMs >= 1786337001000));
  assert.doesNotMatch(JSON.stringify(events), /secret-canary|cc_secret|rawInput|rawOutput|transcript|reasoning|\/workspace\/initiator/i);
  await assert.rejects(() => transport.collectEvidence({ sessionId: SESSION }));
  await transport.terminate({ sessionId: SESSION, reason: "test-complete" });
  assert.equal(closeState.killed, true);
  assert.equal(closeState.closed, true);
  const evidence = await transport.collectEvidence({ sessionId: SESSION });
  assert.equal(evidence.terminalStatus, "completed");
  assert.equal(evidence.usage.inputTokens, "3");
  assert.equal(evidence.usage.outputTokens, "4");
  assert.equal(evidence.teardown.completed, true);
  assert.doesNotMatch(JSON.stringify(evidence), /cc_secret|CLOCKCHAIN_MCP_BEARER|transcript|reasoning|\/workspace/i);
});

test("ACP process transport rejects hostile mandate before prompt serialization", async () => {
  const action = retainedAction({ role: "initiator", commandSha256: DIGEST });
  const calls = [];
  const transport = createAcpProcessTransport({
    harness: "codex",
    pin: ACP_VERSION_PINS.codex,
    spawn: acpFixtureSpawn({ calls, helperAction: action }),
    workspace: "/workspace/initiator",
    home: "/workspace/initiator/home",
    nowMs: () => 1786337001000,
    env: {},
    retainedActions: [],
    trustedAdapterPublicKeys: [action.adapterPublicKey],
  });
  let traps = 0;
  await assert.rejects(
    () => transport.launch({
      acp: ACP_VERSION_PINS.codex,
      runtime: { runtimeId: "runtime-initiator", sessionId: SESSION, role: "initiator", harness: "codex" },
      mandate: new Proxy({}, {
        get() {
          traps += 1;
          return "secret-canary /Users/alice/secret";
        },
        ownKeys() {
          traps += 1;
          return [];
        },
      }),
      mcpEndpoint: MCP_ENDPOINT,
      a2aConfig: a2aConfig("initiator"),
    }),
    (error) => {
      assert.match(error.message, /ACP process transport validation failed safely/);
      assert.doesNotMatch(error.message, /secret-canary|\/Users\/alice\/secret/);
      return true;
    },
  );
  assert.equal(traps, 0);
  await assert.rejects(
    () => transport.launch({
      acp: ACP_VERSION_PINS.codex,
      runtime: { runtimeId: "runtime-initiator", sessionId: SESSION, role: "initiator", harness: "codex" },
      mandate: { get reference() { throw new Error("secret-canary /Users/alice/secret"); } },
      mcpEndpoint: MCP_ENDPOINT,
      a2aConfig: a2aConfig("initiator"),
    }),
    (error) => {
      assert.match(error.message, /ACP process transport validation failed safely/);
      assert.doesNotMatch(error.message, /secret-canary|\/Users\/alice\/secret/);
      return true;
    },
  );
  assert.equal(calls.length, 0);
});

test("ACP process transport registers retained helper actions dynamically from MCP tool updates only", async () => {
  const action = retainedAction({ role: "initiator", requestDigest: "d".repeat(64), commandSha256: DIGEST });
  const calls = [];
  const transport = createAcpProcessTransport({
    harness: "codex",
    pin: ACP_VERSION_PINS.codex,
    spawn: acpFixtureSpawn({ calls, helperAction: action }),
    workspace: "/workspace/initiator",
    home: "/workspace/initiator/home",
    nowMs: () => 1786337001000,
    env: {},
    retainedActions: [],
    trustedAdapterPublicKeys: [action.adapterPublicKey],
  });
  await transport.launch({
    acp: ACP_VERSION_PINS.codex,
    runtime: { runtimeId: "runtime-initiator", sessionId: SESSION, role: "initiator", harness: "codex" },
    mandate: { reference: "NS-1847", validForSeconds: "90", identityPolicy: "fresh-erc8004" },
    mcpEndpoint: MCP_ENDPOINT,
    a2aConfig: a2aConfig("initiator"),
  });
  await transport.terminate({ sessionId: SESSION, reason: "test-complete" });
  const events = await transport.streamEvents({ sessionId: SESSION });
  assert.ok(events.some((event) => event.type === "acp.retained_action.registered"));
  assert.doesNotMatch(JSON.stringify(events), /role-access-secret|invite-secret|helperStep|command|\/Users\/alice\/secret/);
});

test("ACP process transport rejects broad shell permission and non-end-turn completion", async () => {
  const action = retainedAction({ role: "initiator", requestDigest: "d".repeat(64), commandSha256: DIGEST });
  const badPermissionTransport = createAcpProcessTransport({
    harness: "codex",
    pin: ACP_VERSION_PINS.codex,
    spawn: acpFixtureSpawn({ calls: [], permissionCommand: "echo pwned" }),
    workspace: "/workspace/initiator",
    home: "/workspace/initiator/home",
    nowMs: () => 1786337001000,
    env: {},
    retainedActions: [],
    trustedAdapterPublicKeys: [action.adapterPublicKey],
  });
  await assert.rejects(() => badPermissionTransport.launch({
    acp: ACP_VERSION_PINS.codex,
    runtime: { runtimeId: "runtime-initiator", sessionId: SESSION, role: "initiator", harness: "codex" },
    mandate: { reference: "NS-1847" },
    mcpEndpoint: MCP_ENDPOINT,
    a2aConfig: a2aConfig("initiator"),
  }));

  const refusalTransport = createAcpProcessTransport({
    harness: "codex",
    pin: ACP_VERSION_PINS.codex,
    spawn: acpFixtureSpawn({ calls: [], helperAction: action, stopReason: "refusal" }),
    workspace: "/workspace/initiator",
    home: "/workspace/initiator/home",
    env: {},
    retainedActions: [],
    trustedAdapterPublicKeys: [action.adapterPublicKey],
  });
  await assert.rejects(() => refusalTransport.launch({
    acp: ACP_VERSION_PINS.codex,
    runtime: { runtimeId: "runtime-initiator", sessionId: SESSION, role: "initiator", harness: "codex" },
    mandate: { reference: "NS-1847" },
    mcpEndpoint: MCP_ENDPOINT,
    a2aConfig: a2aConfig("initiator"),
  }));
});
