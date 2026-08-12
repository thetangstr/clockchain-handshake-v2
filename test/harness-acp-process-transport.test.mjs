import assert from "node:assert/strict";
import test from "node:test";

import { AgentSideConnection, PROTOCOL_VERSION, ndJsonStream } from "@agentclientprotocol/sdk";

import { acpProcessTransportFailureStage, createAcpProcessTransport } from "../src/harness/acp-process-transport.mjs";
import { ACP_VERSION_PINS } from "../src/harness/version-pins.mjs";
import { DIGEST, MCP_ENDPOINT, OTHER_SESSION, SESSION, a2aConfig, retainedAction } from "./harness-acp-fixtures.mjs";

const VALID_MANDATE = Object.freeze({
  reference: "NS-1847",
  statement: "fresh ERC-8004 identity handshake using a direct A2A peer",
  validForSeconds: "90",
  identityPolicy: Object.freeze({
    erc8004: "required_existing_or_fresh",
    chainId: "eip155:11155111",
    registryAddress: "0x8004a818bfb912233c491871b3d84c89a494bd9e",
  }),
});

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

function helperStepForAction(action, overrides = {}) {
  const shellCommand = overrides.shellCommand ?? `node helper ${action.commandSha256}`;
  return Object.freeze({
    approvalCommand: `clockchain-agent-authorize ${action.commandSha256}`,
    commandLength: Buffer.byteLength(shellCommand),
    commandSha256: action.commandSha256,
    operation: action.operation,
    policyDigest: action.policyDigest,
    role: action.role,
    sessionId: action.sessionId,
    shellCommand,
  });
}

function actionRecorderFor(actions, calls = []) {
  const byDigest = new Map(actions.map((action) => [action.commandSha256, action]));
  return Object.freeze({
    record(helperStep) {
      calls.push(["record", helperStep]);
      assert.equal(helperStep.approvalCommand, `clockchain-agent-authorize ${helperStep.commandSha256}`);
      const action = byDigest.get(helperStep.commandSha256);
      if (action === undefined) throw new Error("unexpected helperStep");
      return action;
    },
  });
}

function partyBridgeFor(calls, { reject = false } = {}) {
  return Object.freeze({
    async observeToolResult(input) {
      calls.push(["partyBridge", input]);
      if (reject) throw new Error("party bridge rejected secret-canary /Users/alice/secret");
      return { observed: true, protocolSessionId: SESSION, toolResultDigest: "f".repeat(64) };
    },
  });
}

function acpFixtureSpawn({
  calls,
  closeState = null,
  helperAction = null,
  newSessionUpdates = null,
  newSessionUpdateSessionId = `acp-${SESSION}`,
  newSessionId = `acp-${SESSION}`,
  sessionUpdates = null,
  closeOnSignal = "SIGTERM",
  failInitialize = false,
  fastClose = false,
  useCloseEvent = false,
  stopReason = "end_turn",
  skipPermission = false,
  permissionCommand = `clockchain-agent-authorize ${DIGEST}`,
  permissionTitle = "display-only approval label",
  promptUpdateSessionId = null,
}) {
  return (command, args, options) => {
    calls.push({ command, args, options });
    const clientToAgent = new TransformStream();
    const agentToClient = new TransformStream();
    new AgentSideConnection((connection) => ({
      async initialize(params) {
        calls.push(["initialize", params]);
        if (failInitialize) throw new Error("initialize failed secret-canary /Users/alice/secret");
        return {
          protocolVersion: PROTOCOL_VERSION,
          agentCapabilities: { loadSession: false },
          authMethods: [],
        };
      },
      async newSession(params) {
        calls.push(["newSession", params]);
        if (newSessionUpdates !== null) {
          for (const update of newSessionUpdates) {
            await connection.sessionUpdate({ sessionId: newSessionUpdateSessionId, update });
          }
        }
        return { sessionId: newSessionId };
      },
      async setSessionConfigOption(params) {
        calls.push(["setSessionConfigOption", params]);
        return { configOptions: [] };
      },
      async loadSession() {
        throw new Error("unexpected loadSession");
      },
      async authenticate() {
        throw new Error("unexpected authenticate");
      },
      async prompt(params) {
        calls.push(["prompt", params]);
        const updateSessionId = promptUpdateSessionId ?? params.sessionId;
        if (sessionUpdates !== null) {
          for (const update of sessionUpdates) {
            await connection.sessionUpdate({ sessionId: updateSessionId, update });
          }
        } else if (helperAction !== null) {
          await connection.sessionUpdate({
            sessionId: params.sessionId,
            update: {
              sessionUpdate: "tool_call_update",
              toolCallId: "tool-mcp-1",
              kind: "other",
              title: "mcp.clockchain-handshake.agent_handshake_next",
              status: "completed",
              rawInput: {
                server: "clockchain-handshake",
                tool: "agent_handshake_next",
                arguments: { reference: "NS-1847" },
              },
              rawOutput: {
                result: {
                  structuredContent: {
                    helperStep: helperStepForAction(helperAction),
                  },
                },
                error: null,
              },
            },
          });
        }
        if (!skipPermission) {
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
        }
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
    const closeListeners = new Set();
    let resolveClosed;
    const closed = new Promise((resolve) => { resolveClosed = resolve; });
    const emitClose = () => {
      if (closeState !== null) closeState.closed = true;
      resolveClosed();
      for (const listener of closeListeners) listener(0, null);
    };
    const child = {
      pid: 4242,
      exitCode: null,
      stdin: clientToAgent.writable,
      stdout: agentToClient.readable,
      stderr: new TransformStream().readable,
      kill(signal) {
        calls.push({ kill: signal });
        if (closeState !== null) closeState.killed = true;
        if (signal === closeOnSignal) {
          setTimeout(() => {
            child.exitCode = 0;
            emitClose();
          }, 5);
        }
      },
      once(name, listener) {
        if (name === "close" || name === "exit") closeListeners.add(listener);
        return this;
      },
      off(name, listener) {
        if (name === "close" || name === "exit") closeListeners.delete(listener);
        return this;
      },
      removeListener(name, listener) {
        return this.off(name, listener);
      },
    };
    if (!useCloseEvent) child.closed = closed;
    if (fastClose) {
      queueMicrotask(emitClose);
    }
    return child;
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
      PATH: "/app/node_modules/.bin:/usr/local/bin:/usr/bin:/bin",
    },
    trustedAdapterPublicKeys: [action.adapterPublicKey],
  });
  await assert.rejects(() => transport.launch({
    acp: ACP_VERSION_PINS.codex,
    runtime: { runtimeId: "runtime-initiator", sessionId: SESSION, role: "initiator", harness: "codex" },
    mandate: VALID_MANDATE,
    mcpEndpoint: MCP_ENDPOINT,
    a2aConfig: a2aConfig("initiator"),
  }));

  assert.equal(calls[0].command, "codex-acp");
  assert.deepEqual(calls[0].args, []);
  assert.equal(calls[0].options.cwd, "/workspace/initiator");
  assert.equal(calls[0].options.env.HOME, "/workspace/initiator/home");
  assert.equal(calls[0].options.env.CLOCKCHAIN_MCP_URL, MCP_ENDPOINT);
  assert.equal(calls[0].options.env.CLOCKCHAIN_MCP_AUTH_HEADER, undefined);
  assert.equal(calls[0].options.env.PATH, "/app/node_modules/.bin:/usr/local/bin:/usr/bin:/bin");
  assert.equal(calls[0].options.env.CLOCKCHAIN_MCP_BEARER, undefined);
  assert.equal(calls[0].options.stdio.length, 3);
});

test("ACP process transport forwards only role-specific provider auth and pins the model deterministically", async () => {
  const codexCalls = [];
  const codexAction = retainedAction({ role: "initiator", commandSha256: DIGEST });
  const codexTransport = createAcpProcessTransport({
    harness: "codex",
    pin: ACP_VERSION_PINS.codex,
    spawn: acpFixtureSpawn({ calls: codexCalls, helperAction: codexAction }),
    workspace: "/workspace/initiator",
    home: "/workspace/initiator/home",
    env: {
      PATH: "/app/node_modules/.bin:/usr/local/bin:/usr/bin:/bin",
      CODEX_API_KEY: "codex-secret-value",
      CLOCKCHAIN_CODEX_MODEL: "gpt-5.6-terra",
      ANTHROPIC_API_KEY: "wrong-role-secret",
      AWS_SECRET_ACCESS_KEY: "wrong-role-aws-secret",
    },
    actionRecorder: actionRecorderFor([codexAction], codexCalls),
    nowMs: () => 1786337001000,
    trustedAdapterPublicKeys: [codexAction.adapterPublicKey],
  });
  await codexTransport.launch({
    acp: ACP_VERSION_PINS.codex,
    runtime: { runtimeId: "runtime-initiator", sessionId: SESSION, role: "initiator", harness: "codex" },
    mandate: VALID_MANDATE,
    mcpEndpoint: MCP_ENDPOINT,
    a2aConfig: a2aConfig("initiator"),
  });
  assert.equal(codexCalls[0].options.env.CODEX_API_KEY, "codex-secret-value");
  assert.equal(codexCalls[0].options.env.OPENAI_API_KEY, undefined);
  assert.equal(codexCalls[0].options.env.ANTHROPIC_API_KEY, undefined);
  assert.equal(codexCalls[0].options.env.AWS_SECRET_ACCESS_KEY, undefined);
  assert.deepEqual(codexCalls.find((call) => Array.isArray(call) && call[0] === "setSessionConfigOption")?.[1], {
    sessionId: `acp-${SESSION}`,
    configId: "model",
    value: "gpt-5.6-terra",
  });
  await codexTransport.terminate({ sessionId: SESSION });
  const codexEvidence = await codexTransport.collectEvidence({ sessionId: SESSION });
  assert.doesNotMatch(JSON.stringify(codexEvidence), /codex-secret-value|wrong-role-secret|gpt-5\.6-terra/);

  const claudeCalls = [];
  const claudeAction = retainedAction({ role: "responder", commandSha256: "e".repeat(64) });
  const claudeTransport = createAcpProcessTransport({
    harness: "claude",
    pin: ACP_VERSION_PINS.claude,
    spawn: acpFixtureSpawn({
      calls: claudeCalls,
      helperAction: claudeAction,
      permissionCommand: `clockchain-agent-authorize ${claudeAction.commandSha256}`,
    }),
    workspace: "/workspace/responder",
    home: "/workspace/responder/home",
    env: {
      PATH: "/app/node_modules/.bin:/usr/local/bin:/usr/bin:/bin",
      CLAUDE_CODE_USE_BEDROCK: "1",
      ANTHROPIC_MODEL: "us.anthropic.claude-sonnet-4-6",
      AWS_REGION: "us-west-2",
      AWS_ACCESS_KEY_ID: "ASIAEXAMPLE",
      AWS_SECRET_ACCESS_KEY: "aws-secret-value",
      AWS_SESSION_TOKEN: "aws-session-token",
    },
    actionRecorder: actionRecorderFor([claudeAction], claudeCalls),
    nowMs: () => 1786337001000,
    trustedAdapterPublicKeys: [claudeAction.adapterPublicKey],
  });
  await claudeTransport.launch({
    acp: ACP_VERSION_PINS.claude,
    runtime: { runtimeId: "runtime-responder", sessionId: SESSION, role: "responder", harness: "claude" },
    mandate: VALID_MANDATE,
    mcpEndpoint: MCP_ENDPOINT,
    a2aConfig: a2aConfig("responder"),
  });
  assert.equal(claudeCalls[0].options.env.CLAUDE_CODE_USE_BEDROCK, "1");
  assert.equal(claudeCalls[0].options.env.ANTHROPIC_MODEL, "us.anthropic.claude-sonnet-4-6");
  assert.equal(claudeCalls[0].options.env.AWS_REGION, "us-west-2");
  assert.equal(claudeCalls[0].options.env.AWS_ACCESS_KEY_ID, "ASIAEXAMPLE");
  assert.equal(claudeCalls[0].options.env.AWS_SECRET_ACCESS_KEY, "aws-secret-value");
  assert.equal(claudeCalls[0].options.env.AWS_SESSION_TOKEN, "aws-session-token");
  assert.equal(claudeCalls[0].options.env.ANTHROPIC_API_KEY, undefined);
  assert.equal(claudeCalls[0].options.env.CODEX_API_KEY, undefined);
  assert.equal(claudeCalls.find((call) => Array.isArray(call) && call[0] === "setSessionConfigOption"), undefined);
  await claudeTransport.terminate({ sessionId: SESSION });
  const claudeEvidence = await claudeTransport.collectEvidence({ sessionId: SESSION });
  assert.doesNotMatch(JSON.stringify(claudeEvidence), /wrong-role|forbidden|us\.anthropic/);
});

test("Codex ACP launch fails closed when the required model pin is absent", async () => {
  const calls = [];
  const action = retainedAction({ role: "initiator", commandSha256: DIGEST });
  assert.throws(
    () => createAcpProcessTransport({
      harness: "codex",
      pin: ACP_VERSION_PINS.codex,
      spawn: acpFixtureSpawn({ calls, helperAction: action }),
      workspace: "/workspace/initiator",
      home: "/workspace/initiator/home",
      env: { PATH: "/app/node_modules/.bin:/usr/local/bin:/usr/bin:/bin", CODEX_API_KEY: "codex-secret-value" },
      actionRecorder: actionRecorderFor([action], calls),
      trustedAdapterPublicKeys: [action.adapterPublicKey],
    }),
    /ACP process transport validation failed safely/,
  );
  assert.equal(calls.length, 0);
});

test("Claude Bedrock auth rejects mixed mechanisms and cross-role provider variables", () => {
  const base = {
    harness: "claude",
    pin: ACP_VERSION_PINS.claude,
    spawn: fakeSpawn([]),
    workspace: "/workspace/responder",
    home: "/workspace/responder/home",
    trustedAdapterPublicKeys: [retainedAction({ role: "responder" }).adapterPublicKey],
  };
  for (const env of [
    {
      CLAUDE_CODE_USE_BEDROCK: "1",
      ANTHROPIC_MODEL: "us.anthropic.claude-sonnet-4-6",
      AWS_REGION: "us-west-2",
      AWS_ACCESS_KEY_ID: "ASIAEXAMPLE",
      AWS_SECRET_ACCESS_KEY: "secret",
      AWS_CONTAINER_CREDENTIALS_RELATIVE_URI: "/v2/credentials/responder",
    },
    {
      CLAUDE_CODE_USE_BEDROCK: "1",
      ANTHROPIC_MODEL: "us.anthropic.claude-sonnet-4-6",
      AWS_REGION: "us-west-2",
      AWS_ACCESS_KEY_ID: "ASIAEXAMPLE",
      AWS_SECRET_ACCESS_KEY: "secret",
      CODEX_API_KEY: "wrong-role",
    },
    {
      CLAUDE_CODE_USE_BEDROCK: "1",
      ANTHROPIC_MODEL: "us.anthropic.claude-sonnet-4-6",
      AWS_REGION: "us-west-2",
      AWS_ACCESS_KEY_ID: "ASIAEXAMPLE",
    },
  ]) {
    assert.throws(() => createAcpProcessTransport({ ...base, env }), /ACP process transport validation failed safely/);
  }
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
      assert.equal(acpProcessTransportFailureStage(error), null);
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
  assert.throws(() => createAcpProcessTransport({
    harness: "codex",
    pin: ACP_VERSION_PINS.codex,
    spawn: fakeSpawn([]),
    workspace: "/workspace/initiator",
    home: "/workspace/initiator/home",
    env: {},
    sessionEvidence: { terminalStatus: "completed" },
    trustedAdapterPublicKeys: [action.adapterPublicKey],
  }));
  const hostileActions = new Proxy([], {
    get() {
      traps += 1;
      throw new Error("secret-canary /Users/alice/secret");
    },
    ownKeys() {
      traps += 1;
      return [];
    },
  });
  assert.throws(
    () => createAcpProcessTransport({
      harness: "codex",
      pin: ACP_VERSION_PINS.codex,
      spawn: fakeSpawn([]),
      workspace: "/workspace/initiator",
      home: "/workspace/initiator/home",
      env: {},
      retainedActions: hostileActions,
      trustedAdapterPublicKeys: [action.adapterPublicKey],
    }),
    (error) => {
      assert.match(error.message, /ACP process transport validation failed safely/);
      assert.doesNotMatch(error.message, /secret-canary|\/Users\/alice\/secret/);
      return true;
    },
  );
  const hostileKeys = [];
  Object.defineProperty(hostileKeys, "0", {
    enumerable: true,
    get() {
      throw new Error("secret-canary /Users/alice/secret");
    },
  });
  assert.throws(
    () => createAcpProcessTransport({
      harness: "codex",
      pin: ACP_VERSION_PINS.codex,
      spawn: fakeSpawn([]),
      workspace: "/workspace/initiator",
      home: "/workspace/initiator/home",
      env: {},
      retainedActions: [],
      trustedAdapterPublicKeys: hostileKeys,
    }),
    (error) => {
      assert.match(error.message, /ACP process transport validation failed safely/);
      assert.doesNotMatch(error.message, /secret-canary|\/Users\/alice\/secret/);
      return true;
    },
  );
  assert.equal(traps, 0);
  const hostileAction = retainedAction({ role: "initiator", commandSha256: DIGEST });
  Object.defineProperty(hostileAction, "actionId", {
    enumerable: true,
    get() {
      throw new Error("secret-canary /Users/alice/secret");
    },
  });
  assert.throws(
    () => createAcpProcessTransport({
      harness: "codex",
      pin: ACP_VERSION_PINS.codex,
      spawn: fakeSpawn([]),
      workspace: "/workspace/initiator",
      home: "/workspace/initiator/home",
      env: {},
      retainedActions: [hostileAction],
      trustedAdapterPublicKeys: [action.adapterPublicKey],
    }),
    (error) => {
      assert.match(error.message, /ACP process transport validation failed safely/);
      assert.doesNotMatch(error.message, /secret-canary|\/Users\/alice\/secret/);
      return true;
    },
  );
  const calls = [];
  const transport = createAcpProcessTransport({
    harness: "codex",
    pin: ACP_VERSION_PINS.codex,
    spawn: acpFixtureSpawn({ calls, helperAction: action }),
    workspace: "/workspace/initiator",
    home: "/workspace/initiator/home",
    nowMs: () => 1786337001000,
    actionRecorder: actionRecorderFor([action], calls),
    env: { CLOCKCHAIN_MCP_BEARER: "token" },
    trustedAdapterPublicKeys: [action.adapterPublicKey],
  });
  await transport.launch({
    acp: ACP_VERSION_PINS.codex,
    runtime: { runtimeId: "runtime-initiator", sessionId: SESSION, role: "initiator", harness: "codex" },
    mandate: VALID_MANDATE,
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
  const responderCalls = [];
  const transport = createAcpProcessTransport({
    harness: "claude",
    pin: ACP_VERSION_PINS.claude,
    spawn: acpFixtureSpawn({ calls: responderCalls, helperAction: action }),
    workspace: "/workspace/responder",
    home: "/workspace/responder/home",
    nowMs: () => 1786337001000,
    actionRecorder: actionRecorderFor([action]),
    env: { CLOCKCHAIN_MCP_BEARER: "token" },
    trustedAdapterPublicKeys: [action.adapterPublicKey],
  });
  await assert.rejects(() => transport.launch({
    acp: ACP_VERSION_PINS.codex,
    runtime: { runtimeId: "runtime-responder", sessionId: SESSION, role: "responder", harness: "claude" },
    mandate: VALID_MANDATE,
    mcpEndpoint: MCP_ENDPOINT,
    a2aConfig: a2aConfig("responder"),
  }));
  await assert.rejects(() => transport.launch({
    acp: ACP_VERSION_PINS.claude,
    runtime: { runtimeId: "runtime-responder", sessionId: SESSION, role: "responder", harness: "claude" },
    mandate: { ...VALID_MANDATE, transcript: "private" },
    mcpEndpoint: MCP_ENDPOINT,
    a2aConfig: a2aConfig("responder"),
  }));
  await assert.rejects(() => transport.launch({
    acp: ACP_VERSION_PINS.claude,
    runtime: { runtimeId: "runtime-responder", sessionId: SESSION, role: "responder", harness: "claude" },
    mandate: VALID_MANDATE,
    mcpEndpoint: "https://mcp.clockchain.network/mcp",
    a2aConfig: a2aConfig("responder"),
  }));
  await transport.launch({
    acp: ACP_VERSION_PINS.claude,
    runtime: { runtimeId: "runtime-responder", sessionId: SESSION, role: "responder", harness: "claude" },
    mandate: VALID_MANDATE,
    mcpEndpoint: MCP_ENDPOINT,
    a2aConfig: { ...a2aConfig("responder"), invitationPath: "/workspace/responder/responder-invitation.txt" },
  });
  const responderPrompt = responderCalls.find((entry) => entry[0] === "prompt")[1].prompt[0].text;
  assert.match(responderPrompt, /read exactly one UTF-8 invitation from \/workspace\/responder\/responder-invitation\.txt/);
  assert.match(responderPrompt, /agent_handshake_accept_invitation/);
  assert.match(responderPrompt, /do not print/i);
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
    actionRecorder: actionRecorderFor([action], calls),
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
    mandate: VALID_MANDATE,
    mcpEndpoint: MCP_ENDPOINT,
    a2aConfig: a2aConfig("initiator"),
  });

  assert.equal(launched.sessionId, SESSION);
  assert.deepEqual(calls.filter(Array.isArray).map((entry) => entry[0]), ["initialize", "newSession", "setSessionConfigOption", "prompt", "record", "permission"]);
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
  assert.match(prompt, /"erc8004":"required_existing_or_fresh"/);
  assert.match(prompt, /"chainId":"eip155:11155111"/);
  assert.match(prompt, /"registryAddress":"0x8004a818bfb912233c491871b3d84c89a494bd9e"/);
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

test("ACP process transport binds setup updates to the session id returned by newSession", async () => {
  const action = retainedAction({ role: "initiator", requestDigest: "d".repeat(64), commandSha256: DIGEST });
  const calls = [];
  const transport = createAcpProcessTransport({
    harness: "codex",
    pin: ACP_VERSION_PINS.codex,
    spawn: acpFixtureSpawn({
      calls,
      newSessionUpdates: [{ sessionUpdate: "available_commands_update", availableCommands: [] }],
      skipPermission: true,
    }),
    workspace: "/workspace/initiator",
    home: "/workspace/initiator/home",
    nowMs: () => 1786337001000,
    actionRecorder: actionRecorderFor([action], calls),
    env: {},
    retainedActions: [],
    trustedAdapterPublicKeys: [action.adapterPublicKey],
  });
  await transport.launch({
    acp: ACP_VERSION_PINS.codex,
    runtime: { runtimeId: "runtime-initiator", sessionId: SESSION, role: "initiator", harness: "codex" },
    mandate: VALID_MANDATE,
    mcpEndpoint: MCP_ENDPOINT,
    a2aConfig: a2aConfig("initiator"),
  });
  assert.equal((await transport.streamEvents({ sessionId: SESSION })).some((event) => event.type === "acp.available_commands_update"), true);

  const mismatch = createAcpProcessTransport({
    harness: "codex",
    pin: ACP_VERSION_PINS.codex,
    spawn: acpFixtureSpawn({
      calls: [],
      newSessionUpdates: [{ sessionUpdate: "available_commands_update", availableCommands: [] }],
      newSessionUpdateSessionId: "acp-provisional",
      newSessionId: "acp-returned",
      skipPermission: true,
    }),
    workspace: "/workspace/initiator",
    home: "/workspace/initiator/home",
    env: {},
    retainedActions: [],
    trustedAdapterPublicKeys: [action.adapterPublicKey],
  });
  await assert.rejects(() => mismatch.launch({
    acp: ACP_VERSION_PINS.codex,
    runtime: { runtimeId: "runtime-initiator", sessionId: SESSION, role: "initiator", harness: "codex" },
    mandate: VALID_MANDATE,
    mcpEndpoint: MCP_ENDPOINT,
    a2aConfig: a2aConfig("initiator"),
  }), (error) => {
    assert.equal(acpProcessTransportFailureStage(error), "session");
    return true;
  });
});

test("ACP process transport reports an active-session update mismatch without retaining either id", async () => {
  const action = retainedAction({ role: "initiator", requestDigest: "d".repeat(64), commandSha256: DIGEST });
  const transport = createAcpProcessTransport({
    harness: "codex",
    pin: ACP_VERSION_PINS.codex,
    spawn: acpFixtureSpawn({
      calls: [],
      promptUpdateSessionId: "acp-foreign-session",
      sessionUpdates: [{ sessionUpdate: "available_commands_update", availableCommands: [] }],
      skipPermission: true,
    }),
    workspace: "/workspace/initiator",
    home: "/workspace/initiator/home",
    env: {},
    retainedActions: [],
    trustedAdapterPublicKeys: [action.adapterPublicKey],
  });
  await assert.rejects(() => transport.launch({
    acp: ACP_VERSION_PINS.codex,
    runtime: { runtimeId: "runtime-initiator", sessionId: SESSION, role: "initiator", harness: "codex" },
    mandate: VALID_MANDATE,
    mcpEndpoint: MCP_ENDPOINT,
    a2aConfig: a2aConfig("initiator"),
  }), (error) => {
    assert.equal(acpProcessTransportFailureStage(error), "completion-protocol-envelope-active-session");
    assert.doesNotMatch(error.message, /acp-foreign-session/);
    return true;
  });
});

test("ACP process transport rejects stale or malformed production v2 mandates before prompt serialization", async () => {
  const action = retainedAction({ role: "initiator", commandSha256: DIGEST });
  const invalidMandates = [
    { ...VALID_MANDATE, validForMinutes: "45" },
    { ...VALID_MANDATE, validForSeconds: "91" },
    { ...VALID_MANDATE, validForSeconds: "0" },
    { ...VALID_MANDATE, identityPolicy: "fresh-erc8004" },
    { ...VALID_MANDATE, identityPolicy: { ...VALID_MANDATE.identityPolicy, erc8004: "fresh-erc8004" } },
    { ...VALID_MANDATE, identityPolicy: { ...VALID_MANDATE.identityPolicy, chainId: "eip155:1" } },
    { ...VALID_MANDATE, identityPolicy: { erc8004: "not_required", chainId: "eip155:11155111", registryAddress: null } },
    { ...VALID_MANDATE, identityPolicy: { erc8004: "not_required", chainId: null, registryAddress: "0x8004a818bfb912233c491871b3d84c89a494bd9e" } },
  ];
  for (const mandate of invalidMandates) {
    const calls = [];
    const transport = createAcpProcessTransport({
      harness: "codex",
      pin: ACP_VERSION_PINS.codex,
      spawn: fakeSpawn(calls),
      workspace: "/workspace/initiator",
      home: "/workspace/initiator/home",
      env: {},
      trustedAdapterPublicKeys: [action.adapterPublicKey],
    });
    await assert.rejects(() => transport.launch({
      acp: ACP_VERSION_PINS.codex,
      runtime: { runtimeId: "runtime-initiator", sessionId: SESSION, role: "initiator", harness: "codex" },
      mandate,
      mcpEndpoint: MCP_ENDPOINT,
      a2aConfig: a2aConfig("initiator"),
    }));
    assert.equal(calls.length, 0);
  }
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
    actionRecorder: actionRecorderFor([action]),
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
    actionRecorder: actionRecorderFor([action], calls),
    env: {},
    retainedActions: [],
    trustedAdapterPublicKeys: [action.adapterPublicKey],
  });
  await transport.launch({
    acp: ACP_VERSION_PINS.codex,
    runtime: { runtimeId: "runtime-initiator", sessionId: SESSION, role: "initiator", harness: "codex" },
    mandate: VALID_MANDATE,
    mcpEndpoint: MCP_ENDPOINT,
    a2aConfig: a2aConfig("initiator"),
  });
  await transport.terminate({ sessionId: SESSION, reason: "test-complete" });
  const events = await transport.streamEvents({ sessionId: SESSION });
  assert.ok(events.some((event) => event.type === "acp.retained_action.registered"));
  assert.doesNotMatch(JSON.stringify(events), /role-access-secret|invite-secret|helperStep|command|\/Users\/alice\/secret/);
});

test("ACP process transport forwards only authoritative completed Codex and Claude MCP results to the party bridge", async () => {
  const action = retainedAction({ role: "initiator", requestDigest: "d".repeat(64), commandSha256: DIGEST });
  const cases = [
    {
      harness: "codex",
      update: {
        sessionUpdate: "tool_call_update",
        toolCallId: "codex-mcp",
        status: "completed",
        rawInput: { server: "clockchain-handshake", tool: "agent_handshake_wait", arguments: {} },
        rawOutput: { result: { structuredContent: { status: "waiting" } }, error: null },
      },
      expectedResult: { structuredContent: { status: "waiting" } },
    },
    {
      harness: "claude",
      update: {
        sessionUpdate: "tool_call_update",
        toolCallId: "claude-mcp",
        status: "completed",
        rawOutput: [{ type: "text", text: JSON.stringify({ status: "waiting" }) }],
        _meta: { claudeCode: { toolName: "mcp__clockchain-handshake__agent_handshake_wait" } },
      },
      expectedResult: [{ type: "text", text: JSON.stringify({ status: "waiting" }) }],
    },
  ];
  for (const item of cases) {
    const calls = [];
    const transport = createAcpProcessTransport({
      harness: item.harness,
      pin: ACP_VERSION_PINS[item.harness],
      spawn: acpFixtureSpawn({ calls, sessionUpdates: [item.update] }),
      workspace: `/workspace/${item.harness}`,
      home: `/workspace/${item.harness}/home`,
      nowMs: () => 1786337001000,
      env: {},
      partyBridge: partyBridgeFor(calls),
      retainedActions: [action],
      trustedAdapterPublicKeys: [action.adapterPublicKey],
    });
    await transport.launch({
      acp: ACP_VERSION_PINS[item.harness],
      runtime: { runtimeId: `runtime-${item.harness}`, sessionId: SESSION, role: "initiator", harness: item.harness },
      mandate: VALID_MANDATE,
      mcpEndpoint: MCP_ENDPOINT,
      a2aConfig: a2aConfig("initiator"),
    });
    const bridgeCalls = calls.filter((entry) => Array.isArray(entry) && entry[0] === "partyBridge");
    assert.deepEqual(bridgeCalls, [["partyBridge", {
      toolName: "agent_handshake_wait",
      result: item.expectedResult,
    }]]);
    const events = await transport.streamEvents({ sessionId: SESSION });
    assert.doesNotMatch(JSON.stringify(events), /structuredContent|rawOutput|partyBridge|secret-canary/);
  }
});

test("ACP process transport never forwards spoofed titles and fails closed when the party bridge rejects", async () => {
  const action = retainedAction({ role: "initiator", requestDigest: "d".repeat(64), commandSha256: DIGEST });
  const spoofCalls = [];
  const spoofTransport = createAcpProcessTransport({
    harness: "codex",
    pin: ACP_VERSION_PINS.codex,
    spawn: acpFixtureSpawn({
      calls: spoofCalls,
      sessionUpdates: [{
        sessionUpdate: "tool_call_update",
        toolCallId: "spoof",
        title: "mcp.clockchain-handshake.agent_handshake_wait",
        name: "Bash",
        status: "completed",
        rawInput: { command: "echo spoof" },
        rawOutput: { result: { structuredContent: { status: "waiting" } }, error: null },
      }],
    }),
    workspace: "/workspace/spoof",
    home: "/workspace/spoof/home",
    nowMs: () => 1786337001000,
    env: {},
    partyBridge: partyBridgeFor(spoofCalls),
    retainedActions: [action],
    trustedAdapterPublicKeys: [action.adapterPublicKey],
  });
  await assert.rejects(() => spoofTransport.launch({
    acp: ACP_VERSION_PINS.codex,
    runtime: { runtimeId: "runtime-spoof", sessionId: SESSION, role: "initiator", harness: "codex" },
    mandate: VALID_MANDATE,
    mcpEndpoint: MCP_ENDPOINT,
    a2aConfig: a2aConfig("initiator"),
  }), /ACP process transport validation failed safely/);
  assert.equal(spoofCalls.some((entry) => Array.isArray(entry) && entry[0] === "partyBridge"), false);

  const rejectCalls = [];
  const rejectTransport = createAcpProcessTransport({
    harness: "codex",
    pin: ACP_VERSION_PINS.codex,
    spawn: acpFixtureSpawn({
      calls: rejectCalls,
      sessionUpdates: [{
        sessionUpdate: "tool_call_update",
        toolCallId: "real",
        status: "completed",
        rawInput: { server: "clockchain-handshake", tool: "agent_handshake_wait", arguments: {} },
        rawOutput: { result: { structuredContent: { status: "waiting" } }, error: null },
      }],
    }),
    workspace: "/workspace/reject",
    home: "/workspace/reject/home",
    nowMs: () => 1786337001000,
    env: {},
    partyBridge: partyBridgeFor(rejectCalls, { reject: true }),
    retainedActions: [action],
    trustedAdapterPublicKeys: [action.adapterPublicKey],
  });
  await assert.rejects(() => rejectTransport.launch({
    acp: ACP_VERSION_PINS.codex,
    runtime: { runtimeId: "runtime-reject", sessionId: SESSION, role: "initiator", harness: "codex" },
    mandate: VALID_MANDATE,
    mcpEndpoint: MCP_ENDPOINT,
    a2aConfig: a2aConfig("initiator"),
  }), /ACP process transport validation failed safely/);
});

test("ACP process transport registers retained actions from installed Codex ACP MCP result shape", async () => {
  const action = retainedAction({ role: "initiator", requestDigest: "d".repeat(64), commandSha256: DIGEST });
  const calls = [];
  const transport = createAcpProcessTransport({
    harness: "codex",
    pin: ACP_VERSION_PINS.codex,
    spawn: acpFixtureSpawn({
      calls,
      sessionUpdates: [{
        sessionUpdate: "tool_call_update",
        toolCallId: "mcp-call-1",
        status: "completed",
        rawInput: {
          server: "clockchain-handshake",
          tool: "agent_handshake_next",
          arguments: { reference: "NS-1847" },
        },
        rawOutput: {
          result: {
            structuredContent: {
              helperStep: helperStepForAction(action),
            },
          },
          error: null,
        },
      }],
    }),
    workspace: "/workspace/initiator",
    home: "/workspace/initiator/home",
    nowMs: () => 1786337001000,
    actionRecorder: actionRecorderFor([action], calls),
    env: {},
    retainedActions: [],
    trustedAdapterPublicKeys: [action.adapterPublicKey],
  });
  await transport.launch({
    acp: ACP_VERSION_PINS.codex,
    runtime: { runtimeId: "runtime-initiator", sessionId: SESSION, role: "initiator", harness: "codex" },
    mandate: VALID_MANDATE,
    mcpEndpoint: MCP_ENDPOINT,
    a2aConfig: a2aConfig("initiator"),
  });
  assert.equal((await transport.executeRetainedAction({ sessionId: SESSION, role: "initiator", actionId: "action-1" })).executed, true);
});

test("ACP keeps controller correlation separate from the bridge-bound protocol session", async () => {
  const action = retainedAction({ role: "initiator", requestDigest: "d".repeat(64), commandSha256: DIGEST });
  const calls = [];
  const transport = createAcpProcessTransport({
    harness: "codex",
    pin: ACP_VERSION_PINS.codex,
    spawn: acpFixtureSpawn({ calls, helperAction: action, permissionCommand: `clockchain-agent-authorize ${action.commandSha256}` }),
    workspace: "/workspace/controller-run",
    home: "/workspace/controller-run/home",
    nowMs: () => 1786337001000,
    actionRecorder: actionRecorderFor([action], calls),
    env: {},
    partyBridge: partyBridgeFor(calls),
    retainedActions: [],
    trustedAdapterPublicKeys: [action.adapterPublicKey],
  });
  const launched = await transport.launch({
    acp: ACP_VERSION_PINS.codex,
    runtime: { runtimeId: "runtime-controller", sessionId: OTHER_SESSION, role: "initiator", harness: "codex" },
    mandate: VALID_MANDATE,
    mcpEndpoint: MCP_ENDPOINT,
    a2aConfig: a2aConfig("initiator"),
  });
  assert.equal(launched.sessionId, OTHER_SESSION);
  assert.equal((await transport.executeRetainedAction({ sessionId: OTHER_SESSION, role: "initiator", actionId: action.actionId })).executed, true);
  const events = await transport.streamEvents({ sessionId: OTHER_SESSION });
  assert.ok(events.every((event) => event.sessionId === OTHER_SESSION));
  assert.doesNotMatch(JSON.stringify(events), new RegExp(SESSION));
});

test("ACP process transport records production-length helper shell commands without public leakage", async () => {
  const action = retainedAction({ role: "initiator", requestDigest: "d".repeat(64), commandSha256: DIGEST, commandLength: 4247 });
  const longShellCommand = `node ${"x".repeat(4242)}`;
  assert.equal(Buffer.byteLength(longShellCommand), 4247);
  const calls = [];
  const transport = createAcpProcessTransport({
    harness: "codex",
    pin: ACP_VERSION_PINS.codex,
    spawn: acpFixtureSpawn({
      calls,
      sessionUpdates: [{
        sessionUpdate: "tool_call_update",
        toolCallId: "mcp-call-long",
        status: "completed",
        rawInput: {
          server: "clockchain-handshake",
          tool: "agent_handshake_next",
          arguments: { reference: "NS-1847" },
        },
        rawOutput: {
          result: {
            content: [{ type: "text", text: JSON.stringify({ localAction: { helperStep: helperStepForAction(action, { shellCommand: longShellCommand }) } }) }],
          },
          error: null,
        },
      }],
    }),
    workspace: "/workspace/initiator",
    home: "/workspace/initiator/home",
    nowMs: () => 1786337001000,
    actionRecorder: actionRecorderFor([action], calls),
    env: {},
    retainedActions: [],
    trustedAdapterPublicKeys: [action.adapterPublicKey],
  });
  await transport.launch({
    acp: ACP_VERSION_PINS.codex,
    runtime: { runtimeId: "runtime-initiator", sessionId: SESSION, role: "initiator", harness: "codex" },
    mandate: VALID_MANDATE,
    mcpEndpoint: MCP_ENDPOINT,
    a2aConfig: a2aConfig("initiator"),
  });
  const events = await transport.streamEvents({ sessionId: SESSION });
  assert.doesNotMatch(JSON.stringify(events), new RegExp(longShellCommand.slice(0, 80)));
  assert.equal((await transport.executeRetainedAction({ sessionId: SESSION, role: "initiator", actionId: "action-1" })).executed, true);
});

test("ACP process transport treats helperless completed Clockchain MCP calls as benign", async () => {
  const action = retainedAction({ role: "initiator", requestDigest: "d".repeat(64), commandSha256: DIGEST });
  const transport = createAcpProcessTransport({
    harness: "codex",
    pin: ACP_VERSION_PINS.codex,
    spawn: acpFixtureSpawn({
      calls: [],
      sessionUpdates: [{
        sessionUpdate: "tool_call_update",
        toolCallId: "mcp-call-status",
        status: "completed",
        rawInput: {
          server: "clockchain-handshake",
          tool: "agent_handshake_wait",
          arguments: { reference: "NS-1847" },
        },
        rawOutput: {
          result: {
            structuredContent: { status: "waiting" },
          },
          error: null,
        },
      }],
    }),
    workspace: "/workspace/initiator",
    home: "/workspace/initiator/home",
    nowMs: () => 1786337001000,
    env: {},
    retainedActions: [action],
    trustedAdapterPublicKeys: [action.adapterPublicKey],
  });
  await transport.launch({
    acp: ACP_VERSION_PINS.codex,
    runtime: { runtimeId: "runtime-initiator", sessionId: SESSION, role: "initiator", harness: "codex" },
    mandate: VALID_MANDATE,
    mcpEndpoint: MCP_ENDPOINT,
    a2aConfig: a2aConfig("initiator"),
  });
  assert.equal((await transport.executeRetainedAction({ sessionId: SESSION, role: "initiator", actionId: "action-1" })).executed, true);
});

test("ACP process transport ignores unrelated tool updates with spoofed bare Clockchain titles", async () => {
  const action = retainedAction({ role: "initiator", requestDigest: "d".repeat(64), commandSha256: DIGEST });
  const calls = [];
  const transport = createAcpProcessTransport({
    harness: "codex",
    pin: ACP_VERSION_PINS.codex,
    spawn: acpFixtureSpawn({
      calls,
      sessionUpdates: [{
        sessionUpdate: "tool_call_update",
        toolCallId: "bash-spoof",
        title: "agent_handshake_next",
        name: "Bash",
        kind: "execute",
        status: "completed",
        rawInput: { command: "echo not-a-clockchain-tool" },
        rawOutput: {
          result: {
            structuredContent: { helperStep: helperStepForAction(action) },
          },
          error: null,
        },
      }],
    }),
    workspace: "/workspace/initiator",
    home: "/workspace/initiator/home",
    nowMs: () => 1786337001000,
    actionRecorder: Object.freeze({
      record() {
        throw new Error("spoofed title reached recorder secret-canary /Users/alice/secret");
      },
    }),
    env: {},
    retainedActions: [action],
    trustedAdapterPublicKeys: [action.adapterPublicKey],
  });
  await transport.launch({
    acp: ACP_VERSION_PINS.codex,
    runtime: { runtimeId: "runtime-initiator", sessionId: SESSION, role: "initiator", harness: "codex" },
    mandate: VALID_MANDATE,
    mcpEndpoint: MCP_ENDPOINT,
    a2aConfig: a2aConfig("initiator"),
  });
  const events = await transport.streamEvents({ sessionId: SESSION });
  assert.equal(calls.some((entry) => entry[0] === "record"), false);
  assert.doesNotMatch(JSON.stringify(events), /spoofed title|secret-canary|helperStep|command|\/Users\/alice/);
  assert.equal((await transport.executeRetainedAction({ sessionId: SESSION, role: "initiator", actionId: "action-1" })).executed, true);
});

test("ACP process transport ignores unrelated tool updates with spoofed fully qualified Clockchain titles", async () => {
  const allowedAction = retainedAction({ role: "initiator", actionId: "allowed-action", commandSha256: DIGEST });
  const spoofedAction = retainedAction({ role: "initiator", actionId: "spoofed-action", requestDigest: "d".repeat(64), commandSha256: "e".repeat(64) });
  const calls = [];
  const transport = createAcpProcessTransport({
    harness: "codex",
    pin: ACP_VERSION_PINS.codex,
    spawn: acpFixtureSpawn({
      calls,
      sessionUpdates: [{
        sessionUpdate: "tool_call_update",
        toolCallId: "bash-spoof-qualified",
        title: "mcp.clockchain-handshake.agent_handshake_next",
        name: "Bash",
        kind: "execute",
        status: "completed",
        rawInput: { command: "echo not mcp" },
        rawOutput: {
          result: {
            structuredContent: { helperStep: helperStepForAction(spoofedAction) },
          },
          error: null,
        },
      }],
    }),
    workspace: "/workspace/initiator",
    home: "/workspace/initiator/home",
    nowMs: () => 1786337001000,
    actionRecorder: actionRecorderFor([spoofedAction], calls),
    env: {},
    retainedActions: [allowedAction],
    trustedAdapterPublicKeys: [allowedAction.adapterPublicKey, spoofedAction.adapterPublicKey],
  });
  await transport.launch({
    acp: ACP_VERSION_PINS.codex,
    runtime: { runtimeId: "runtime-initiator", sessionId: SESSION, role: "initiator", harness: "codex" },
    mandate: VALID_MANDATE,
    mcpEndpoint: MCP_ENDPOINT,
    a2aConfig: a2aConfig("initiator"),
  });
  const events = await transport.streamEvents({ sessionId: SESSION });
  assert.equal(calls.some((entry) => entry[0] === "record"), false);
  assert.doesNotMatch(JSON.stringify(events), /helperStep|command|echo not mcp/);
  await assert.rejects(
    () => transport.executeRetainedAction({ sessionId: SESSION, role: "initiator", actionId: "spoofed-action" }),
    /ACP process transport validation failed safely/,
  );
});

test("ACP process transport registers retained actions from installed Claude ACP tool result sequence", async () => {
  const action = retainedAction({ role: "responder", requestDigest: "d".repeat(64), commandSha256: DIGEST });
  const calls = [];
  const transport = createAcpProcessTransport({
    harness: "claude",
    pin: ACP_VERSION_PINS.claude,
    spawn: acpFixtureSpawn({
      calls,
      sessionUpdates: [
        {
          sessionUpdate: "tool_call",
          toolCallId: "toolu_01",
          title: "agent_handshake_next",
          kind: "other",
          status: "pending",
          rawInput: { reference: "NS-1847" },
          _meta: { claudeCode: { toolName: "mcp__clockchain-handshake__agent_handshake_next" } },
        },
        {
          sessionUpdate: "tool_call_update",
          toolCallId: "toolu_01",
          status: "completed",
          rawOutput: [{
            type: "text",
            text: JSON.stringify({ helperStep: helperStepForAction(action) }),
          }],
          _meta: { claudeCode: { toolName: "mcp__clockchain-handshake__agent_handshake_next" } },
        },
      ],
    }),
    workspace: "/workspace/responder",
    home: "/workspace/responder/home",
    nowMs: () => 1786337001000,
    actionRecorder: actionRecorderFor([action], calls),
    env: {},
    retainedActions: [],
    trustedAdapterPublicKeys: [action.adapterPublicKey],
  });
  await transport.launch({
    acp: ACP_VERSION_PINS.claude,
    runtime: { runtimeId: "runtime-responder", sessionId: SESSION, role: "responder", harness: "claude" },
    mandate: VALID_MANDATE,
    mcpEndpoint: MCP_ENDPOINT,
    a2aConfig: a2aConfig("responder"),
  });
  assert.equal((await transport.executeRetainedAction({ sessionId: SESSION, role: "responder", actionId: "action-1" })).executed, true);
});

test("ACP process transport fails closed on ambiguous or malformed MCP helper outputs", async () => {
  const action = retainedAction({ role: "initiator", requestDigest: "d".repeat(64), commandSha256: DIGEST });
  const otherAction = retainedAction({ role: "initiator", actionId: "action-2", requestDigest: "e".repeat(64), commandSha256: "e".repeat(64) });
  const cases = [
    {
      expectedProtocolStage: "retained",
      rawOutput: {
        result: {
          content: [
            { type: "text", text: JSON.stringify({ helperStep: helperStepForAction(action) }) },
            { type: "text", text: JSON.stringify({ helperStep: helperStepForAction(otherAction) }) },
          ],
        },
        error: null,
      },
    },
    {
      expectedProtocolStage: "retained",
      rawOutput: {
        result: { content: [{ type: "image", text: JSON.stringify({ helperStep: helperStepForAction(action) }) }] },
        error: null,
      },
    },
    {
      expectedProtocolStage: "retained",
      rawOutput: {
        result: { content: [{ type: "text", text: "{not-json" }] },
        error: null,
      },
    },
    {
      expectedProtocolStage: "tool-result",
      rawOutput: {
        result: { structuredContent: { helperStep: helperStepForAction(action) } },
        error: { message: "tool failed secret-canary /Users/alice/secret" },
      },
    },
  ];
  for (const item of cases) {
    const calls = [];
    const transport = createAcpProcessTransport({
      harness: "codex",
      pin: ACP_VERSION_PINS.codex,
      spawn: acpFixtureSpawn({
        calls,
        sessionUpdates: [{
          sessionUpdate: "tool_call_update",
          toolCallId: "mcp-call-bad",
          status: "completed",
          rawInput: {
            server: "clockchain-handshake",
            tool: "agent_handshake_next",
            arguments: { reference: "NS-1847" },
          },
          rawOutput: item.rawOutput,
        }],
      }),
      workspace: "/workspace/initiator",
      home: "/workspace/initiator/home",
      nowMs: () => 1786337001000,
      actionRecorder: actionRecorderFor([action, otherAction], calls),
      env: {},
      retainedActions: [],
      trustedAdapterPublicKeys: [action.adapterPublicKey, otherAction.adapterPublicKey],
    });
    await assert.rejects(() => transport.launch({
      acp: ACP_VERSION_PINS.codex,
      runtime: { runtimeId: "runtime-initiator", sessionId: SESSION, role: "initiator", harness: "codex" },
      mandate: VALID_MANDATE,
      mcpEndpoint: MCP_ENDPOINT,
      a2aConfig: a2aConfig("initiator"),
    }), (error) => {
      assert.equal(acpProcessTransportFailureStage(error), `completion-protocol-${item.expectedProtocolStage}`);
      return true;
    });
    const events = await transport.streamEvents({ sessionId: SESSION });
    assert.doesNotMatch(JSON.stringify(events), /secret-canary|\/Users\/alice\/secret|helperStep|command|rawOutput/);
  }
});

test("ACP process transport proves teardown from close events without a closed promise", async () => {
  const action = retainedAction({ role: "initiator", requestDigest: "d".repeat(64), commandSha256: DIGEST });
  const calls = [];
  const closeState = { killed: false, closed: false };
  const transport = createAcpProcessTransport({
    harness: "codex",
    pin: ACP_VERSION_PINS.codex,
    spawn: acpFixtureSpawn({ calls, closeState, helperAction: action, useCloseEvent: true }),
    workspace: "/workspace/initiator",
    home: "/workspace/initiator/home",
    nowMs: () => 1786337001000,
    actionRecorder: actionRecorderFor([action], calls),
    env: {},
    retainedActions: [],
    trustedAdapterPublicKeys: [action.adapterPublicKey],
  });
  await transport.launch({
    acp: ACP_VERSION_PINS.codex,
    runtime: { runtimeId: "runtime-initiator", sessionId: SESSION, role: "initiator", harness: "codex" },
    mandate: VALID_MANDATE,
    mcpEndpoint: MCP_ENDPOINT,
    a2aConfig: a2aConfig("initiator"),
  });
  await transport.terminate({ sessionId: SESSION, reason: "test-complete" });
  assert.equal(closeState.killed, true);
  assert.equal(closeState.closed, true);
  assert.equal(calls.some((entry) => entry.kill === "SIGTERM"), true);
  const evidence = await transport.collectEvidence({ sessionId: SESSION });
  assert.equal(evidence.teardown.completed, true);
});

test("ACP process transport escalates process teardown from SIGTERM to SIGKILL when close is delayed", async () => {
  const action = retainedAction({ role: "initiator", requestDigest: "d".repeat(64), commandSha256: DIGEST });
  const calls = [];
  const closeState = { killed: false, closed: false };
  const transport = createAcpProcessTransport({
    harness: "codex",
    pin: ACP_VERSION_PINS.codex,
    spawn: acpFixtureSpawn({ calls, closeState, helperAction: action, closeOnSignal: "SIGKILL", useCloseEvent: true }),
    workspace: "/workspace/initiator",
    home: "/workspace/initiator/home",
    nowMs: () => 1786337001000,
    actionRecorder: actionRecorderFor([action], calls),
    env: {},
    retainedActions: [],
    trustedAdapterPublicKeys: [action.adapterPublicKey],
  });
  await transport.launch({
    acp: ACP_VERSION_PINS.codex,
    runtime: { runtimeId: "runtime-initiator", sessionId: SESSION, role: "initiator", harness: "codex" },
    mandate: VALID_MANDATE,
    mcpEndpoint: MCP_ENDPOINT,
    a2aConfig: a2aConfig("initiator"),
  });
  await transport.terminate({ sessionId: SESSION, reason: "test-complete" });
  assert.deepEqual(calls.filter((entry) => entry.kill).map((entry) => entry.kill), ["SIGTERM", "SIGKILL"]);
  assert.equal(closeState.closed, true);
  const evidence = await transport.collectEvidence({ sessionId: SESSION });
  assert.equal(evidence.teardown.completed, true);
});

test("ACP process transport cleans up spawned child when ACP lifecycle fails", async () => {
  const action = retainedAction({ role: "initiator", requestDigest: "d".repeat(64), commandSha256: DIGEST });
  const calls = [];
  const closeState = { killed: false, closed: false };
  const transport = createAcpProcessTransport({
    harness: "codex",
    pin: ACP_VERSION_PINS.codex,
    spawn: acpFixtureSpawn({ calls, closeState, failInitialize: true, helperAction: action, useCloseEvent: true }),
    workspace: "/workspace/initiator",
    home: "/workspace/initiator/home",
    nowMs: () => 1786337001000,
    actionRecorder: actionRecorderFor([action], calls),
    env: {},
    retainedActions: [],
    trustedAdapterPublicKeys: [action.adapterPublicKey],
  });
  await assert.rejects(
    () => transport.launch({
      acp: ACP_VERSION_PINS.codex,
      runtime: { runtimeId: "runtime-initiator", sessionId: SESSION, role: "initiator", harness: "codex" },
      mandate: VALID_MANDATE,
      mcpEndpoint: MCP_ENDPOINT,
      a2aConfig: a2aConfig("initiator"),
    }),
    (error) => {
      assert.match(error.message, /ACP process transport validation failed safely/);
      assert.equal(acpProcessTransportFailureStage(error), "initialize");
      assert.doesNotMatch(error.message, /secret-canary|\/Users\/alice\/secret/);
      return true;
    },
  );
  assert.equal(closeState.killed, true);
  assert.equal(closeState.closed, true);
  assert.equal(calls.some((entry) => entry.kill === "SIGTERM"), true);
  await assert.rejects(() => transport.collectEvidence({ sessionId: SESSION }));
});

test("ACP process transport records fast child close before terminate is requested", async () => {
  const action = retainedAction({ role: "initiator", requestDigest: "d".repeat(64), commandSha256: DIGEST });
  const calls = [];
  const closeState = { killed: false, closed: false };
  const transport = createAcpProcessTransport({
    harness: "codex",
    pin: ACP_VERSION_PINS.codex,
    spawn: acpFixtureSpawn({ calls, closeState, fastClose: true, helperAction: action, useCloseEvent: true }),
    workspace: "/workspace/initiator",
    home: "/workspace/initiator/home",
    nowMs: () => 1786337001000,
    actionRecorder: actionRecorderFor([action], calls),
    env: {},
    retainedActions: [],
    trustedAdapterPublicKeys: [action.adapterPublicKey],
  });
  await transport.launch({
    acp: ACP_VERSION_PINS.codex,
    runtime: { runtimeId: "runtime-initiator", sessionId: SESSION, role: "initiator", harness: "codex" },
    mandate: VALID_MANDATE,
    mcpEndpoint: MCP_ENDPOINT,
    a2aConfig: a2aConfig("initiator"),
  });
  await transport.terminate({ sessionId: SESSION, reason: "test-complete" });
  assert.equal(closeState.closed, true);
  assert.equal(calls.some((entry) => entry.kill), false);
  const evidence = await transport.collectEvidence({ sessionId: SESSION });
  assert.equal(evidence.teardown.completed, true);
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
    actionRecorder: actionRecorderFor([action]),
    env: {},
    retainedActions: [],
    trustedAdapterPublicKeys: [action.adapterPublicKey],
  });
  await assert.rejects(() => badPermissionTransport.launch({
    acp: ACP_VERSION_PINS.codex,
    runtime: { runtimeId: "runtime-initiator", sessionId: SESSION, role: "initiator", harness: "codex" },
    mandate: VALID_MANDATE,
    mcpEndpoint: MCP_ENDPOINT,
    a2aConfig: a2aConfig("initiator"),
  }), (error) => {
    assert.equal(acpProcessTransportFailureStage(error), "completion-permission");
    return true;
  });

  const refusalTransport = createAcpProcessTransport({
    harness: "codex",
    pin: ACP_VERSION_PINS.codex,
    spawn: acpFixtureSpawn({ calls: [], stopReason: "refusal", skipPermission: true }),
    workspace: "/workspace/initiator",
    home: "/workspace/initiator/home",
    env: {},
    actionRecorder: actionRecorderFor([action]),
    retainedActions: [],
    trustedAdapterPublicKeys: [action.adapterPublicKey],
  });
  await assert.rejects(() => refusalTransport.launch({
    acp: ACP_VERSION_PINS.codex,
    runtime: { runtimeId: "runtime-initiator", sessionId: SESSION, role: "initiator", harness: "codex" },
    mandate: VALID_MANDATE,
    mcpEndpoint: MCP_ENDPOINT,
    a2aConfig: a2aConfig("initiator"),
  }), (error) => {
    assert.equal(acpProcessTransportFailureStage(error), "completion-stop");
    return true;
  });
});
