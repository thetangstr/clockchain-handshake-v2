import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";

import { AgentSideConnection, PROTOCOL_VERSION, ndJsonStream } from "@agentclientprotocol/sdk";

import { acpProcessTransportFailureStage, createAcpProcessTransport } from "../src/harness/acp-process-transport.mjs";
import { ACP_VERSION_PINS } from "../src/harness/version-pins.mjs";
import { DIGEST, INVITATION, MCP_ENDPOINT, OTHER_SESSION, SESSION, a2aConfig, retainedAction } from "./harness-acp-fixtures.mjs";

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

function productionHelperStep({ operation, role = "initiator", sessionId = SESSION, payload, prefix = "node verified-helper" }) {
  const argvAfterVerifiedPrefix = [operation, "--state-dir", `$TMPDIR/.clockchain/handshakes/${sessionId}/${role}`];
  if (payload !== undefined) {
    argvAfterVerifiedPrefix.push("--payload-base64url", Buffer.from(JSON.stringify(payload), "utf8").toString("base64url"));
  }
  const shellCommandSuffix = argvAfterVerifiedPrefix
    .map((value, index) => index === 2 ? `"${value}"` : value)
    .join(" ");
  return Object.freeze({
    operation,
    argvAfterVerifiedPrefix: Object.freeze(argvAfterVerifiedPrefix),
    shellCommand: `${prefix} ${shellCommandSuffix}`,
    shellCommandSuffix,
  });
}

function retainedActionForProductionStep(step, overrides = {}) {
  return retainedAction({
    commandLength: Buffer.byteLength(step.shellCommand),
    commandSha256: createHash("sha256").update(step.shellCommand).digest("hex"),
    operation: step.operation,
    ...overrides,
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

function partyBridgeFor(calls, { delayMs = 0, reject = false, completionStatus = () => ({ complete: true, protocolSessionId: SESSION }) } = {}) {
  return Object.freeze({
    completionStatus() {
      const status = completionStatus();
      return {
        certificatePending: false,
        certificateVerified: status.complete,
        directDeliveryComplete: status.complete,
        ...status,
      };
    },
    async observeToolResult(input) {
      calls.push(["partyBridge", input]);
      if (delayMs > 0) await new Promise((resolve) => setTimeout(resolve, delayMs));
      if (reject) throw new Error("party bridge rejected secret-canary /Users/alice/secret");
      return { observed: true, protocolSessionId: SESSION, toolResultDigest: "f".repeat(64) };
    },
  });
}

function acpFixtureSpawn({
  calls,
  closeState = null,
  concurrentHelperPermission = false,
  helperUpdateAfterPermissionRequest = false,
  helperAction = null,
  newSessionUpdates = null,
  newSessionResolvedMarker = false,
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
  permissionCwd = undefined,
  permissionDescription = undefined,
  permissionRawInputExtras = null,
  permissionOptions = null,
  permissionTitle = "display-only approval label",
  promptUpdateSessionId = null,
  unrelatedPermissionBeforeHelper = false,
  unrelatedPermissionOptions = null,
  unrelatedPermissionRawInput = null,
  duplicatePermissionAfterHelper = false,
  duplicatePermissionOptions = null,
}) {
  let promptCount = 0;
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
        if (newSessionResolvedMarker) calls.push(["newSessionResolved"]);
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
        const currentPromptCount = promptCount;
        promptCount += 1;
        const updateSessionId = promptUpdateSessionId ?? params.sessionId;
        let effectiveStopReason = stopReason;
        if (unrelatedPermissionBeforeHelper) {
          const denied = await connection.requestPermission({
            sessionId: params.sessionId,
            toolCall: {
              toolCallId: "tool-unrelated",
              kind: "execute",
              status: "pending",
              rawInput: unrelatedPermissionRawInput ?? { command: "pwd", cwd: permissionCwd },
            },
            options: unrelatedPermissionOptions ?? [
              { optionId: "allow_once", name: "Allow once", kind: "allow_once" },
              { optionId: "reject_once", name: "Reject", kind: "reject_once" },
            ],
          });
          calls.push(["unrelatedPermission", denied]);
          if (denied.outcome.outcome === "cancelled") effectiveStopReason = "cancelled";
        }
        let helperUpdate = null;
        if (sessionUpdates !== null) {
          const updates = typeof sessionUpdates === "function" ? sessionUpdates(currentPromptCount) : sessionUpdates;
          for (const update of updates) {
            await connection.sessionUpdate({ sessionId: updateSessionId, update });
          }
        } else if (helperAction !== null) {
          const sendHelperUpdate = () => connection.sessionUpdate({
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
          if (!helperUpdateAfterPermissionRequest) {
            helperUpdate = sendHelperUpdate();
            if (!concurrentHelperPermission) await helperUpdate;
          } else {
            helperUpdate = sendHelperUpdate;
          }
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
              rawInput: {
                command: permissionCommand,
                ...(permissionCwd === undefined ? {} : { cwd: permissionCwd }),
                transcript: "secret-canary /Users/alice/secret",
              },
            },
          });
          const permissionRequest = connection.requestPermission({
            sessionId: params.sessionId,
            toolCall: {
              toolCallId: "tool-1",
              title: permissionTitle,
              name: "Bash",
              kind: "execute",
              status: "pending",
              rawInput: {
                command: permissionCommand,
                ...(permissionCwd === undefined ? {} : { cwd: permissionCwd }),
                ...(permissionDescription === undefined ? {} : { description: permissionDescription }),
                ...(permissionRawInputExtras ?? {}),
              },
            },
            options: permissionOptions ?? [
              { optionId: "allow_once", name: "Allow once", kind: "allow_once" },
              { optionId: "reject_once", name: "Reject", kind: "reject_once" },
            ],
          });
          if (typeof helperUpdate === "function") helperUpdate = helperUpdate();
          const permission = await permissionRequest;
          calls.push(["permission", permission]);
          if (duplicatePermissionAfterHelper) {
            const duplicatePermission = await connection.requestPermission({
              sessionId: params.sessionId,
              toolCall: {
                toolCallId: "tool-1-duplicate",
                kind: "execute",
                status: "pending",
                rawInput: {
                  command: permissionCommand,
                  ...(permissionCwd === undefined ? {} : { cwd: permissionCwd }),
                },
              },
              options: duplicatePermissionOptions ?? [
                { optionId: "allow_once", name: "Allow once", kind: "allow_once" },
                { optionId: "reject_once", name: "Reject", kind: "reject_once" },
              ],
            });
            calls.push(["duplicatePermission", duplicatePermission]);
            if (duplicatePermission.outcome.outcome === "cancelled") effectiveStopReason = "cancelled";
          }
        }
        if (helperUpdate !== null) await helperUpdate;
        await connection.sessionUpdate({
          sessionId: params.sessionId,
          update: { sessionUpdate: "usage_update", used: 7, size: 100000 },
        });
        return {
          stopReason: effectiveStopReason,
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
  assert.equal(calls[0].options.env.TMPDIR, "/workspace/initiator/tmp");
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
  assert.equal(codexCalls.some((call) => Array.isArray(call) && call[0] === "setSessionConfigOption"), false);
  assert.deepEqual(codexCalls.find((call) => Array.isArray(call) && call[0] === "newSession")?.[1].mcpServers, [{
    type: "http",
    name: "clockchain-handshake",
    url: MCP_ENDPOINT,
    headers: [],
  }]);
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
      permissionDescription: "Authorize the exact retained Clockchain helper",
      permissionOptions: [
        { optionId: "reject", name: "Deny", kind: "reject_once" },
        { optionId: "allow", name: "Allow Once", kind: "allow_once" },
        { optionId: "allow_always", name: "Always Allow", kind: "allow_always" },
      ],
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
  assert.equal(claudeCalls[0].options.env.TMPDIR, "/workspace/responder/tmp");
  assert.equal(claudeCalls[0].options.env.ANTHROPIC_API_KEY, undefined);
  assert.equal(claudeCalls[0].options.env.CODEX_API_KEY, undefined);
  assert.equal(claudeCalls.find((call) => Array.isArray(call) && call[0] === "setSessionConfigOption"), undefined);
  assert.deepEqual(claudeCalls.find((entry) => entry[0] === "permission")[1], {
    outcome: { outcome: "selected", optionId: "allow" },
  });
  await claudeTransport.terminate({ sessionId: SESSION });
  const claudeEvidence = await claudeTransport.collectEvidence({ sessionId: SESSION });
  assert.doesNotMatch(JSON.stringify(claudeEvidence), /wrong-role|forbidden|us\.anthropic/);

  const claudeSubscriptionCalls = [];
  const claudeSubscriptionTransport = createAcpProcessTransport({
    harness: "claude",
    pin: ACP_VERSION_PINS.claude,
    spawn: acpFixtureSpawn({
      calls: claudeSubscriptionCalls,
      helperAction: claudeAction,
      permissionCommand: `clockchain-agent-authorize ${claudeAction.commandSha256}`,
    }),
    workspace: "/workspace/responder",
    home: "/workspace/responder/home",
    env: { CLOCKCHAIN_CLAUDE_MODEL: "sonnet" },
    actionRecorder: actionRecorderFor([claudeAction], claudeSubscriptionCalls),
    nowMs: () => 1786337001000,
    trustedAdapterPublicKeys: [claudeAction.adapterPublicKey],
  });
  await claudeSubscriptionTransport.launch({
    acp: ACP_VERSION_PINS.claude,
    runtime: { runtimeId: "runtime-responder", sessionId: SESSION, role: "responder", harness: "claude" },
    mandate: VALID_MANDATE,
    mcpEndpoint: MCP_ENDPOINT,
    a2aConfig: a2aConfig("responder"),
  });
  assert.deepEqual(claudeSubscriptionCalls.find((call) => Array.isArray(call) && call[0] === "setSessionConfigOption")?.[1], {
    sessionId: `acp-${SESSION}`,
    configId: "model",
    value: "sonnet",
  });
});

test("ACP process transport authorizes the exact safe Claude Bash input envelope", async () => {
  const calls = [];
  const action = retainedAction({ role: "responder", requestDigest: "d".repeat(64), commandSha256: DIGEST });
  const transport = createAcpProcessTransport({
    harness: "claude",
    pin: ACP_VERSION_PINS.claude,
    spawn: acpFixtureSpawn({
      calls,
      helperAction: action,
      permissionCommand: `clockchain-agent-authorize ${action.commandSha256}`,
      permissionDescription: "Authorize the exact retained Clockchain helper",
      permissionRawInputExtras: {
        timeout: 120_000,
        run_in_background: false,
        dangerouslyDisableSandbox: true,
      },
    }),
    workspace: "/workspace/responder",
    home: "/workspace/responder/home",
    env: { CLOCKCHAIN_CLAUDE_MODEL: "sonnet" },
    actionRecorder: actionRecorderFor([action], calls),
    nowMs: () => 1786337001000,
    trustedAdapterPublicKeys: [action.adapterPublicKey],
  });
  await transport.launch({
    acp: ACP_VERSION_PINS.claude,
    runtime: { runtimeId: "runtime-responder", sessionId: SESSION, role: "responder", harness: "claude" },
    mandate: VALID_MANDATE,
    mcpEndpoint: MCP_ENDPOINT,
    a2aConfig: a2aConfig("responder"),
  });
  assert.deepEqual(calls.find((entry) => entry[0] === "permission")?.[1], {
    outcome: { outcome: "selected", optionId: "allow_once" },
  });
  await transport.terminate({ sessionId: SESSION, reason: "test-complete" });
});

test("ACP process transport rejects unsafe Claude Bash execution controls", async () => {
  const unsafeInputs = [
    { timeout: 0 },
    { timeout: 600_001 },
    { timeout: 1.5 },
    { run_in_background: true },
    { dangerouslyDisableSandbox: "true" },
  ];
  for (const permissionRawInputExtras of unsafeInputs) {
    const calls = [];
    const action = retainedAction({ role: "responder", requestDigest: "d".repeat(64), commandSha256: DIGEST });
    const transport = createAcpProcessTransport({
      harness: "claude",
      pin: ACP_VERSION_PINS.claude,
      spawn: acpFixtureSpawn({
        calls,
        helperAction: action,
        permissionCommand: `clockchain-agent-authorize ${action.commandSha256}`,
        permissionRawInputExtras,
      }),
      workspace: "/workspace/responder",
      home: "/workspace/responder/home",
      env: { CLOCKCHAIN_CLAUDE_MODEL: "sonnet" },
      actionRecorder: actionRecorderFor([action], calls),
      nowMs: () => 1786337001000,
      partyBridge: partyBridgeFor(calls),
      trustedAdapterPublicKeys: [action.adapterPublicKey],
    });
    await transport.launch({
      acp: ACP_VERSION_PINS.claude,
      runtime: { runtimeId: "runtime-responder", sessionId: SESSION, role: "responder", harness: "claude" },
      mandate: VALID_MANDATE,
      mcpEndpoint: MCP_ENDPOINT,
      a2aConfig: a2aConfig("responder"),
    });
    assert.deepEqual(calls.find((entry) => entry[0] === "permission")?.[1], {
      outcome: { outcome: "selected", optionId: "reject_once" },
    });
    await transport.terminate({ sessionId: SESSION, reason: "test-complete" });
  }
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
    a2aConfig: a2aConfig("responder"),
  });
  const responderPrompt = responderCalls.find((entry) => entry[0] === "prompt")[1].prompt[0].text;
  assert.match(responderPrompt, new RegExp(INVITATION.replace(".", "\\.")));
  assert.match(responderPrompt, /agent_handshake_accept_invitation/);
  assert.match(responderPrompt, new RegExp(`session: ${SESSION}`));
  assert.match(responderPrompt, /direct A2A endpoint:/i);
  assert.match(responderPrompt, /direct A2A peer card:/i);
  assert.match(responderPrompt, /direct A2A peer endpoint:/i);
  assert.match(responderPrompt, /do not print/i);
  assert.match(responderPrompt, /Continue until Clockchain returns a certificate/i);
  assert.match(responderPrompt, /helperStep\.approvalCommand/i);
  assert.doesNotMatch(responderPrompt, /exactly one action now/i);
  assert.doesNotMatch(responderPrompt, /read.*(?:file|path)|responder-invitation/i);
  assert.doesNotMatch(JSON.stringify(responderCalls[0]), new RegExp(INVITATION.replace(".", "\\.")));
  assert.doesNotMatch(JSON.stringify(await transport.streamEvents({ sessionId: SESSION })), new RegExp(INVITATION.replace(".", "\\.")));
  assert.equal((await transport.executeRetainedAction({ sessionId: SESSION, role: "responder", actionId: "action-1" })).executed, true);
  await transport.terminate({ sessionId: SESSION, reason: "test-complete" });
  assert.doesNotMatch(JSON.stringify(await transport.collectEvidence({ sessionId: SESSION })), new RegExp(INVITATION.replace(".", "\\.")));
  await assert.rejects(() => transport.streamEvents({ sessionId: "other" }));
  assert.equal(DIGEST.length, 64);
});

test("ACP process transport performs real ACP lifecycle with unauthenticated dedicated MCP config", async () => {
  const action = retainedAction({ role: "initiator", requestDigest: "d".repeat(64), commandSha256: DIGEST });
  const calls = [];
  const publicEvents = [];
  const closeState = { killed: false, closed: false };
  let now = 1786337001000;
  const transport = createAcpProcessTransport({
    harness: "codex",
    pin: ACP_VERSION_PINS.codex,
    spawn: acpFixtureSpawn({ calls, closeState, helperAction: action, permissionCwd: "/workspace/initiator" }),
    workspace: "/workspace/initiator",
    home: "/workspace/initiator/home",
    nowMs: () => now++,
    actionRecorder: actionRecorderFor([action], calls),
    env: {
      CLOCKCHAIN_MCP_BEARER: "cc_secret_token_should_not_leak",
      HTTP_PROXY: "http://proxy.local:8080",
    },
    retainedActions: [],
    publicEventSink(event) { publicEvents.push(event); },
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
  assert.deepEqual(calls.filter(Array.isArray).map((entry) => entry[0]), [
    "initialize", "newSession", "prompt", "record", "permission",
  ]);
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
  const configOptions = calls.filter((entry) => entry[0] === "setSessionConfigOption").map((entry) => entry[1]);
  assert.deepEqual(configOptions, []);
  const prompt = calls.find((entry) => entry[0] === "prompt")[1].prompt[0].text;
  assert.match(prompt, /role: initiator/);
  assert.match(prompt, /NS-1847/);
  assert.match(prompt, /"validForSeconds":"90"/);
  assert.match(prompt, /"erc8004":"required_existing_or_fresh"/);
  assert.match(prompt, /"chainId":"eip155:11155111"/);
  assert.match(prompt, /"registryAddress":"0x8004a818bfb912233c491871b3d84c89a494bd9e"/);
  assert.doesNotMatch(prompt, /validForMinutes|45/);
  assert.match(prompt, new RegExp(`session: ${SESSION}`));
  assert.match(prompt, /First call agent_handshake_invite/i);
  assert.match(prompt, /direct A2A endpoint:/i);
  assert.match(prompt, /direct A2A peer card:/i);
  assert.match(prompt, /direct A2A peer endpoint:/i);
  assert.match(prompt, /error field is not an invitation/);
  assert.match(prompt, /Continue until Clockchain returns a certificate/i);
  assert.match(prompt, /helperStep\.approvalCommand/i);
  assert.doesNotMatch(prompt, /exactly one action now/i);
  assert.doesNotMatch(prompt, /privateKey|secret|CLOCKCHAIN_MCP_BEARER|cc_secret|controller authority/i);
  assert.deepEqual(calls.find((entry) => entry[0] === "permission")[1], {
    outcome: { outcome: "selected", optionId: "allow_once" },
  });
  const events = await transport.streamEvents({ sessionId: SESSION });
  assert.deepEqual(publicEvents, events);
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

test("ACP process transport waits for an in-flight authoritative MCP result before approving its retained command", async () => {
  const action = retainedAction({ role: "initiator", requestDigest: "d".repeat(64), commandSha256: DIGEST });
  const calls = [];
  const transport = createAcpProcessTransport({
    harness: "codex",
    pin: ACP_VERSION_PINS.codex,
    spawn: acpFixtureSpawn({
      calls,
      concurrentHelperPermission: true,
      helperAction: action,
      permissionCwd: "/workspace/initiator",
    }),
    workspace: "/workspace/initiator",
    home: "/workspace/initiator/home",
    nowMs: () => 1786337001000,
    actionRecorder: actionRecorderFor([action], calls),
    env: {},
    retainedActions: [],
    partyBridge: partyBridgeFor(calls, { delayMs: 20 }),
    trustedAdapterPublicKeys: [action.adapterPublicKey],
  });

  await transport.launch({
    acp: ACP_VERSION_PINS.codex,
    runtime: { runtimeId: "runtime-initiator", sessionId: SESSION, role: "initiator", harness: "codex" },
    mandate: VALID_MANDATE,
    mcpEndpoint: MCP_ENDPOINT,
    a2aConfig: a2aConfig("initiator"),
  });

  assert.deepEqual(calls.find((entry) => entry[0] === "permission")[1], {
    outcome: { outcome: "selected", optionId: "allow_once" },
  });
  assert.ok(calls.findIndex((entry) => entry[0] === "partyBridge") < calls.findIndex((entry) => entry[0] === "record"));
  await transport.terminate({ sessionId: SESSION, reason: "test-complete" });
});

test("ACP process transport waits for a matching authoritative MCP result that arrives after its permission request", async () => {
  const action = retainedAction({ role: "initiator", requestDigest: "d".repeat(64), commandSha256: DIGEST });
  const calls = [];
  const transport = createAcpProcessTransport({
    harness: "codex",
    pin: ACP_VERSION_PINS.codex,
    spawn: acpFixtureSpawn({
      calls,
      helperAction: action,
      helperUpdateAfterPermissionRequest: true,
      permissionCwd: "/workspace/initiator",
    }),
    workspace: "/workspace/initiator",
    home: "/workspace/initiator/home",
    nowMs: () => 1786337001000,
    actionRecorder: actionRecorderFor([action], calls),
    env: {},
    retainedActions: [],
    partyBridge: partyBridgeFor(calls, { delayMs: 20 }),
    trustedAdapterPublicKeys: [action.adapterPublicKey],
  });

  await transport.launch({
    acp: ACP_VERSION_PINS.codex,
    runtime: { runtimeId: "runtime-initiator", sessionId: SESSION, role: "initiator", harness: "codex" },
    mandate: VALID_MANDATE,
    mcpEndpoint: MCP_ENDPOINT,
    a2aConfig: a2aConfig("initiator"),
  });

  assert.deepEqual(calls.find((entry) => entry[0] === "permission")[1], {
    outcome: { outcome: "selected", optionId: "allow_once" },
  });
  await transport.terminate({ sessionId: SESSION, reason: "test-complete" });
});

test("ACP completion waits for the legacy session-update callback before judging bridge state", async () => {
  const calls = [];
  let observed = false;
  const update = {
    sessionUpdate: "tool_call_update",
    toolCallId: "tool-invite-race",
    kind: "other",
    title: "mcp.clockchain-handshake.agent_handshake_invite",
    status: "completed",
    rawInput: { server: "clockchain-handshake", tool: "agent_handshake_invite", arguments: {} },
    rawOutput: { result: { structuredContent: { sessionId: SESSION, responderInvitation: "opaque-invitation" } }, error: null },
  };
  const transport = createAcpProcessTransport({
    harness: "codex",
    pin: ACP_VERSION_PINS.codex,
    spawn: acpFixtureSpawn({ calls, sessionUpdates: [update], skipPermission: true }),
    workspace: "/workspace/initiator",
    home: "/workspace/initiator/home",
    env: {},
    partyBridge: {
      async observeToolResult() {
        await new Promise((resolve) => setTimeout(resolve, 20));
        observed = true;
        return { observed: true, protocolSessionId: SESSION, toolResultDigest: "f".repeat(64) };
      },
      completionStatus() {
        return {
          certificatePending: false,
          certificateVerified: observed,
          complete: observed,
          directDeliveryComplete: observed,
          protocolSessionId: observed ? SESSION : null,
        };
      },
    },
    trustedAdapterPublicKeys: [retainedAction({ role: "initiator" }).adapterPublicKey],
  });

  await transport.launch({
    acp: ACP_VERSION_PINS.codex,
    runtime: { runtimeId: "runtime-initiator", sessionId: SESSION, role: "initiator", harness: "codex" },
    mandate: VALID_MANDATE,
    mcpEndpoint: MCP_ENDPOINT,
    a2aConfig: a2aConfig("initiator"),
  });

  assert.equal(observed, true);
  assert.equal(calls.filter((entry) => Array.isArray(entry) && entry[0] === "prompt").length, 1);
  await transport.terminate({ sessionId: SESSION, reason: "test-complete" });
});

test("ACP process transport denies an unrelated command without poisoning a later authoritative retained action", async () => {
  const action = retainedAction({ role: "initiator", requestDigest: "d".repeat(64), commandSha256: DIGEST });
  const calls = [];
  const transport = createAcpProcessTransport({
    harness: "codex",
    pin: ACP_VERSION_PINS.codex,
    spawn: acpFixtureSpawn({
      calls,
      helperAction: action,
      permissionCwd: "/workspace/initiator",
      unrelatedPermissionBeforeHelper: true,
    }),
    workspace: "/workspace/initiator",
    home: "/workspace/initiator/home",
    nowMs: () => 1786337001000,
    actionRecorder: actionRecorderFor([action], calls),
    env: {},
    retainedActions: [],
    partyBridge: partyBridgeFor(calls),
    trustedAdapterPublicKeys: [action.adapterPublicKey],
  });

  await transport.launch({
    acp: ACP_VERSION_PINS.codex,
    runtime: { runtimeId: "runtime-initiator", sessionId: SESSION, role: "initiator", harness: "codex" },
    mandate: VALID_MANDATE,
    mcpEndpoint: MCP_ENDPOINT,
    a2aConfig: a2aConfig("initiator"),
  });
  assert.deepEqual(calls.find((entry) => entry[0] === "unrelatedPermission")[1], {
    outcome: { outcome: "selected", optionId: "reject_once" },
  });
  assert.deepEqual(calls.find((entry) => entry[0] === "permission")[1], {
    outcome: { outcome: "selected", optionId: "allow_once" },
  });
  await transport.terminate({ sessionId: SESSION, reason: "test-complete" });
});

test("ACP process transport rejects a non-command permission without poisoning the retained Clockchain action", async () => {
  const action = retainedAction({ role: "responder", requestDigest: "d".repeat(64), commandSha256: DIGEST });
  const calls = [];
  const transport = createAcpProcessTransport({
    harness: "claude",
    pin: ACP_VERSION_PINS.claude,
    spawn: acpFixtureSpawn({
      calls,
      helperAction: action,
      permissionCwd: "/workspace/responder",
      unrelatedPermissionBeforeHelper: true,
      unrelatedPermissionRawInput: { path: "/workspace/responder" },
    }),
    workspace: "/workspace/responder",
    home: "/workspace/responder/home",
    nowMs: () => 1786337001000,
    actionRecorder: actionRecorderFor([action], calls),
    env: {},
    retainedActions: [],
    partyBridge: partyBridgeFor(calls),
    trustedAdapterPublicKeys: [action.adapterPublicKey],
  });
  await transport.launch({
    acp: ACP_VERSION_PINS.claude,
    runtime: { runtimeId: "runtime-responder", sessionId: SESSION, role: "responder", harness: "claude" },
    mandate: VALID_MANDATE,
    mcpEndpoint: MCP_ENDPOINT,
    a2aConfig: a2aConfig("responder"),
  });
  assert.deepEqual(calls.find((entry) => entry[0] === "unrelatedPermission")[1], {
    outcome: { outcome: "selected", optionId: "reject_once" },
  });
  assert.deepEqual(calls.find((entry) => entry[0] === "permission")[1], {
    outcome: { outcome: "selected", optionId: "allow_once" },
  });
  await transport.terminate({ sessionId: SESSION, reason: "test-complete" });
});

test("ACP process transport cancels a non-command permission without a reject option and continues Clockchain", async () => {
  const action = retainedAction({ role: "responder", requestDigest: "d".repeat(64), commandSha256: DIGEST });
  const calls = [];
  const transport = createAcpProcessTransport({
    harness: "claude",
    pin: ACP_VERSION_PINS.claude,
    spawn: acpFixtureSpawn({
      calls,
      helperAction: action,
      permissionCwd: "/workspace/responder",
      unrelatedPermissionBeforeHelper: true,
      unrelatedPermissionOptions: [{ optionId: "allow_once", name: "Allow once", kind: "allow_once" }],
      unrelatedPermissionRawInput: { path: "/workspace/responder" },
    }),
    workspace: "/workspace/responder",
    home: "/workspace/responder/home",
    nowMs: () => 1786337001000,
    actionRecorder: actionRecorderFor([action], calls),
    env: {},
    retainedActions: [],
    partyBridge: partyBridgeFor(calls),
    trustedAdapterPublicKeys: [action.adapterPublicKey],
  });
  await transport.launch({
    acp: ACP_VERSION_PINS.claude,
    runtime: { runtimeId: "runtime-responder", sessionId: SESSION, role: "responder", harness: "claude" },
    mandate: VALID_MANDATE,
    mcpEndpoint: MCP_ENDPOINT,
    a2aConfig: a2aConfig("responder"),
  });
  assert.deepEqual(calls.find((entry) => entry[0] === "unrelatedPermission")[1], {
    outcome: { outcome: "cancelled" },
  });
  assert.deepEqual(calls.find((entry) => entry[0] === "permission")[1], {
    outcome: { outcome: "selected", optionId: "allow_once" },
  });
  await transport.terminate({ sessionId: SESSION, reason: "test-complete" });
});

test("ACP continuation restates every exact pending retained approval before another MCP call", async () => {
  const actions = ["init", "policy", "inspect"].map((operation, index) => retainedAction({
    actionId: `action-${index}`,
    commandSha256: String(index + 1).repeat(64),
    operation,
  }));
  const calls = [];
  let completionChecks = 0;
  const transport = createAcpProcessTransport({
    harness: "codex",
    pin: ACP_VERSION_PINS.codex,
    spawn: acpFixtureSpawn({
      calls,
      permissionCommand: `clockchain-agent-authorize ${actions[0].commandSha256}`,
      sessionUpdates: (promptCount) => promptCount === 0 ? [{
        sessionUpdate: "tool_call_update",
        toolCallId: "tool-mcp-setup",
        status: "completed",
        rawInput: { server: "clockchain-handshake", tool: "agent_handshake_invite", arguments: {} },
        rawOutput: {
          result: { structuredContent: { helperSteps: actions.map((action) => helperStepForAction(action)) } },
          error: null,
        },
      }] : [],
    }),
    workspace: "/workspace/initiator",
    home: "/workspace/initiator/home",
    nowMs: () => 1786337001000,
    actionRecorder: actionRecorderFor(actions, calls),
    env: {},
    partyBridge: partyBridgeFor(calls, {
      completionStatus() {
        completionChecks += 1;
        return completionChecks >= 2
          ? { complete: true, protocolSessionId: SESSION }
          : { complete: false, protocolSessionId: SESSION };
      },
    }),
    trustedAdapterPublicKeys: actions.map((action) => action.adapterPublicKey),
  });
  await transport.launch({
    acp: ACP_VERSION_PINS.codex,
    runtime: { runtimeId: "runtime-initiator", sessionId: SESSION, role: "initiator", harness: "codex" },
    mandate: VALID_MANDATE,
    mcpEndpoint: MCP_ENDPOINT,
    a2aConfig: a2aConfig("initiator"),
  });
  const prompts = calls.filter((entry) => entry[0] === "prompt");
  assert.equal(prompts.length, 2);
  const continuation = prompts[1][1].prompt[0].text;
  assert.doesNotMatch(continuation, new RegExp(actions[0].commandSha256));
  assert.match(continuation, new RegExp(`clockchain-agent-authorize ${actions[1].commandSha256}`));
  assert.match(continuation, new RegExp(`clockchain-agent-authorize ${actions[2].commandSha256}`));
  assert.match(continuation, /one at a time, in this order/i);
  assert.match(continuation, /run_in_background must be false/i);
  assert.match(continuation, /Do not call another MCP tool/i);
  await transport.terminate({ sessionId: SESSION, reason: "test-complete" });
});

test("ACP process transport fails closed when an unrelated command lacks one exact rejection option", async () => {
  const action = retainedAction({ role: "initiator", requestDigest: "d".repeat(64), commandSha256: DIGEST });
  const invalidOptionLists = [
    [{ optionId: "allow_once", name: "Allow once", kind: "allow_once" }],
    [
      { optionId: "reject_once", name: "Reject", kind: "reject_once" },
      { optionId: "reject_once", name: "Reject duplicate", kind: "reject_once" },
    ],
    [{ optionId: "reject_once", name: "Reject", kind: "allow_once" }],
  ];
  for (const unrelatedPermissionOptions of invalidOptionLists) {
    const transport = createAcpProcessTransport({
      harness: "codex",
      pin: ACP_VERSION_PINS.codex,
      spawn: acpFixtureSpawn({
        calls: [],
        helperAction: action,
        permissionCwd: "/workspace/initiator",
        unrelatedPermissionBeforeHelper: true,
        unrelatedPermissionOptions,
      }),
      workspace: "/workspace/initiator",
      home: "/workspace/initiator/home",
      nowMs: () => 1786337001000,
      actionRecorder: actionRecorderFor([action]),
      env: {},
      retainedActions: [],
      partyBridge: partyBridgeFor([]),
      trustedAdapterPublicKeys: [action.adapterPublicKey],
    });
    await assert.rejects(() => transport.launch({
      acp: ACP_VERSION_PINS.codex,
      runtime: { runtimeId: "runtime-initiator", sessionId: SESSION, role: "initiator", harness: "codex" },
      mandate: VALID_MANDATE,
      mcpEndpoint: MCP_ENDPOINT,
      a2aConfig: a2aConfig("initiator"),
    }), (error) => {
      assert.equal(acpProcessTransportFailureStage(error), "completion-permission-command-approval");
      return true;
    });
  }
});

test("ACP process transport declines a replay of an already authorized retained action without cancelling the turn", async () => {
  const action = retainedAction({ role: "initiator", requestDigest: "d".repeat(64), commandSha256: DIGEST });
  const calls = [];
  const transport = createAcpProcessTransport({
    harness: "codex",
    pin: ACP_VERSION_PINS.codex,
    spawn: acpFixtureSpawn({
      calls,
      duplicatePermissionAfterHelper: true,
      helperAction: action,
      permissionCwd: "/workspace/initiator",
    }),
    workspace: "/workspace/initiator",
    home: "/workspace/initiator/home",
    nowMs: () => 1786337001000,
    actionRecorder: actionRecorderFor([action], calls),
    env: {},
    retainedActions: [],
    partyBridge: partyBridgeFor(calls),
    trustedAdapterPublicKeys: [action.adapterPublicKey],
  });
  await transport.launch({
    acp: ACP_VERSION_PINS.codex,
    runtime: { runtimeId: "runtime-initiator", sessionId: SESSION, role: "initiator", harness: "codex" },
    mandate: VALID_MANDATE,
    mcpEndpoint: MCP_ENDPOINT,
    a2aConfig: a2aConfig("initiator"),
  });
  assert.deepEqual(calls.find((entry) => entry[0] === "permission")[1], {
    outcome: { outcome: "selected", optionId: "allow_once" },
  });
  assert.deepEqual(calls.find((entry) => entry[0] === "duplicatePermission")[1], {
    outcome: { outcome: "selected", optionId: "reject_once" },
  });
  await transport.terminate({ sessionId: SESSION, reason: "test-complete" });
});

test("ACP process transport safely absorbs an exact retained-action replay when ACP offers no reject option", async () => {
  const action = retainedAction({ role: "initiator", requestDigest: "d".repeat(64), commandSha256: DIGEST });
  const calls = [];
  const transport = createAcpProcessTransport({
    harness: "codex",
    pin: ACP_VERSION_PINS.codex,
    spawn: acpFixtureSpawn({
      calls,
      duplicatePermissionAfterHelper: true,
      duplicatePermissionOptions: [{ optionId: "allow_once", name: "Allow once", kind: "allow_once" }],
      helperAction: action,
      permissionCwd: "/workspace/initiator",
    }),
    workspace: "/workspace/initiator",
    home: "/workspace/initiator/home",
    nowMs: () => 1786337001000,
    actionRecorder: actionRecorderFor([action], calls),
    env: {},
    retainedActions: [],
    partyBridge: partyBridgeFor(calls),
    trustedAdapterPublicKeys: [action.adapterPublicKey],
  });
  await transport.launch({
    acp: ACP_VERSION_PINS.codex,
    runtime: { runtimeId: "runtime-initiator", sessionId: SESSION, role: "initiator", harness: "codex" },
    mandate: VALID_MANDATE,
    mcpEndpoint: MCP_ENDPOINT,
    a2aConfig: a2aConfig("initiator"),
  });
  assert.deepEqual(calls.find((entry) => entry[0] === "duplicatePermission")[1], {
    outcome: { outcome: "cancelled" },
  });
  await transport.terminate({ sessionId: SESSION, reason: "test-complete" });
});

test("ACP process transport re-prompts an end-turning agent until the Clockchain bridge is complete", async () => {
  const calls = [];
  let completionChecks = 0;
  const statusUpdate = {
    sessionUpdate: "tool_call_update",
    toolCallId: "tool-handshake-status",
    kind: "other",
    title: "agent_handshake_status",
    status: "completed",
    rawInput: { server: "clockchain-handshake", tool: "agent_handshake_status", arguments: {} },
    rawOutput: { result: { sessionId: SESSION }, error: null },
  };
  const transport = createAcpProcessTransport({
    harness: "codex",
    pin: ACP_VERSION_PINS.codex,
    spawn: acpFixtureSpawn({ calls, sessionUpdates: [statusUpdate], skipPermission: true }),
    workspace: "/workspace/initiator",
    home: "/workspace/initiator/home",
    partyBridge: partyBridgeFor(calls, {
      completionStatus() {
        completionChecks += 1;
        return { complete: completionChecks >= 2, protocolSessionId: SESSION };
      },
    }),
    env: {},
    trustedAdapterPublicKeys: [retainedAction({ role: "initiator" }).adapterPublicKey],
  });
  await transport.launch({
    acp: ACP_VERSION_PINS.codex,
    runtime: { runtimeId: "runtime-initiator", sessionId: SESSION, role: "initiator", harness: "codex" },
    mandate: VALID_MANDATE,
    mcpEndpoint: MCP_ENDPOINT,
    a2aConfig: a2aConfig("initiator"),
  });
  const prompts = calls.filter((entry) => entry[0] === "prompt");
  assert.equal(prompts.length, 2);
  assert.match(prompts[1][1].prompt[0].text, /Continue the existing Clockchain handshake/i);
  assert.match(prompts[1][1].prompt[0].text, new RegExp(SESSION));
  assert.match(prompts[1][1].prompt[0].text, /agent_handshake_join/);
  assert.match(prompts[1][1].prompt[0].text, /agent_handshake_next/);
  assert.match(prompts[1][1].prompt[0].text, /agent_handshake_get_certificate/);
  assert.doesNotMatch(prompts[1][1].prompt[0].text, /agent_handshake_invite/);
  assert.equal(completionChecks, 2);
});

test("ACP completion loop leaves headroom to verify a certificate after sixteen protocol turns", async () => {
  const calls = [];
  let completionChecks = 0;
  const transport = createAcpProcessTransport({
    harness: "codex",
    pin: ACP_VERSION_PINS.codex,
    spawn: acpFixtureSpawn({ calls, sessionUpdates: [], skipPermission: true }),
    workspace: "/workspace/initiator",
    home: "/workspace/initiator/home",
    partyBridge: partyBridgeFor(calls, {
      completionStatus() {
        completionChecks += 1;
        return { complete: completionChecks >= 17, protocolSessionId: SESSION };
      },
    }),
    env: {},
    trustedAdapterPublicKeys: [retainedAction({ role: "initiator" }).adapterPublicKey],
  });
  await transport.launch({
    acp: ACP_VERSION_PINS.codex,
    runtime: { runtimeId: "runtime-initiator", sessionId: SESSION, role: "initiator", harness: "codex" },
    mandate: VALID_MANDATE,
    mcpEndpoint: MCP_ENDPOINT,
    a2aConfig: a2aConfig("initiator"),
  });
  assert.equal(calls.filter((entry) => entry[0] === "prompt").length, 17);
  assert.equal(completionChecks, 17);
});

test("ACP continuation asks only for the certificate after the direct party delivery is complete", async () => {
  const calls = [];
  let completionChecks = 0;
  const transport = createAcpProcessTransport({
    harness: "codex",
    pin: ACP_VERSION_PINS.codex,
    spawn: acpFixtureSpawn({ calls, sessionUpdates: [], skipPermission: true }),
    workspace: "/workspace/initiator",
    home: "/workspace/initiator/home",
    partyBridge: partyBridgeFor(calls, {
      completionStatus() {
        completionChecks += 1;
        return completionChecks >= 2
          ? { complete: true, certificateVerified: true, directDeliveryComplete: true, protocolSessionId: SESSION }
          : { complete: false, certificateVerified: false, directDeliveryComplete: true, protocolSessionId: SESSION };
      },
    }),
    env: {},
    trustedAdapterPublicKeys: [retainedAction({ role: "initiator" }).adapterPublicKey],
  });
  await transport.launch({
    acp: ACP_VERSION_PINS.codex,
    runtime: { runtimeId: "runtime-initiator", sessionId: SESSION, role: "initiator", harness: "codex" },
    mandate: VALID_MANDATE,
    mcpEndpoint: MCP_ENDPOINT,
    a2aConfig: a2aConfig("initiator"),
  });
  const secondPrompt = calls.filter((entry) => entry[0] === "prompt")[1][1].prompt[0].text;
  assert.match(secondPrompt, /^Call agent_handshake_get_certificate now/);
  assert.doesNotMatch(secondPrompt, /agent_handshake_status|agent_handshake_next|agent_handshake_invite/);
});

test("ACP continuation repeats the exact role bootstrap while no protocol session exists", async () => {
  const calls = [];
  let completionChecks = 0;
  const transport = createAcpProcessTransport({
    harness: "codex",
    pin: ACP_VERSION_PINS.codex,
    spawn: acpFixtureSpawn({ calls, sessionUpdates: [], skipPermission: true }),
    workspace: "/workspace/initiator",
    home: "/workspace/initiator/home",
    partyBridge: partyBridgeFor(calls, {
      completionStatus() {
        completionChecks += 1;
        return completionChecks >= 2
          ? { complete: true, protocolSessionId: SESSION }
          : { complete: false, protocolSessionId: null };
      },
    }),
    env: {},
    trustedAdapterPublicKeys: [retainedAction({ role: "initiator" }).adapterPublicKey],
  });
  await transport.launch({
    acp: ACP_VERSION_PINS.codex,
    runtime: { runtimeId: "runtime-initiator", sessionId: SESSION, role: "initiator", harness: "codex" },
    mandate: VALID_MANDATE,
    mcpEndpoint: MCP_ENDPOINT,
    a2aConfig: a2aConfig("initiator"),
  });
  const prompts = calls.filter((entry) => entry[0] === "prompt");
  assert.equal(prompts.length, 2);
  assert.match(prompts[1][1].prompt[0].text, /agent_handshake_invite/);
  assert.match(prompts[1][1].prompt[0].text, /"validForSeconds":"90"/);
  assert.match(prompts[1][1].prompt[0].text, /"erc8004":"required_existing_or_fresh"/);
  assert.doesNotMatch(prompts[1][1].prompt[0].text, /existing Clockchain handshake/i);
});

test("ACP responder continuation repeats the exact private invitation while no protocol session exists", async () => {
  const calls = [];
  let completionChecks = 0;
  const transport = createAcpProcessTransport({
    harness: "claude",
    pin: ACP_VERSION_PINS.claude,
    spawn: acpFixtureSpawn({ calls, sessionUpdates: [], skipPermission: true }),
    workspace: "/workspace/responder",
    home: "/workspace/responder/home",
    partyBridge: partyBridgeFor(calls, {
      completionStatus() {
        completionChecks += 1;
        return completionChecks >= 2
          ? { complete: true, protocolSessionId: SESSION }
          : { complete: false, protocolSessionId: null };
      },
    }),
    env: {},
    trustedAdapterPublicKeys: [retainedAction({ role: "responder" }).adapterPublicKey],
  });
  await transport.launch({
    acp: ACP_VERSION_PINS.claude,
    runtime: { runtimeId: "runtime-responder", sessionId: SESSION, role: "responder", harness: "claude" },
    mandate: VALID_MANDATE,
    mcpEndpoint: MCP_ENDPOINT,
    a2aConfig: a2aConfig("responder"),
  });
  const prompts = calls.filter((entry) => entry[0] === "prompt");
  assert.equal(prompts.length, 2);
  assert.match(prompts[1][1].prompt[0].text, new RegExp(INVITATION.replace(".", "\\.")));
  assert.match(prompts[1][1].prompt[0].text, /agent_handshake_accept_invitation/);
  assert.doesNotMatch(prompts[1][1].prompt[0].text, /read.*(?:file|path)|responder-invitation/i);
});

test("ACP process transport distinguishes each public Clockchain boundary at incomplete completion", async () => {
  const successfulUpdate = {
    sessionUpdate: "tool_call_update",
    toolCallId: "status",
    status: "completed",
    rawInput: { server: "clockchain-handshake", tool: "agent_handshake_status", arguments: {} },
    rawOutput: { result: { status: "waiting" }, error: null },
  };
  const cases = [
    {
      expectedStage: "completion-protocol-bridge-incomplete-no-clockchain-tool",
      protocolSessionId: null,
      sessionUpdates: [],
    },
    {
      expectedStage: "completion-protocol-bridge-incomplete-clockchain-tool-incomplete",
      protocolSessionId: null,
      sessionUpdates: [{
        sessionUpdate: "tool_call_update",
        toolCallId: "pending-invite",
        status: "in_progress",
        rawInput: { server: "clockchain-handshake", tool: "agent_handshake_invite", arguments: {} },
      }],
    },
    {
      expectedStage: "completion-protocol-bridge-incomplete-clockchain-tool-failed",
      protocolSessionId: null,
      sessionUpdates: [{
        sessionUpdate: "tool_call_update",
        toolCallId: "failed-invite",
        status: "failed",
        rawInput: { server: "clockchain-handshake", tool: "agent_handshake_invite", arguments: {} },
        rawOutput: { result: null, error: "redacted by ACP fixture" },
      }],
    },
    {
      expectedStage: "completion-protocol-bridge-incomplete-mcp-failure",
      protocolSessionId: null,
      sessionUpdates: [{
        sessionUpdate: "tool_call_update",
        toolCallId: "failed-invite",
        status: "completed",
        rawInput: { server: "clockchain-handshake", tool: "agent_handshake_invite", arguments: {} },
        rawOutput: {
          result: {
            content: [{ type: "text", text: JSON.stringify({ error: "HANDSHAKE_UNAVAILABLE", retryable: false }) }],
            isError: true,
          },
          error: null,
        },
      }],
    },
    {
      expectedStage: "completion-protocol-bridge-incomplete-open-session",
      protocolSessionId: SESSION,
      sessionUpdates: [successfulUpdate],
    },
  ];
  for (const item of cases) {
    const calls = [];
    const transport = createAcpProcessTransport({
      harness: "codex",
      pin: ACP_VERSION_PINS.codex,
      spawn: acpFixtureSpawn({ calls, sessionUpdates: item.sessionUpdates, skipPermission: true }),
      workspace: "/workspace/initiator",
      home: "/workspace/initiator/home",
      partyBridge: Object.freeze({
        completionStatus: () => ({
          certificatePending: false,
          certificateVerified: false,
          complete: false,
          directDeliveryComplete: false,
          protocolSessionId: item.protocolSessionId,
        }),
        async observeToolResult(input) {
          calls.push(["partyBridge", input]);
          return { observed: true, protocolSessionId: item.protocolSessionId, toolResultDigest: "f".repeat(64) };
        },
      }),
      env: {},
      trustedAdapterPublicKeys: [retainedAction({ role: "initiator" }).adapterPublicKey],
    });
    await assert.rejects(() => transport.launch({
      acp: ACP_VERSION_PINS.codex,
      runtime: { runtimeId: "runtime-initiator", sessionId: SESSION, role: "initiator", harness: "codex" },
      mandate: VALID_MANDATE,
      mcpEndpoint: MCP_ENDPOINT,
      a2aConfig: a2aConfig("initiator"),
    }), (error) => {
      assert.equal(acpProcessTransportFailureStage(error), item.expectedStage);
      return true;
    });
  }
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

test("ACP process transport defers setup-time MCP tool results until newSession confirms the exact session", async () => {
  const action = retainedAction({ role: "initiator", requestDigest: "d".repeat(64), commandSha256: DIGEST });
  const calls = [];
  const transport = createAcpProcessTransport({
    harness: "codex",
    pin: ACP_VERSION_PINS.codex,
    spawn: acpFixtureSpawn({
      calls,
      newSessionResolvedMarker: true,
      newSessionUpdates: [...Array.from({ length: 32 }, (_, index) => ({
        sessionUpdate: index % 2 === 0 ? "tool_call" : "tool_call_update",
        toolCallId: `tool-progress-${index}`,
        kind: "other",
        title: "MCP setup progress",
        status: "pending",
      })), {
        sessionUpdate: "tool_call_update",
        toolCallId: "tool-early-invite",
        kind: "other",
        title: "agent_handshake_invite",
        status: "completed",
        rawInput: { server: "clockchain-handshake", tool: "agent_handshake_invite", arguments: {} },
        rawOutput: { result: { responderInvitation: "opaque-invitation" }, error: null },
      }],
      skipPermission: true,
    }),
    workspace: "/workspace/initiator",
    home: "/workspace/initiator/home",
    nowMs: () => 1786337001000,
    actionRecorder: actionRecorderFor([action], calls),
    partyBridge: partyBridgeFor(calls),
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
  assert.equal(calls.findIndex((entry) => entry[0] === "newSessionResolved") < calls.findIndex((entry) => entry[0] === "partyBridge"), true);

  const mismatchCalls = [];
  const mismatch = createAcpProcessTransport({
    harness: "codex",
    pin: ACP_VERSION_PINS.codex,
    spawn: acpFixtureSpawn({
      calls: mismatchCalls,
      newSessionUpdateSessionId: "acp-provisional",
      newSessionId: "acp-returned",
      newSessionUpdates: [{
        sessionUpdate: "tool_call_update",
        toolCallId: "tool-early-invite",
        kind: "other",
        title: "agent_handshake_invite",
        status: "completed",
        rawInput: { server: "clockchain-handshake", tool: "agent_handshake_invite", arguments: {} },
        rawOutput: { result: { responderInvitation: "opaque-invitation" }, error: null },
      }],
      skipPermission: true,
    }),
    workspace: "/workspace/initiator",
    home: "/workspace/initiator/home",
    partyBridge: partyBridgeFor(mismatchCalls),
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
  assert.equal(mismatchCalls.some((entry) => entry[0] === "partyBridge"), false);
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

test("ACP process transport ignores explanatory MCP text beside one authoritative structured helper", async () => {
  const action = retainedAction({ role: "initiator", requestDigest: "d".repeat(64), commandSha256: DIGEST });
  const calls = [];
  const transport = createAcpProcessTransport({
    harness: "codex",
    pin: ACP_VERSION_PINS.codex,
    spawn: acpFixtureSpawn({
      calls,
      sessionUpdates: [{
        sessionUpdate: "tool_call_update",
        toolCallId: "mcp-call-explanatory",
        status: "completed",
        rawInput: { server: "clockchain-handshake", tool: "agent_handshake_next", arguments: {} },
        rawOutput: {
          result: {
            content: [{ type: "text", text: "Continue with the retained local action shown in structured content." }],
            structuredContent: { helperStep: helperStepForAction(action) },
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
    trustedAdapterPublicKeys: [action.adapterPublicKey],
  });
  try {
    await transport.launch({
      acp: ACP_VERSION_PINS.codex,
      runtime: { runtimeId: "runtime-initiator", sessionId: SESSION, role: "initiator", harness: "codex" },
      mandate: VALID_MANDATE,
      mcpEndpoint: MCP_ENDPOINT,
      a2aConfig: a2aConfig("initiator"),
    });
  } catch (error) {
    assert.fail(`unexpected stage ${acpProcessTransportFailureStage(error)}`);
  }
  assert.equal((await transport.executeRetainedAction({ sessionId: SESSION, role: "initiator", actionId: action.actionId })).executed, true);
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

test("ACP process transport does not forward terminal or retryable MCP error bodies to the party bridge", async () => {
  const action = retainedAction({ role: "initiator", requestDigest: "d".repeat(64), commandSha256: DIGEST });
  const cases = [
    {
      harness: "codex",
      result: {
        content: [{ type: "text", text: JSON.stringify({ error: "HANDSHAKE_UNAVAILABLE", retryable: false }) }],
        isError: true,
      },
    },
    {
      harness: "codex",
      result: {
        content: [{ type: "text", text: JSON.stringify({ error: "HANDSHAKE_TEMPORARILY_UNAVAILABLE", retryable: true, retryAfterMs: 5000 }) }],
        structuredContent: { error: "HANDSHAKE_TEMPORARILY_UNAVAILABLE", retryable: true, retryAfterMs: 5000 },
      },
    },
    {
      harness: "claude",
      result: [{ type: "text", text: JSON.stringify({ error: "HANDSHAKE_UNAVAILABLE", retryable: false }) }],
    },
  ];
  for (const item of cases) {
    const calls = [];
    const update = item.harness === "codex" ? {
      sessionUpdate: "tool_call_update",
      toolCallId: "failed-invite",
      status: "completed",
      rawInput: { server: "clockchain-handshake", tool: "agent_handshake_invite", arguments: {} },
      rawOutput: { result: item.result, error: null },
    } : {
      sessionUpdate: "tool_call_update",
      toolCallId: "failed-invite",
      status: "completed",
      rawOutput: item.result,
      _meta: { claudeCode: { toolName: "mcp__clockchain-handshake__agent_handshake_invite" } },
    };
    const transport = createAcpProcessTransport({
      harness: item.harness,
      pin: ACP_VERSION_PINS[item.harness],
      spawn: acpFixtureSpawn({ calls, sessionUpdates: [update], skipPermission: true }),
      workspace: `/workspace/${item.harness}`,
      home: `/workspace/${item.harness}/home`,
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
    assert.equal(calls.some((entry) => Array.isArray(entry) && entry[0] === "partyBridge"), false);
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

test("ACP process transport derives retained metadata from the production MCP setup batch", async () => {
  const steps = [
    productionHelperStep({ operation: "init" }),
    productionHelperStep({ operation: "policy", payload: { policyDigest: "a".repeat(64), role: "initiator", sessionId: SESSION, operation: "policy" } }),
    productionHelperStep({ operation: "inspect" }),
  ];
  const actions = steps.map((step, index) => retainedActionForProductionStep(step, {
    actionId: `setup-${index + 1}`,
    requestDigest: String(index + 1).repeat(64),
  }));
  const calls = [];
  const transport = createAcpProcessTransport({
    harness: "codex",
    pin: ACP_VERSION_PINS.codex,
    spawn: acpFixtureSpawn({
      calls,
      skipPermission: true,
      sessionUpdates: [{
        sessionUpdate: "tool_call_update",
        toolCallId: "mcp-call-setup",
        status: "completed",
        rawInput: { server: "clockchain-handshake", tool: "agent_handshake_create_invitation", arguments: {} },
        rawOutput: {
          result: { structuredContent: { localAction: { helperSteps: steps } } },
          error: null,
        },
      }],
    }),
    workspace: "/workspace/initiator",
    home: "/workspace/initiator/home",
    nowMs: () => 1786337001000,
    actionRecorder: actionRecorderFor(actions, calls),
    env: {},
    partyBridge: partyBridgeFor(calls),
    retainedActions: [],
    trustedAdapterPublicKeys: actions.map((action) => action.adapterPublicKey),
  });
  await transport.launch({
    acp: ACP_VERSION_PINS.codex,
    runtime: { runtimeId: "runtime-initiator", sessionId: OTHER_SESSION, role: "initiator", harness: "codex" },
    mandate: VALID_MANDATE,
    mcpEndpoint: MCP_ENDPOINT,
    a2aConfig: a2aConfig("initiator"),
  });
  const recorded = calls.filter((entry) => Array.isArray(entry) && entry[0] === "record").map((entry) => entry[1]);
  assert.equal(recorded.length, 3);
  assert.deepEqual(recorded.map((entry) => entry.operation), ["init", "policy", "inspect"]);
  assert.ok(recorded.every((entry) => entry.role === "initiator" && entry.sessionId === SESSION));
  assert.ok(recorded.every((entry) => entry.approvalCommand === `clockchain-agent-authorize ${entry.commandSha256}`));
});

test("ACP process transport derives retained metadata from one production MCP signing step", async () => {
  const step = productionHelperStep({
    operation: "sign",
    role: "responder",
    payload: { operation: "sign", policyDigest: "a".repeat(64), role: "responder", sessionId: SESSION },
  });
  const action = retainedActionForProductionStep(step, { role: "responder", policyDigest: "a".repeat(64) });
  const calls = [];
  const transport = createAcpProcessTransport({
    harness: "claude",
    pin: ACP_VERSION_PINS.claude,
    spawn: acpFixtureSpawn({
      calls,
      skipPermission: true,
      sessionUpdates: [{
        sessionUpdate: "tool_call_update",
        toolCallId: "mcp-call-sign",
        status: "completed",
        rawOutput: [{ type: "text", text: JSON.stringify({ localAction: { helperStep: step } }) }],
        _meta: { claudeCode: { toolName: "mcp__clockchain-handshake__agent_handshake_next" } },
      }],
    }),
    workspace: "/workspace/responder",
    home: "/workspace/responder/home",
    nowMs: () => 1786337001000,
    actionRecorder: actionRecorderFor([action], calls),
    env: {},
    partyBridge: partyBridgeFor(calls),
    retainedActions: [],
    trustedAdapterPublicKeys: [action.adapterPublicKey],
  });
  await transport.launch({
    acp: ACP_VERSION_PINS.claude,
    runtime: { runtimeId: "runtime-responder", sessionId: OTHER_SESSION, role: "responder", harness: "claude" },
    mandate: VALID_MANDATE,
    mcpEndpoint: MCP_ENDPOINT,
    a2aConfig: a2aConfig("responder"),
  });
  const recorded = calls.find((entry) => Array.isArray(entry) && entry[0] === "record")[1];
  assert.equal(recorded.commandLength, Buffer.byteLength(step.shellCommand));
  assert.equal(recorded.commandSha256, createHash("sha256").update(step.shellCommand).digest("hex"));
  assert.equal(recorded.policyDigest, "a".repeat(64));
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
      expectedProtocolStage: "retained-extract",
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
      expectedProtocolStage: "retained-extract",
      rawOutput: {
        result: { content: [{ type: "image", text: JSON.stringify({ helperStep: helperStepForAction(action) }) }] },
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

test("ACP process transport denies broad shell permission and rejects malformed retained or non-end-turn completion", async () => {
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
  await badPermissionTransport.launch({
    acp: ACP_VERSION_PINS.codex,
    runtime: { runtimeId: "runtime-initiator", sessionId: SESSION, role: "initiator", harness: "codex" },
    mandate: VALID_MANDATE,
    mcpEndpoint: MCP_ENDPOINT,
    a2aConfig: a2aConfig("initiator"),
  });
  const denialEvents = await badPermissionTransport.streamEvents({ sessionId: SESSION });
  assert.equal(denialEvents.some((event) => event.type === "acp.permission.denied"), true);
  await badPermissionTransport.terminate({ sessionId: SESSION, reason: "test-complete" });

  const wrongCwdTransport = createAcpProcessTransport({
    harness: "codex",
    pin: ACP_VERSION_PINS.codex,
    spawn: acpFixtureSpawn({
      calls: [],
      helperAction: action,
      permissionCwd: "/workspace/other",
    }),
    workspace: "/workspace/initiator",
    home: "/workspace/initiator/home",
    nowMs: () => 1786337001000,
    actionRecorder: actionRecorderFor([action]),
    env: {},
    retainedActions: [],
    trustedAdapterPublicKeys: [action.adapterPublicKey],
  });
  await assert.rejects(() => wrongCwdTransport.launch({
    acp: ACP_VERSION_PINS.codex,
    runtime: { runtimeId: "runtime-initiator", sessionId: SESSION, role: "initiator", harness: "codex" },
    mandate: VALID_MANDATE,
    mcpEndpoint: MCP_ENDPOINT,
    a2aConfig: a2aConfig("initiator"),
  }), (error) => {
    assert.equal(acpProcessTransportFailureStage(error), "completion-permission-command-cwd");
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
    assert.equal(acpProcessTransportFailureStage(error), "completion-stop-refusal");
    return true;
  });
});
