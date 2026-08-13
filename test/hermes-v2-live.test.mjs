import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { test } from "node:test";
import { gzipSync } from "node:zlib";

import { recoverMessageAddress } from "viem";
import { privateKeyToAccount } from "viem/accounts";

import { digestHex } from "../src/core/canonical.mjs";
import {
  CLOCKCHAIN_V2_TOOLS,
  buildHermesConfig,
  buildHermesInvocation,
  commitmentCheckpointDigest,
  commitmentCheckpointSigningBytes,
  createCommitmentCheckpoint,
  createHermesDecisionPrompt,
  createStreamableMcpClient,
  extractSigningRequestFromArgv,
  parseHermesDecision,
} from "../src/testing/hermes-v2-live.mjs";

const SESSION = "123e4567-e89b-42d3-a456-426614174000";
const POLICY_DIGEST = "a".repeat(64);
const BYTES_DIGEST = "b".repeat(64);
const account = privateKeyToAccount(`0x${"1".repeat(64)}`);

test("Hermes decision is exact and bound to the expected action digest", () => {
  assert.deepEqual(
    parseHermesDecision(
      JSON.stringify({ decision: "approve", actionDigest: BYTES_DIGEST, reasonCode: "POLICY_MATCH" }),
      { expectedActionDigest: BYTES_DIGEST },
    ),
    { decision: "approve", actionDigest: BYTES_DIGEST, reasonCode: "POLICY_MATCH" },
  );
  assert.throws(() => parseHermesDecision(
    JSON.stringify({ decision: "approve", actionDigest: "c".repeat(64), reasonCode: "POLICY_MATCH" }),
    { expectedActionDigest: BYTES_DIGEST },
  ));
  assert.throws(() => parseHermesDecision(
    JSON.stringify({ decision: "approve", actionDigest: BYTES_DIGEST, reasonCode: "POLICY_MATCH", extra: true }),
    { expectedActionDigest: BYTES_DIGEST },
  ));
});

test("Hermes decision prompt contains public policy facts and no transport authority", () => {
  const prompt = createHermesDecisionPrompt({
    action: { operation: "proposal", role: "initiator", sessionId: SESSION, bytesSha256: BYTES_DIGEST },
    policy: {
      role: "initiator",
      reference: "NS-1847",
      statementDigest: POLICY_DIGEST,
      maxValidForSeconds: "90",
      externalBusinessActionsAllowed: false,
      identityPolicy: {
        erc8004: "required_fresh",
        chainId: "eip155:11155111",
        registryAddress: "0x8004a818bfb912233c491871b3d84c89a494bd9e",
      },
    },
  });
  assert.match(prompt, /NS-1847/);
  assert.match(prompt, /required_fresh/);
  assert.match(prompt, new RegExp(BYTES_DIGEST));
  assert.match(prompt, /Identity claim is a prerequisite/i);
  assert.match(prompt, /registration happens only after Clockchain funds the new key/i);
  assert.match(prompt, /expected to differ from localPolicy\.statementDigest/i);
  assert.match(prompt, /never compare those two digests/i);
  assert.match(prompt, /APPROVE_POLICY_MATCH/i);
  for (const forbidden of ["roleAccess", "invitation", "privateKey", "signatureHex", "bytesGzipBase64Url"]) {
    assert.doesNotMatch(prompt, new RegExp(forbidden, "i"));
  }
});

test("Hermes decision prompt accepts only the stable four fields of an MCP signing summary", () => {
  const summary = {
    schema: "clockchain.agent-handshake-signing-summary/v1",
    bytesSha256: BYTES_DIGEST,
    operation: "proposal",
    role: "initiator",
    sessionId: SESSION,
  };
  const action = {
    bytesSha256: summary.bytesSha256,
    operation: summary.operation,
    role: summary.role,
    sessionId: summary.sessionId,
  };
  assert.doesNotThrow(() => createHermesDecisionPrompt({ action, policy: {
    role: "initiator", reference: "NS-1847", statementDigest: POLICY_DIGEST, maxValidForSeconds: "90",
    externalBusinessActionsAllowed: false,
    identityPolicy: { erc8004: "not_required", chainId: null, registryAddress: null },
  } }));
  assert.throws(() => createHermesDecisionPrompt({ action: summary, policy: {} }));
});

test("signing request is recovered exactly from the bound helper argv", () => {
  const payload = {
    schema: "clockchain.agent-handshake-signing-request/v1",
    helperVersion: "2.1.2",
    operation: "proposal",
    role: "initiator",
    sessionId: SESSION,
    policyDigest: POLICY_DIGEST,
    bytesGzipBase64Url: gzipSync(Buffer.from('{"hello":"world"}')).toString("base64url"),
    bytesSha256: BYTES_DIGEST,
  };
  const argv = [
    "node", "--input-type=commonjs", "--eval", "bootstrap", "d".repeat(64),
    "/tmp/manifest.json", "/tmp/helper.cjs", "sign", "--state-dir", "/tmp/state",
    "--payload-base64url", Buffer.from(JSON.stringify(payload)).toString("base64url"),
  ];
  assert.deepEqual(extractSigningRequestFromArgv(argv), payload);
  assert.throws(() => extractSigningRequestFromArgv(argv.slice(0, -1)));
});

test("proposal checkpoint binds the exact signed envelope to the same role key", async () => {
  const artifactPayload = {
    schema: "clockchain.agent-handshake-proposal/v2",
    protocol: "clockchain.agent-handshake/v2",
    sessionId: SESSION,
    reference: "NS-1847",
  };
  const artifactSignatureHex = await account.signMessage({ message: { raw: "0x1234" } });
  const checkpoint = await createCommitmentCheckpoint({
    artifactPayload,
    artifactSignatureHex,
    artifactType: "proposal",
    nowMs: 1_786_000_000_000,
    previousCheckpoint: null,
    role: "initiator",
    sessionId: SESSION,
    signerAddress: account.address.toLowerCase(),
    signMessage: ({ raw }) => account.signMessage({ message: { raw } }),
  });
  const envelope = {
    payload: artifactPayload,
    schema: "clockchain.agent-handshake-proposal-envelope/v2",
    signature: { address: account.address.toLowerCase(), algorithm: "eip191", value: artifactSignatureHex },
  };
  assert.equal(checkpoint.artifactDigest, digestHex(envelope));
  assert.equal(checkpoint.sequence, "1");
  assert.equal(checkpoint.previousCheckpointDigest, null);
  assert.match(commitmentCheckpointDigest(checkpoint), /^[0-9a-f]{64}$/);
  assert.equal(
    await recoverMessageAddress({
      message: { raw: `0x${commitmentCheckpointSigningBytes(checkpoint).toString("hex")}` },
      signature: checkpoint.signature.value,
    }),
    account.address,
  );
});

test("acceptance checkpoint chains to the proposal checkpoint", async () => {
  const proposal = Object.freeze({
    schema: "clockchain.agent-handshake-commitment-checkpoint/v1",
    version: "1",
    protocol: "clockchain.agent-handshake/v2",
    sessionId: SESSION,
    role: "initiator",
    artifactType: "proposal",
    artifactDigest: "d".repeat(64),
    sequence: "1",
    previousCheckpointDigest: null,
    issuedAtMs: "1786000000000",
    expiresAtMs: "1786000060000",
    signerAddress: account.address.toLowerCase(),
    signature: { address: account.address.toLowerCase(), algorithm: "eip191", value: `0x${"1".repeat(130)}` },
  });
  const signature = await account.signMessage({ message: { raw: "0x5678" } });
  const checkpoint = await createCommitmentCheckpoint({
    artifactPayload: { schema: "clockchain.agent-handshake-acceptance/v2", sessionId: SESSION },
    artifactSignatureHex: signature,
    artifactType: "acceptance",
    nowMs: 1_786_000_001_000,
    previousCheckpoint: proposal,
    role: "responder",
    sessionId: SESSION,
    signerAddress: account.address.toLowerCase(),
    signMessage: ({ raw }) => account.signMessage({ message: { raw } }),
  });
  assert.equal(checkpoint.sequence, "2");
  assert.equal(checkpoint.previousCheckpointDigest, commitmentCheckpointDigest(proposal));
});

test("Hermes role config exposes only the production handshake endpoint and eight tools", () => {
  const config = buildHermesConfig();
  assert.deepEqual(Object.keys(config.mcp_servers), ["clockchain"]);
  assert.equal(config.mcp_servers.clockchain.url, "https://mcp.clockchain.network/handshake/mcp");
  assert.deepEqual(config.mcp_servers.clockchain.tools.include, CLOCKCHAIN_V2_TOOLS);
  assert.equal(config.mcp_servers.clockchain.tools.prompts, false);
  assert.equal(config.mcp_servers.clockchain.tools.resources, false);
  assert.deepEqual(config.fallback_providers, []);
  assert.deepEqual(config.memory, { memory_enabled: false, user_profile_enabled: false });
});

test("Hermes invocation is K3, ignores rules, and inherits only the explicit role environment", () => {
  const invocation = buildHermesInvocation({
    cache: "/private/tmp/run/responder/cache",
    hermesHome: "/private/tmp/run/responder/hermes",
    home: "/private/tmp/run/responder/home",
    providerSecret: "provider-secret-canary",
    prompt: "decide",
    tmp: "/private/tmp/run/responder/tmp",
    usageFile: "/private/tmp/run/responder/usage.json",
    workspace: "/private/tmp/run/responder/workspace",
  });
  assert.deepEqual(invocation.args, [
    "-z", "decide", "--provider", "kimi-coding", "-m", "k3", "-t", "file",
    "--ignore-rules", "--usage-file", "/private/tmp/run/responder/usage.json",
  ]);
  assert.equal(invocation.cwd, "/private/tmp/run/responder/workspace");
  assert.equal(invocation.env.KIMI_API_KEY, "provider-secret-canary");
  assert.equal(invocation.env.HERMES_HOME, "/private/tmp/run/responder/hermes");
  assert.equal(invocation.env.HOME, "/private/tmp/run/responder/home");
  assert.equal(Object.hasOwn(invocation.env, "ANTHROPIC_API_KEY"), false);
  assert.equal(Object.hasOwn(invocation.env, "OPENAI_API_KEY"), false);
});

test("native streamable MCP client initializes, lists, and parses tool content", async () => {
  const methods = [];
  const fetchImpl = async (_url, options) => {
    const request = JSON.parse(options.body);
    methods.push(request.method);
    if (request.method === "notifications/initialized") {
      return new Response(null, { status: 202 });
    }
    const result = request.method === "initialize"
      ? { protocolVersion: "2025-06-18", capabilities: { tools: {} }, serverInfo: { name: "test", version: "1" } }
      : request.method === "tools/list"
        ? { tools: CLOCKCHAIN_V2_TOOLS.map((name) => ({ name })) }
        : { content: [{ type: "text", text: JSON.stringify({ ok: true, stage: "party_ready" }) }] };
    return new Response(`event: message\ndata: ${JSON.stringify({ jsonrpc: "2.0", id: request.id, result })}\n\n`, {
      status: 200,
      headers: { "content-type": "text/event-stream" },
    });
  };
  const client = createStreamableMcpClient({ endpoint: "https://example.test/mcp", fetchImpl });
  await client.connect();
  assert.deepEqual(await client.listTools(), CLOCKCHAIN_V2_TOOLS);
  assert.deepEqual(await client.callTool("agent_handshake_status", { access: "opaque" }), { ok: true, stage: "party_ready" });
  assert.deepEqual(methods, ["initialize", "notifications/initialized", "tools/list", "tools/call"]);
});

test("native streamable MCP client rejects a hung transport before the live deadline", async () => {
  let aborted = false;
  const client = createStreamableMcpClient({
    endpoint: "https://example.test/mcp",
    fetchImpl: async (_url, { signal }) => new Promise((_, reject) => signal.addEventListener("abort", () => { aborted = true; reject(new Error("aborted")); }, { once: true })),
    requestTimeoutMs: 5,
  });
  await assert.rejects(() => client.connect(), /failed safely/);
  assert.equal(aborted, true);
});

test("native streamable MCP client preserves public MCP unavailability as a typed failure", async () => {
  const fetchImpl = async (_url, options) => {
    const request = JSON.parse(options.body);
    if (request.method === "notifications/initialized") return new Response(null, { status: 202 });
    const result = request.method === "initialize"
      ? { protocolVersion: "2025-06-18", capabilities: {}, serverInfo: { name: "test", version: "1" } }
      : request.method === "tools/list"
        ? { tools: CLOCKCHAIN_V2_TOOLS.map((name) => ({ name })) }
        : { content: [{ type: "text", text: JSON.stringify({ error: "HANDSHAKE_UNAVAILABLE", retryable: false }) }], isError: true };
    return new Response(`data: ${JSON.stringify({ jsonrpc: "2.0", id: request.id, result })}\n\n`, {
      status: 200,
      headers: { "content-type": "text/event-stream" },
    });
  };
  const client = createStreamableMcpClient({ endpoint: "https://example.test/mcp", fetchImpl });
  await client.connect();
  await client.listTools();
  await assert.rejects(
    () => client.callTool("agent_handshake_invite", { reference: "NS-1847" }),
    (error) => error?.code === "MCP_TOOL_UNAVAILABLE" && error?.tool === "agent_handshake_invite",
  );
});

test("live runner opens the short invitation window only after both fresh Hermes preflights", async () => {
  const source = await readFile(new URL("../src/testing/hermes-v2-orchestrator.mjs", import.meta.url), "utf8");
  const preflight = source.indexOf('publicEvent({ event: "hermes_preflight_complete" })');
  const discovery = source.indexOf("const discovery = await waitForFreshDiscovery(deadline);");
  const invite = source.indexOf('client.callTool("agent_handshake_invite", terms)');
  assert.ok(preflight >= 0 && discovery > preflight && invite > discovery);
  assert.match(source, /MIN_INVITE_REMAINING_MS = 15_000/);
});

test("live runner uses the public roleAccess capability, never stripped private access fields", async () => {
  const source = await readFile(new URL("../src/testing/hermes-v2-orchestrator.mjs", import.meta.url), "utf8");
  const setup = source.slice(source.indexOf("async function setupAndJoin"), source.indexOf("async function reachPartyReady"));
  assert.match(setup, /agent\.access = invitationResult\.roleAccess/);
  assert.doesNotMatch(setup, /initiatorAccess|responderAccess/);
});

test("live runner uses MCP-confirmed party identities after ERC-8004 registration", async () => {
  const source = await readFile(new URL("../src/testing/hermes-v2-orchestrator.mjs", import.meta.url), "utf8");
  assert.match(source, /initiator\.identity\?\.erc8004\?\.agentId/);
  assert.match(source, /responder\.identity\?\.erc8004\?\.agentId/);
  assert.doesNotMatch(source, /initiator\.registration\.agentId|responder\.registration\.agentId/);
});

test("live CLI retains only a redacted terminal outcome record", async () => {
  const source = await readFile(new URL("../scripts/run-hermes-v2-live.mjs", import.meta.url), "utf8");
  assert.match(source, /clockchain-hermes-v2-last-result\.json/);
  assert.match(source, /mode: 0o600/);
  assert.match(source, /const record = \{ event: "production_gate_failed", code/);
});
