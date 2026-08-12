import assert from "node:assert/strict";
import { mkdir, mkdtemp, readFile, stat, symlink } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ReadableStream } from "node:stream/web";
import test from "node:test";

import { parseFargateRunnerArgs, checkProductionMcpGate, retainFargateSuccessEvidence, waitProductionInvitationWindow } from "../scripts/run-mechanics-proof-fargate.mjs";

function bodyResponse(body, { contentType = "application/json", contentLength = null } = {}) {
  const bytes = new TextEncoder().encode(body);
  return {
    ok: true,
    headers: {
      get(name) {
        if (name.toLowerCase() === "content-type") return contentType;
        if (name.toLowerCase() === "content-length") return contentLength;
        return null;
      },
    },
    body: new ReadableStream({
      start(controller) {
        controller.enqueue(bytes);
        controller.close();
      },
    }),
    text: async () => { throw new Error("unbounded text reader must not be used"); },
  };
}

test("Fargate runner --run requires explicit live gate inputs", () => {
  const parsed = parseFargateRunnerArgs([
    "node",
    "scripts/run-mechanics-proof-fargate.mjs",
    "--run",
    "--account", "123456789012",
    "--region", "us-west-2",
    "--run-id", "11111111-2222-4333-8444-555555555555",
    "--vpc-id", "vpc-live",
    "--public-subnet-id", "subnet-public",
    "--initiator-private-cidr", "10.44.16.0/24",
    "--initiator-az", "us-west-2a",
    "--responder-private-cidr", "10.44.17.0/24",
    "--responder-az", "us-west-2b",
    "--codex-secret-arn", "arn:aws:secretsmanager:us-west-2:123456789012:secret:clockchain/codex-AbCdEf",
    "--image", `123456789012.dkr.ecr.us-west-2.amazonaws.com/clockchain-mechanics-proof@sha256:${"6".repeat(64)}`,
    "--evidence-dir", "/private/tmp/mechanics-proof-fargate",
    "--ttl-seconds", "3600",
    "--budget-usd", "25",
    "--mcp-url", "https://mcp.clockchain.network/handshake/mcp",
  ]);

  assert.equal(parsed.mode, "run");
  assert.equal(parsed.accountId, "123456789012");
  assert.equal(parsed.maxConcurrency, 2);
  assert.equal(parsed.bedrockModelArn, "arn:aws:bedrock:us-west-2:123456789012:inference-profile/us.anthropic.claude-sonnet-4-6");
});

test("Fargate runner binds AWS control-plane StackId validation to the requested account", async () => {
  const source = await readFile(new URL("../scripts/run-mechanics-proof-fargate.mjs", import.meta.url), "utf8");
  assert.match(source, /createAwsCliControlPlane\(\{\s*region: parsed\.region,\s*accountId: parsed\.accountId\s*\}\)/);
});

test("Fargate runner rejects missing run gates and dry-run/run ambiguity", () => {
  assert.throws(() => parseFargateRunnerArgs(["node", "script", "--run", "--account", "123456789012"]), /Fargate mechanics proof runner failed safely/);
  assert.throws(() => parseFargateRunnerArgs(["node", "script", "--run", "--dry-run"]), /Fargate mechanics proof runner failed safely/);
  assert.throws(() => parseFargateRunnerArgs(["node", "script", "--run", "--ttl-seconds", "3601"]), /Fargate mechanics proof runner failed safely/);
});

test("Fargate runner preserves dry-run mode and has no import side effect", () => {
  assert.deepEqual(parseFargateRunnerArgs(["node", "script", "--dry-run"]), { mode: "dry-run" });
});

test("production MCP gate accepts bounded JSON or one SSE message with exact eight tools", async () => {
  const tools = [
    "agent_handshake_accept_invitation",
    "agent_handshake_get_certificate",
    "agent_handshake_invite",
    "agent_handshake_join",
    "agent_handshake_next",
    "agent_handshake_status",
    "agent_handshake_submit",
    "agent_handshake_submit_checkpoint",
  ].sort();
  let jsonCalls = 0;
  const jsonGate = await checkProductionMcpGate({
    url: "https://mcp.clockchain.network/handshake/mcp",
    fetch: async (url, options) => {
      jsonCalls += 1;
      assert.equal(options.redirect, "error");
      assert.equal("authorization" in Object.fromEntries(Object.entries(options.headers).map(([key, value]) => [key.toLowerCase(), value])), false);
      if (url === "https://mcp.clockchain.network/health") {
        assert.equal(options.method, "GET");
        return bodyResponse(JSON.stringify({ status: "ok" }));
      }
      assert.equal(url, "https://mcp.clockchain.network/handshake/mcp");
      const body = JSON.parse(options.body);
      return bodyResponse(JSON.stringify(body.method === "initialize"
        ? (assert.equal(body.params.protocolVersion, "2025-06-18"), { jsonrpc: "2.0", id: "clockchain-fargate-initialize", result: { serverInfo: { name: "clockchain-agent-handshake", version: "2.1.2" }, protocolVersion: "2025-06-18" } })
        : { jsonrpc: "2.0", id: "clockchain-fargate-tools/list", result: { tools: tools.map((name) => ({ name })) } }));
    },
  });
  assert.equal(jsonGate.healthy, true);
  assert.equal(jsonGate.checkpointTool, true);
  assert.equal(jsonCalls, 3);

  let sseCalls = 0;

  const sseGate = await checkProductionMcpGate({
    url: "https://mcp.clockchain.network/handshake/mcp",
    fetch: async (url, options) => {
      sseCalls += 1;
      if (url === "https://mcp.clockchain.network/health") {
        return bodyResponse(JSON.stringify({ status: "ok" }));
      }
      const body = JSON.parse(options.body);
      return bodyResponse(`event: message\ndata: ${JSON.stringify(body.method === "initialize"
        ? { jsonrpc: "2.0", id: "clockchain-fargate-initialize", result: { serverInfo: { name: "clockchain-agent-handshake", version: "2.1.2" }, protocolVersion: "2025-06-18" } }
        : { jsonrpc: "2.0", id: "clockchain-fargate-tools/list", result: { tools: tools.map((name) => ({ name })) } })}\n\n`, { contentType: "text/event-stream" });
    },
  });
  assert.equal(sseGate.healthy, true);
  assert.equal(sseCalls, 3);
});

test("production invitation gate waits for a newly opened public discovery window before task launch", async () => {
  let now = 1_000_000;
  let calls = 0;
  const discovery = (invitationExpiresAtMs) => ({
    schema: "clockchain.agent-handshake-discovery/v2",
    protocol: "clockchain.agent-handshake/v2",
    sessionId: "11111111-2222-4333-8444-555555555555",
    repositorySha: "a".repeat(40),
    kitRepoUrl: "https://github.com/thetangstr/clockchain-handshake-v2",
    relayUrl: "http://44.249.47.220:8080",
    createdAtMs: "900000",
    invitationExpiresAtMs: String(invitationExpiresAtMs),
    sessionDeadlineMs: "1600000",
    hostSessionKeyCertificate: {},
    sessionOpenedBlock: "11476230",
    externalBusinessActionPerformed: false,
  });
  const result = await waitProductionInvitationWindow({
    deadlineMs: 1_300_000,
    minimumRemainingMs: 90_000,
    now: () => now,
    sleep: async (ms) => { assert.equal(ms, 2000); now += ms; },
    fetch: async (url, options) => {
      calls += 1;
      assert.equal(url, "http://44.249.47.220:8080/v1/discovery/current");
      assert.equal(options.method, "GET");
      return bodyResponse(JSON.stringify(discovery(calls === 1 ? 1_080_000 : 1_120_000)));
    },
  });
  assert.deepEqual(result, { ready: true });
  assert.equal(calls, 2);
});

test("production MCP gate rejects seven-tool deployment and unsafe response forms", async () => {
  const sevenTools = [
    "agent_handshake_get_agent",
    "agent_handshake_invite",
    "agent_handshake_join",
    "agent_handshake_next",
    "agent_handshake_status",
    "agent_handshake_submit",
    "agent_handshake_get_certificate",
  ];
  let call = 0;
  await assert.rejects(() => checkProductionMcpGate({
    url: "https://mcp.clockchain.network/handshake/mcp",
    fetch: async () => {
      call += 1;
      if (call === 1) return bodyResponse(JSON.stringify({ status: "ok" }));
      return bodyResponse(`event: message\ndata: ${JSON.stringify(call === 2
        ? { jsonrpc: "2.0", id: "clockchain-fargate-initialize", result: { serverInfo: { name: "clockchain-agent-handshake", version: "2.1.2" }, protocolVersion: "2025-06-18" } }
        : { jsonrpc: "2.0", id: "clockchain-fargate-tools/list", result: { tools: sevenTools.map((name) => ({ name })) } })}\n\n`, { contentType: "text/event-stream" });
    },
  }), /Fargate mechanics proof runner failed safely/);

  await assert.rejects(() => checkProductionMcpGate({
    url: "https://evil.example.test/mcp",
    fetch: async () => { throw new Error("must not fetch"); },
  }), /Fargate mechanics proof runner failed safely/);
});

test("production MCP gate rejects oversized, ambiguous, timed out, and hostile responses", async () => {
  const okHealth = bodyResponse(JSON.stringify({ status: "ok" }));
  const init = { jsonrpc: "2.0", id: "clockchain-fargate-initialize", result: { serverInfo: { name: "clockchain-agent-handshake", version: "2.1.2" }, protocolVersion: "2025-06-18" } };
  const tools = { jsonrpc: "2.0", id: "clockchain-fargate-tools/list", result: { tools: [
    "agent_handshake_accept_invitation", "agent_handshake_get_certificate", "agent_handshake_invite", "agent_handshake_join",
    "agent_handshake_next", "agent_handshake_status", "agent_handshake_submit", "agent_handshake_submit_checkpoint",
  ].map((name) => ({ name })) } };
  for (const bad of [
    bodyResponse("{}", { contentLength: "200000" }),
    bodyResponse("x".repeat(140_000)),
    bodyResponse(`event: message\ndata: ${JSON.stringify(init)}\n\nevent: message\ndata: ${JSON.stringify(init)}\n\n`, { contentType: "text/event-stream" }),
    bodyResponse(`event: message\ndata: ${JSON.stringify(init)}\ndata: ${JSON.stringify(init)}\n\n`, { contentType: "text/event-stream" }),
  ]) {
    let call = 0;
    await assert.rejects(() => checkProductionMcpGate({
      url: "https://mcp.clockchain.network/handshake/mcp",
      fetch: async () => (++call === 1 ? okHealth : bad),
    }), /Fargate mechanics proof runner failed safely/);
  }
  for (const toolNames of [
    [...tools.result.tools.map((tool) => tool.name), "agent_handshake_submit_checkpoint"],
    [...tools.result.tools.map((tool) => tool.name), "agent_handshake_unknown"],
  ]) {
    let call = 0;
    await assert.rejects(() => checkProductionMcpGate({
      url: "https://mcp.clockchain.network/handshake/mcp",
      fetch: async () => {
        call += 1;
        if (call === 1) return okHealth;
        if (call === 2) return bodyResponse(JSON.stringify(init));
        return bodyResponse(JSON.stringify({ ...tools, result: { tools: toolNames.map((name) => ({ name })) } }));
      },
    }), /Fargate mechanics proof runner failed safely/);
  }
  let idCall = 0;
  await assert.rejects(() => checkProductionMcpGate({
    url: "https://mcp.clockchain.network/handshake/mcp",
    fetch: async () => {
      idCall += 1;
      if (idCall === 1) return okHealth;
      if (idCall === 2) return bodyResponse(JSON.stringify({ ...init, id: "wrong" }));
      return bodyResponse(JSON.stringify(tools));
    },
  }), /Fargate mechanics proof runner failed safely/);
  await assert.rejects(() => checkProductionMcpGate({
    url: "https://mcp.clockchain.network/handshake/mcp",
    fetch: async () => { throw new DOMException("timed out", "TimeoutError"); },
  }), /Fargate mechanics proof runner failed safely/);
});

test("production MCP gate reads response bodies through a capped stream and rejects malformed lengths", async () => {
  const init = { jsonrpc: "2.0", id: "clockchain-fargate-initialize", result: { serverInfo: { name: "clockchain-agent-handshake", version: "2.1.2" }, protocolVersion: "2025-06-18" } };
  const tools = { jsonrpc: "2.0", id: "clockchain-fargate-tools/list", result: { tools: [
    "agent_handshake_accept_invitation", "agent_handshake_get_certificate", "agent_handshake_invite", "agent_handshake_join",
    "agent_handshake_next", "agent_handshake_status", "agent_handshake_submit", "agent_handshake_submit_checkpoint",
  ].map((name) => ({ name })) } };
  let call = 0;
  const result = await checkProductionMcpGate({
    url: "https://mcp.clockchain.network/handshake/mcp",
    fetch: async () => {
      call += 1;
      if (call === 1) return bodyResponse(JSON.stringify({ status: "ok" }));
      if (call === 2) return bodyResponse(JSON.stringify(init));
      return bodyResponse(JSON.stringify(tools));
    },
  });
  assert.equal(result.healthy, true);

  await assert.rejects(() => checkProductionMcpGate({
    url: "https://mcp.clockchain.network/handshake/mcp",
    fetch: async () => bodyResponse(JSON.stringify({ status: "ok" }), { contentLength: "abc" }),
  }), /Fargate mechanics proof runner failed safely/);

  await assert.rejects(() => checkProductionMcpGate({
    url: "https://mcp.clockchain.network/handshake/mcp",
    fetch: async () => bodyResponse("x".repeat(131_073)),
  }), /Fargate mechanics proof runner failed safely/);
});

test("retained success evidence uses private exclusive directory and file modes", async () => {
  const root = await mkdtemp(join(tmpdir(), "mechanics-proof-test-"));
  const dir = join(root, "mechanics-proof-fargate");
  const bundle = {
    controllerEvidence: { schema: "clockchain.fargate-live-controller-evidence/v1", ok: true },
    publicProof: { schema: "clockchain.mechanics-proof-cloud-evidence/v1", ok: true },
  };
  await retainFargateSuccessEvidence(dir, bundle);
  assert.equal((await stat(dir)).mode & 0o777, 0o700);
  assert.equal((await stat(join(dir, "controller-evidence.json"))).mode & 0o777, 0o600);
  assert.equal((await stat(join(dir, "public-proof.json"))).mode & 0o777, 0o600);
  await assert.rejects(() => retainFargateSuccessEvidence(dir, bundle), /Fargate mechanics proof runner failed safely/);
  assert.deepEqual(JSON.parse(await readFile(join(dir, "controller-evidence.json"), "utf8")), bundle.controllerEvidence);
  assert.deepEqual(JSON.parse(await readFile(join(dir, "public-proof.json"), "utf8")), bundle.publicProof);
});

test("retained success evidence rejects unsafe evidence paths", async () => {
  const root = await mkdtemp(join(tmpdir(), "mechanics-proof-test-"));
  const symlinkPath = join(root, "mechanics-proof-link");
  await symlink(tmpdir(), symlinkPath);
  await mkdir(join(root, "mechanics-proof-permissive"), { mode: 0o755 });
  for (const dir of [
    "relative/mechanics-proof-fargate",
    "/",
    process.env.HOME,
    symlinkPath,
    join(root, "not-mechanics-proof"),
    join(root, "mechanics-proof-permissive"),
    "/etc/mechanics-proof-fargate",
  ]) {
    await assert.rejects(() => retainFargateSuccessEvidence(dir, {
      controllerEvidence: { ok: true },
      publicProof: { ok: true },
    }), /Fargate mechanics proof runner failed safely/, dir);
  }
});
