import assert from "node:assert/strict";
import test from "node:test";

import { createAgentHandshakeCheckpointClient } from "../src/harness/agent-handshake-mcp-client.mjs";

const ACCESS = `ccra_${"A".repeat(22)}`;
const SIGNATURE = `0x${"1".repeat(128)}1b`;
const DIGEST = "d".repeat(64);
const SESSION_ID = "11111111-2222-4333-8444-555555555555";
const checkpoint = Object.freeze({
  schema: "clockchain.agent-handshake-commitment-checkpoint/v1",
  version: 1,
  protocol: "clockchain.agent-handshake/v2",
  sessionId: SESSION_ID,
  role: "initiator",
  artifactType: "proposal",
  artifactDigest: "a".repeat(64),
  sequence: "1",
  previousCheckpointDigest: null,
  issuedAtMs: "1786337000001",
  expiresAtMs: "1786337090000",
  signerAddress: "0x7564105e977516c53be337314c7e53838967bdac",
  signature: Object.freeze({ address: "0x7564105e977516c53be337314c7e53838967bdac", algorithm: "eip191", value: SIGNATURE }),
});

function successEnvelope(id = 1) {
  return {
    jsonrpc: "2.0",
    id,
    result: {
      content: [{ type: "text", text: JSON.stringify({ role: "initiator", sessionId: SESSION_ID, stage: "proposal_checkpoint_submitted", checkpointDigest: DIGEST, roleAccess: ACCESS }) }],
      structuredContent: { role: "initiator", sessionId: SESSION_ID, stage: "proposal_checkpoint_submitted", checkpointDigest: DIGEST, roleAccess: ACCESS },
    },
  };
}

function signatureSuccessEnvelope(id = 1) {
  return {
    jsonrpc: "2.0",
    id,
    result: {
      content: [{ type: "text", text: JSON.stringify({ role: "initiator", sessionId: SESSION_ID, stage: "proposal_submitted" }) }],
      structuredContent: { role: "initiator", sessionId: SESSION_ID, stage: "proposal_submitted" },
    },
  };
}

test("private checkpoint client performs one exact JSON-RPC write and accepts JSON or SSE", async () => {
  for (const sse of [false, true]) {
    const calls = [];
    const client = createAgentHandshakeCheckpointClient({
      endpoint: "https://mcp.clockchain.network/handshake/mcp",
      fetchImpl: async (url, init) => {
        calls.push({ url, init });
        const raw = JSON.stringify(successEnvelope());
        return new Response(sse ? `event: message\ndata: ${raw}\n\n` : raw, {
          status: 200,
          headers: { "content-type": sse ? "text/event-stream" : "application/json" },
        });
      },
      timeoutMs: 1_000,
    });
    const result = await client.submitCheckpoint({ access: ACCESS, artifactSignatureHex: SIGNATURE, checkpoint });
    assert.deepEqual(result, { role: "initiator", sessionId: SESSION_ID, stage: "proposal_checkpoint_submitted", checkpointDigest: DIGEST });
    assert.equal(calls.length, 1);
    assert.equal(calls[0].url, "https://mcp.clockchain.network/handshake/mcp");
    assert.deepEqual(JSON.parse(calls[0].init.body), {
      jsonrpc: "2.0",
      id: 1,
      method: "tools/call",
      params: { name: "agent_handshake_submit_checkpoint", arguments: { access: ACCESS, artifactSignatureHex: SIGNATURE, checkpoint } },
    });
    assert.equal(calls[0].init.method, "POST");
    assert.equal(calls[0].init.headers.accept, "application/json, text/event-stream");
  }
});

test("private checkpoint client never retries an ambiguous write and leaks no private input", async () => {
  for (const fetchImpl of [
    async () => { throw new Error(`${ACCESS} ${SIGNATURE}`); },
    async () => new Response("x".repeat(70_000), { status: 200 }),
    async (_url, { signal }) => await new Promise((_resolve, reject) => signal.addEventListener("abort", () => reject(new Error("aborted")), { once: true })),
  ]) {
    let calls = 0;
    const client = createAgentHandshakeCheckpointClient({
      endpoint: "https://mcp.clockchain.network/handshake/mcp",
      fetchImpl: async (...args) => { calls += 1; return fetchImpl(...args); },
      timeoutMs: 10,
    });
    await assert.rejects(
      client.submitCheckpoint({ access: ACCESS, artifactSignatureHex: SIGNATURE, checkpoint }),
      (error) => error?.message === "Clockchain checkpoint submission failed safely." && !JSON.stringify(error).includes(ACCESS) && !JSON.stringify(error).includes(SIGNATURE),
    );
    assert.equal(calls, 1);
  }
});

test("private handshake client submits one policy-bound signature without model mediation", async () => {
  const calls = [];
  const client = createAgentHandshakeCheckpointClient({
    endpoint: "https://mcp.clockchain.network/handshake/mcp",
    fetchImpl: async (url, init) => {
      calls.push({ url, init });
      return new Response(JSON.stringify(signatureSuccessEnvelope()), { status: 200 });
    },
    timeoutMs: 1_000,
  });
  const result = await client.submitSignature({ access: ACCESS, policyDigest: DIGEST, signatureHex: SIGNATURE });
  assert.deepEqual(result, { role: "initiator", sessionId: SESSION_ID, stage: "proposal_submitted" });
  assert.equal(calls.length, 1);
  assert.deepEqual(JSON.parse(calls[0].init.body), {
    jsonrpc: "2.0",
    id: 1,
    method: "tools/call",
    params: {
      name: "agent_handshake_submit",
      arguments: { access: ACCESS, policyDigest: DIGEST, signatureHex: SIGNATURE },
    },
  });
});

test("private handshake client rejects malformed signature acknowledgements without retrying", async () => {
  let calls = 0;
  const client = createAgentHandshakeCheckpointClient({
    endpoint: "https://mcp.clockchain.network/handshake/mcp",
    fetchImpl: async () => {
      calls += 1;
      const envelope = signatureSuccessEnvelope();
      envelope.result.structuredContent.stage = "unexpected";
      envelope.result.content[0].text = JSON.stringify(envelope.result.structuredContent);
      return new Response(JSON.stringify(envelope), { status: 200 });
    },
    timeoutMs: 1_000,
  });
  await assert.rejects(
    client.submitSignature({ access: ACCESS, policyDigest: DIGEST, signatureHex: SIGNATURE }),
    /Clockchain checkpoint submission failed safely/,
  );
  assert.equal(calls, 1);
});
