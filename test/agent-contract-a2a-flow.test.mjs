import assert from "node:assert/strict";
import test from "node:test";

import { runAgentContractA2AFlow } from "../src/testing/agent-contract-a2a-flow.mjs";
import { FACILITATED_A2A_AUTHORIZATION_STATEMENT } from "../src/testing/agent-contract-a2a-flow.mjs";

const SESSION_ID = "11111111-2222-4333-8444-555555555555";
const PROPOSAL_TASK_ID = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";
const ACK_TASK_ID = "bbbbbbbb-cccc-4ddd-8eee-ffffffffffff";
const CERTIFICATE = "a".repeat(64);
const AUTHORIZATION = `0x${"7".repeat(64)}`;

function publicHandshakeEvidence() {
  return Object.freeze({
    schema: "clockchain.fresh-agent-canary-evidence/v1",
    runId: "77777777-8888-4999-8aaa-bbbbbbbbbbbb",
    release: { manifestDigest: "f".repeat(64), hostRoots: ["e".repeat(64)] },
    clients: { initiator: "codex", responder: "claude" },
    roles: {
      initiator: {
        address: `0x${"4".repeat(40)}`,
        certificateDigest: CERTIFICATE,
        certificateVerified: true,
        erc8004: { agentId: "9452", reference: "eip155:11155111:9452" },
        externalBusinessActionPerformed: false,
        policyDigest: "1".repeat(64),
        receiptIds: [
          "10000000-0000-4000-8000-000000000001",
          "10000000-0000-4000-8000-000000000002",
          "10000000-0000-4000-8000-000000000003",
        ],
        role: "initiator",
        sessionId: SESSION_ID,
      },
      responder: {
        address: `0x${"5".repeat(40)}`,
        certificateDigest: CERTIFICATE,
        certificateVerified: true,
        erc8004: { agentId: "9453", reference: "eip155:11155111:9453" },
        externalBusinessActionPerformed: false,
        policyDigest: "2".repeat(64),
        receiptIds: [
          "10000000-0000-4000-8000-000000000001",
          "10000000-0000-4000-8000-000000000002",
          "10000000-0000-4000-8000-000000000003",
        ],
        role: "responder",
        sessionId: SESSION_ID,
      },
    },
    certificateVerified: true,
    binding: {
      certificateDigest: CERTIFICATE,
      hostRootFingerprint: "e".repeat(64),
      hostSessionKeyCertificateDigest: "d".repeat(64),
      repositorySha: "c".repeat(40),
      sessionDeadlineMs: Date.parse("2026-08-15T20:01:30.000Z"),
      statementDigest: "b".repeat(64),
    },
    monitor: {
      certificate: { digest: CERTIFICATE, issuedAtMs: Date.parse("2026-08-15T20:00:00.000Z"), outcome: "VERIFIED" },
      checker: { stage: "VERIFIED", lastSeenMs: Date.parse("2026-08-15T20:00:02.000Z") },
      hostTrust: {
        rootKid: "test-root",
        rootFingerprint: "e".repeat(64),
        sessionPublicKey: "cHVibGljLWtleQ==",
        sessionKeyCertificateDigest: "d".repeat(64),
      },
      receipts: {
        proposal: { kind: "proposal", ledgerId: "10000000-0000-4000-8000-000000000001", digest: "7".repeat(64), blockHeight: "1", blockTimeRaw: "x", explorerUrl: "https://example.test/1" },
        acceptance: { kind: "acceptance", ledgerId: "10000000-0000-4000-8000-000000000002", digest: "8".repeat(64), blockHeight: "2", blockTimeRaw: "x", explorerUrl: "https://example.test/2" },
        acknowledgment: { kind: "acknowledgment", ledgerId: "10000000-0000-4000-8000-000000000003", digest: "9".repeat(64), blockHeight: "3", blockTimeRaw: "x", explorerUrl: "https://example.test/3" },
      },
      sessionId: SESSION_ID,
      terms: {
        reference: "NS-1847",
        statement: FACILITATED_A2A_AUTHORIZATION_STATEMENT,
        statementDigest: "b".repeat(64),
        validForSeconds: "90",
      },
    },
  });
}

function exchangeFixture() {
  const calls = [];
  const continuations = [];
  let proposalTask = null;
  let acknowledgmentTask = null;
  const fetchImpl = async (url, init) => {
    calls.push({ url: String(url), init });
    const path = new URL(url).pathname;
    if (path.endsWith("/activate")) {
      return Response.json({
        sessionId: SESSION_ID,
        capabilities: { buyer: "buyer-secret", provider: "provider-secret" },
        authorization: {
          digest: AUTHORIZATION,
          scope: "single_provider_proposal_nonbinding_buyer_acknowledgment",
          expiresAt: "2026-08-15T20:10:03.000Z",
        },
      });
    }
    if (path.endsWith("/agents/buyer/inbox")) return Response.json(proposalTask === null ? [] : [proposalTask]);
    if (path.endsWith("/agents/provider/inbox")) return Response.json(acknowledgmentTask === null ? [] : [acknowledgmentTask]);
    if (path.endsWith("/export")) {
      return Response.json({
        schema: "agent-contract.facilitated-a2a-export/v1",
        provenance: "live_a2a_facilitator",
        session: {
          sessionId: SESSION_ID,
          participants: {
            buyer: { address: `0x${"4".repeat(40)}`, erc8004AgentId: "9452", client: "codex" },
            provider: { address: `0x${"5".repeat(40)}`, erc8004AgentId: "9453", client: "claude" },
          },
          certificate: { digest: `0x${CERTIFICATE}` },
          authorization: { digest: AUTHORIZATION },
          tasks: [proposalTask, acknowledgmentTask],
        },
        verification: {
          identityContinuity: true,
          providerDiscoveredBuyerCard: true,
          proposalSignatureVerified: true,
          proposalAuthorityVerified: true,
          buyerAcknowledgmentVerified: true,
          predecessorBindingVerified: true,
        },
      });
    }
    return new Response(null, { status: 404 });
  };
  const continueRole = async (role, request) => {
    continuations.push({ role, request, proposalWasStored: proposalTask !== null });
    if (role === "responder") {
      proposalTask = { id: PROPOSAL_TASK_ID, contextId: SESSION_ID, history: [{ parts: [{ data: { kind: "firm_proposal" } }] }] };
    } else {
      acknowledgmentTask = { id: ACK_TASK_ID, contextId: SESSION_ID, history: [{ parts: [{ data: { kind: "proposal_acknowledgment", binding: false } }] }] };
    }
    return { completed: true };
  };
  return { calls, continuations, continueRole, fetchImpl };
}

test("activates, resumes provider then buyer, and returns a live bound export", async () => {
  const fixture = exchangeFixture();
  const result = await runAgentContractA2AFlow({
    evidence: publicHandshakeEvidence(),
    continueRole: fixture.continueRole,
    baseUrl: "http://127.0.0.1:3017",
    operatorToken: "operator-secret",
    fetchImpl: fixture.fetchImpl,
    now: () => "2026-08-15T20:00:03.000Z",
  });

  assert.equal(fixture.continuations[0].role, "responder");
  assert.equal(fixture.continuations[1].role, "initiator");
  assert.equal(fixture.continuations[1].proposalWasStored, true);
  assert.match(fixture.continuations[0].request.prompt, /independently choose/i);
  assert.equal(fixture.continuations[1].request.prompt.includes("firm_proposal"), false);
  assert.match(fixture.continuations[1].request.prompt, /exact stored proposal/i);
  assert.equal(fixture.continuations[0].request.environment.AGENT_CONTRACT_A2A_ROLE_TOKEN, "provider-secret");
  assert.equal(fixture.continuations[0].request.environment.AGENT_CONTRACT_A2A_CONTINUATION_DIGEST, AUTHORIZATION);
  assert.equal(fixture.continuations[1].request.environment.AGENT_CONTRACT_A2A_ROLE_TOKEN, "buyer-secret");
  assert.equal(fixture.continuations[0].request.environment.AGENT_CONTRACT_A2A_ADDRESS, `0x${"5".repeat(40)}`);
  assert.equal(fixture.continuations[1].request.environment.AGENT_CONTRACT_A2A_ADDRESS, `0x${"4".repeat(40)}`);
  assert.deepEqual(result, {
    schema: "agent-contract.facilitated-a2a-result/v1",
    provenance: "live_a2a_facilitator",
    sessionId: SESSION_ID,
    clients: { buyer: "codex", provider: "claude" },
    identities: {
      buyer: { address: `0x${"4".repeat(40)}`, erc8004AgentId: "9452" },
      provider: { address: `0x${"5".repeat(40)}`, erc8004AgentId: "9453" },
    },
    certificateDigest: `0x${CERTIFICATE}`,
    continuationDigest: AUTHORIZATION,
    proposalTaskId: PROPOSAL_TASK_ID,
    acknowledgmentTaskId: ACK_TASK_ID,
    verification: {
      identityContinuity: true,
      providerDiscoveredBuyerCard: true,
      proposalSignatureVerified: true,
      proposalAuthorityVerified: true,
      buyerAcknowledgmentVerified: true,
      predecessorBindingVerified: true,
    },
  });
  assert.equal(JSON.stringify(result).includes("operator-secret"), false);
  assert.equal(JSON.stringify(result).includes("provider-secret"), false);
  assert.equal(JSON.stringify(result).includes("buyer-secret"), false);
});

test("does not resume buyer if provider continuation fails", async () => {
  const fixture = exchangeFixture();
  const seen = [];
  await assert.rejects(runAgentContractA2AFlow({
    evidence: publicHandshakeEvidence(),
    continueRole: async (role) => { seen.push(role); throw new Error("provider failed"); },
    baseUrl: "http://127.0.0.1:3017",
    operatorToken: "operator-secret",
    fetchImpl: fixture.fetchImpl,
    now: () => "2026-08-15T20:00:03.000Z",
  }), /provider failed/);
  assert.deepEqual(seen, ["responder"]);
});

test("refuses to prompt the buyer unless Agent Contract stored exactly one proposal", async () => {
  const fixture = exchangeFixture();
  const roles = [];
  await assert.rejects(runAgentContractA2AFlow({
    evidence: publicHandshakeEvidence(),
    continueRole: async (role) => { roles.push(role); },
    baseUrl: "http://127.0.0.1:3017",
    operatorToken: "operator-secret",
    fetchImpl: fixture.fetchImpl,
    now: () => "2026-08-15T20:00:03.000Z",
  }), /store exactly one proposal/i);
  assert.deepEqual(roles, ["responder"]);
});

test("fails the extension when the final export changes identity or provenance", async () => {
  for (const mode of ["fixture", "identity"]) {
    const fixture = exchangeFixture();
    const originalFetch = fixture.fetchImpl;
    fixture.fetchImpl = async (url, init) => {
      const response = await originalFetch(url, init);
      if (!new URL(url).pathname.endsWith("/export")) return response;
      const value = await response.json();
      if (mode === "fixture") value.provenance = "fixture_a2a_facilitator";
      else value.session.participants.provider.address = `0x${"6".repeat(40)}`;
      return Response.json(value);
    };
    await assert.rejects(runAgentContractA2AFlow({
      evidence: publicHandshakeEvidence(),
      continueRole: fixture.continueRole,
      baseUrl: "http://127.0.0.1:3017",
      operatorToken: "operator-secret",
      fetchImpl: fixture.fetchImpl,
      now: () => "2026-08-15T20:00:03.000Z",
    }), /export/i);
  }
});
