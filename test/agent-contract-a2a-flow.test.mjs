import assert from "node:assert/strict";
import test from "node:test";
import { getAddress } from "viem";

import {
  AgentContractA2AFlowError,
  runAgentContractA2AFlow,
} from "../src/testing/agent-contract-a2a-flow.mjs";
import { FACILITATED_A2A_AUTHORIZATION_STATEMENT } from "../src/testing/agent-contract-a2a-flow.mjs";
import { canonicalDigest } from "../src/testing/agent-contract-a2a-adapter.mjs";

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

function exchangeFixture({ mutateContinuation = (_role, value) => value } = {}) {
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
      const data = { kind: "firm_proposal", proposal: { proposalId: "proposal:live-witness" } };
      const message = {
        messageId: "cccccccc-dddd-4eee-8fff-000000000001",
        contextId: SESSION_ID,
        parts: [{ data }],
        metadata: { clockchainTrust: {
          objectDigest: canonicalDigest(data),
          predecessorMessageDigest: null,
          sentAt: "2026-08-15T20:00:04.000Z",
        } },
      };
      proposalTask = {
        id: PROPOSAL_TASK_ID,
        contextId: SESSION_ID,
        status: { timestamp: "2026-08-15T20:00:05.000Z" },
        history: [message],
      };
      return mutateContinuation(role, {
        completed: true,
        activity: { tools: ["agent_contract_discover_counterparty", "agent_contract_send_proposal"] },
        runtime: {
          client: "claude-code",
          modelId: "sonnet",
          runtimeId: "22222222-3333-4444-8555-666666666666",
          processDigest: `0x${"2".repeat(64)}`,
        },
        ledger: {
          schema: "agent-contract.a2a-authorship-ledger/v1",
          runtimeId: "22222222-3333-4444-8555-666666666666",
          entries: [
            {
              kind: "agent_card_discovered",
              toolName: "agent_contract_discover_counterparty",
              argumentsDigest: canonicalDigest({}),
              occurredAt: "2026-08-15T20:00:03.500Z",
              runtimeId: "22222222-3333-4444-8555-666666666666",
            },
            {
              kind: "proposal_authorship",
              toolName: "agent_contract_send_proposal",
              argumentsDigest: message.metadata.clockchainTrust.objectDigest,
              persistedObjectDigest: message.metadata.clockchainTrust.objectDigest,
              messageDigest: canonicalDigest(message),
              predecessorMessageDigest: null,
              authoredAt: "2026-08-15T20:00:04.000Z",
              persistedAt: "2026-08-15T20:00:05.000Z",
              runtimeId: "22222222-3333-4444-8555-666666666666",
            },
          ],
        },
      });
    } else {
      const predecessorMessageDigest = canonicalDigest(proposalTask.history[0]);
      const data = { kind: "proposal_acknowledgment", binding: false };
      const message = {
        messageId: "dddddddd-eeee-4fff-8000-000000000002",
        contextId: SESSION_ID,
        parts: [{ data }],
        metadata: { clockchainTrust: {
          objectDigest: canonicalDigest(data),
          predecessorMessageDigest,
          sentAt: "2026-08-15T20:00:06.000Z",
        } },
      };
      acknowledgmentTask = {
        id: ACK_TASK_ID,
        contextId: SESSION_ID,
        status: { timestamp: "2026-08-15T20:00:07.000Z" },
        history: [message],
      };
      return mutateContinuation(role, {
        completed: true,
        activity: { tools: ["agent_contract_read_inbox", "agent_contract_acknowledge_proposal"] },
        runtime: {
          client: "codex-cli",
          modelId: "gpt-5.6-terra",
          runtimeId: "33333333-4444-4555-8666-777777777777",
          processDigest: `0x${"3".repeat(64)}`,
        },
        ledger: {
          schema: "agent-contract.a2a-authorship-ledger/v1",
          runtimeId: "33333333-4444-4555-8666-777777777777",
          entries: [
            {
              kind: "inbox_read",
              toolName: "agent_contract_read_inbox",
              argumentsDigest: canonicalDigest({}),
              occurredAt: "2026-08-15T20:00:05.500Z",
              runtimeId: "33333333-4444-4555-8666-777777777777",
            },
            {
              kind: "acknowledgment_authorship",
              toolName: "agent_contract_acknowledge_proposal",
              argumentsDigest: message.metadata.clockchainTrust.objectDigest,
              persistedObjectDigest: message.metadata.clockchainTrust.objectDigest,
              messageDigest: canonicalDigest(message),
              predecessorMessageDigest,
              authoredAt: "2026-08-15T20:00:06.000Z",
              persistedAt: "2026-08-15T20:00:07.000Z",
              runtimeId: "33333333-4444-4555-8666-777777777777",
            },
          ],
        },
      });
    }
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
  assert.match(fixture.continuations[0].request.prompt, /both lowercase platform formats, json and markdown/);
  assert.match(fixture.continuations[0].request.prompt, /price no greater than 20/);
  assert.match(fixture.continuations[0].request.prompt, /checksum-and-required-sections\/v1/);
  assert.equal(fixture.continuations[1].request.prompt.includes("firm_proposal"), false);
  assert.match(fixture.continuations[1].request.prompt, /exact stored proposal/i);
  assert.match(fixture.continuations[1].request.prompt, /both lowercase platform formats, json and markdown/);
  assert.match(fixture.continuations[1].request.prompt, /delivered within 24 hours/);
  assert.match(fixture.continuations[1].request.prompt, /price no greater than 20/);
  assert.match(fixture.continuations[1].request.prompt, /checksum-and-required-sections\/v1/);
  assert.match(fixture.continuations[1].request.prompt, /agent_contract_read_inbox/);
  assert.match(fixture.continuations[1].request.prompt, /agent_contract_acknowledge_proposal/);
  assert.match(fixture.continuations[1].request.prompt, /do not finish until/i);
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

test("assembles the exact privacy-safe live two-runtime witness", async () => {
  const fixture = exchangeFixture();
  const times = ["2026-08-15T20:00:03.000Z", "2026-08-15T20:00:08.000Z"];
  const result = await runAgentContractA2AFlow({
    evidence: publicHandshakeEvidence(),
    continueRole: fixture.continueRole,
    baseUrl: "http://127.0.0.1:3017",
    operatorToken: "operator-secret",
    fetchImpl: fixture.fetchImpl,
    now: () => times.shift(),
    witnessSource: {
      agentContractCommit: "5058b4672ef974ea6f8138fdf6caa6a20d5f90f6",
      continuumCommit: "8c25194000000000000000000000000000000000",
    },
  });

  const witness = result.liveRuntimeWitness;
  assert.equal(witness.schema, "agent-contract.live-runtime-a2a-witness/v1");
  assert.equal(witness.mode, "fresh_live_two_runtime");
  assert.equal(witness.runtimes.buyer.client, "codex-cli");
  assert.equal(witness.runtimes.provider.client, "claude-code");
  assert.notEqual(witness.runtimes.buyer.processDigest, witness.runtimes.provider.processDigest);
  assert.deepEqual(witness.events.map((event) => event.kind), [
    "certificate_verified",
    "session_activated",
    "agent_card_discovered",
    "proposal_authored",
    "proposal_persisted_verified",
    "acknowledgment_authored",
    "acknowledgment_persisted_verified",
    "witness_completed",
  ]);
  assert.equal(
    witness.authorship.acknowledgment.predecessorMessageDigest,
    witness.authorship.proposal.messageDigest,
  );
  assert.deepEqual(new Set(Object.values(witness.acceptance)), new Set([true]));
  assert.deepEqual(witness.privacy, {
    rawTranscriptRetained: false,
    chainOfThoughtRetained: false,
    privateKeysRetained: false,
    capabilitiesRetained: false,
    bearerTokensRetained: false,
    secretScan: "PASS",
  });
  assert.equal(JSON.stringify(witness).includes("operator-secret"), false);
});

test("accepts co-timestamped certificate issuance and verification as the run boundary", async () => {
  const fixture = exchangeFixture();
  const evidence = structuredClone(publicHandshakeEvidence());
  evidence.monitor.checker.lastSeenMs = evidence.monitor.certificate.issuedAtMs;
  const times = ["2026-08-15T20:00:03.000Z", "2026-08-15T20:00:08.000Z"];

  const result = await runAgentContractA2AFlow({
    evidence,
    continueRole: fixture.continueRole,
    baseUrl: "http://127.0.0.1:3017",
    operatorToken: "operator-secret",
    fetchImpl: fixture.fetchImpl,
    now: () => times.shift(),
    witnessSource: {
      agentContractCommit: "5058b4672ef974ea6f8138fdf6caa6a20d5f90f6",
      continuumCommit: "8c25194000000000000000000000000000000000",
    },
  });

  assert.equal(result.liveRuntimeWitness.events[0].occurredAt, result.liveRuntimeWitness.startedAt);
  assert.ok(
    Date.parse(result.liveRuntimeWitness.events[1].occurredAt) >
      Date.parse(result.liveRuntimeWitness.events[0].occurredAt),
  );
});

test("rejects certificate verification before the run boundary", async () => {
  const fixture = exchangeFixture();
  const evidence = structuredClone(publicHandshakeEvidence());
  evidence.monitor.checker.lastSeenMs = evidence.monitor.certificate.issuedAtMs - 1;
  const times = ["2026-08-15T20:00:03.000Z", "2026-08-15T20:00:08.000Z"];

  await assert.rejects(
    runAgentContractA2AFlow({
      evidence,
      continueRole: fixture.continueRole,
      baseUrl: "http://127.0.0.1:3017",
      operatorToken: "operator-secret",
      fetchImpl: fixture.fetchImpl,
      now: () => times.shift(),
      witnessSource: {
        agentContractCommit: "5058b4672ef974ea6f8138fdf6caa6a20d5f90f6",
        continuumCommit: "8c25194000000000000000000000000000000000",
      },
    }),
    (error) =>
      error instanceof AgentContractA2AFlowError &&
      error.code === "A2A_WITNESS_EVENT_ORDER_INVALID",
  );
});

test("rejects runtime and authorship substitutions before witness completion", async () => {
  const mutations = [
    (role, value) => {
      if (role === "initiator") value.runtime.processDigest = `0x${"2".repeat(64)}`;
      return value;
    },
    (role, value) => {
      if (role === "responder") value.runtime.modelId = "unrecorded-model";
      return value;
    },
    (role, value) => {
      if (role === "responder") value.ledger.entries[1].persistedObjectDigest = `0x${"9".repeat(64)}`;
      return value;
    },
    (role, value) => {
      if (role === "initiator") value.ledger.entries[1].predecessorMessageDigest = `0x${"9".repeat(64)}`;
      return value;
    },
    (role, value) => {
      if (role === "responder") value.activity.tools = ["agent_contract_discover_counterparty"];
      return value;
    },
    (role, value) => {
      if (role === "responder") value.ledger.entries[1].authoredAt = "2026-08-15T20:00:03.000Z";
      return value;
    },
  ];

  for (const mutateContinuation of mutations) {
    const fixture = exchangeFixture({ mutateContinuation });
    const times = ["2026-08-15T20:00:03.000Z", "2026-08-15T20:00:08.000Z"];
    await assert.rejects(runAgentContractA2AFlow({
      evidence: publicHandshakeEvidence(),
      continueRole: fixture.continueRole,
      baseUrl: "http://127.0.0.1:3017",
      operatorToken: "operator-secret",
      fetchImpl: fixture.fetchImpl,
      now: () => times.shift(),
      witnessSource: {
        agentContractCommit: "5058b4672ef974ea6f8138fdf6caa6a20d5f90f6",
        continuumCommit: "8c25194000000000000000000000000000000000",
      },
    }), /live runtime/i);
  }
});

test("rejects unpinned witness source revisions", async () => {
  const fixture = exchangeFixture();
  const times = ["2026-08-15T20:00:03.000Z", "2026-08-15T20:00:08.000Z"];
  await assert.rejects(runAgentContractA2AFlow({
    evidence: publicHandshakeEvidence(),
    continueRole: fixture.continueRole,
    baseUrl: "http://127.0.0.1:3017",
    operatorToken: "operator-secret",
    fetchImpl: fixture.fetchImpl,
    now: () => times.shift(),
    witnessSource: {
      agentContractCommit: "dirty",
      continuumCommit: "8c25194000000000000000000000000000000000",
    },
  }), /source/i);
});

test("canonicalizes lowercase Continuum identities before validating the platform export", async () => {
  const buyerLower = "0x352d509388c88c7ff6f87127c55d96fb37bf007c";
  const providerLower = "0xa07fde46fb84f4edebe68ea01f00a1906427646d";
  const evidence = publicHandshakeEvidence();
  evidence.roles.initiator.address = buyerLower;
  evidence.roles.responder.address = providerLower;
  const fixture = exchangeFixture();
  const originalFetch = fixture.fetchImpl;
  fixture.fetchImpl = async (url, init) => {
    const response = await originalFetch(url, init);
    if (!new URL(url).pathname.endsWith("/export")) return response;
    const value = await response.json();
    value.session.participants.buyer.address = getAddress(buyerLower);
    value.session.participants.provider.address = getAddress(providerLower);
    return Response.json(value);
  };

  const result = await runAgentContractA2AFlow({
    evidence,
    continueRole: fixture.continueRole,
    baseUrl: "http://127.0.0.1:3017",
    operatorToken: "operator-secret",
    fetchImpl: fixture.fetchImpl,
    now: () => "2026-08-15T20:00:03.000Z",
  });

  assert.equal(result.identities.buyer.address, getAddress(buyerLower));
  assert.equal(result.identities.provider.address, getAddress(providerLower));
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
