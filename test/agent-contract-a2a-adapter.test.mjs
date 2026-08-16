import assert from "node:assert/strict";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { verifyMessage } from "viem";
import { privateKeyToAccount } from "viem/accounts";

import {
  AGENT_CONTRACT_A2A_TOOLS,
  createAgentContractA2AAdapter,
} from "../src/testing/agent-contract-a2a-adapter.mjs";

const SESSION_ID = "11111111-2222-4333-8444-555555555555";
const CERTIFICATE_DIGEST = `0x${"a".repeat(64)}`;
const CONTINUATION_DIGEST = `0x${"7".repeat(64)}`;
const PROVIDER_KEY = `0x${"4".repeat(64)}`;
const BUYER_KEY = `0x${"5".repeat(64)}`;
const PROVIDER = privateKeyToAccount(PROVIDER_KEY);
const BUYER = privateKeyToAccount(BUYER_KEY);
const NOW = "2026-08-15T20:00:00.000Z";

async function walletFile(t, privateKey) {
  const root = await mkdtemp(join(tmpdir(), "agent-contract-wallet-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const account = privateKeyToAccount(privateKey);
  const path = join(root, "wallet.json");
  await writeFile(path, JSON.stringify({ address: account.address, privateKey }), { mode: 0o600 });
  return path;
}

function baseConfig(role, walletPath, fetchImpl, overrides = {}) {
  const account = role === "provider" ? PROVIDER : BUYER;
  return {
    role,
    baseUrl: "http://127.0.0.1:3017",
    sessionId: SESSION_ID,
    certificateDigest: CERTIFICATE_DIGEST,
    continuationDigest: CONTINUATION_DIGEST,
    address: account.address,
    erc8004AgentId: role === "provider" ? "9453" : "9452",
    partyId: role === "provider" ? "provider:proofworks" : "buyer:co",
    opportunityId: "opportunity:1",
    roleCapability: `${role}-capability-secret`,
    walletPath,
    now: () => NOW,
    fetchImpl,
    ...overrides,
  };
}

test("advertises exactly the four role-local Agent Contract tools", () => {
  assert.deepEqual(
    AGENT_CONTRACT_A2A_TOOLS.map((tool) => tool.name),
    [
      "agent_contract_discover_counterparty",
      "agent_contract_send_proposal",
      "agent_contract_read_inbox",
      "agent_contract_acknowledge_proposal",
    ],
  );
  assert.equal(new Set(AGENT_CONTRACT_A2A_TOOLS.map((tool) => tool.name)).size, 4);
  const proposalTool = AGENT_CONTRACT_A2A_TOOLS.find(
    (tool) => tool.name === "agent_contract_send_proposal",
  );
  assert.deepEqual(
    proposalTool.inputSchema.properties.formats.items.enum,
    ["json", "markdown"],
  );
  assert.equal(
    proposalTool.inputSchema.properties.verificationMethod.const,
    "checksum-and-required-sections/v1",
  );
});

test("proposal vocabulary matches the platform schema before any request is sent", async (t) => {
  const walletPath = await walletFile(t, PROVIDER_KEY);
  let requests = 0;
  const adapter = await createAgentContractA2AAdapter(
    baseConfig("provider", walletPath, async () => {
      requests += 1;
      return Response.json({});
    }),
  );

  await assert.rejects(
    adapter.callTool("agent_contract_send_proposal", {
      deliverableSummary: "Produce one evidence pack",
      formats: ["JSON", "Markdown"],
      deliveryHours: 12,
      price: "10",
      verificationMethod: "checksum-and-required-sections/v1",
    }),
    /Proposal arguments are invalid/,
  );
  assert.equal(requests, 0);
});

test("provider discovers the buyer and signs its own typed proposal", async (t) => {
  const walletPath = await walletFile(t, PROVIDER_KEY);
  const calls = [];
  const fetchImpl = async (url, init) => {
    calls.push({ url, init });
    if (String(url).endsWith("/agents/buyer/card")) {
      return Response.json({ name: "buyer-card", supportedInterfaces: [] });
    }
    const body = JSON.parse(init.body);
    return Response.json({
      id: "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
      contextId: SESSION_ID,
      status: { state: "TASK_STATE_SUBMITTED", timestamp: NOW },
      history: [body.message],
    }, { status: 201 });
  };
  const adapter = await createAgentContractA2AAdapter(baseConfig("provider", walletPath, fetchImpl));

  const card = await adapter.callTool("agent_contract_discover_counterparty", {});
  assert.equal(card.name, "buyer-card");
  const task = await adapter.callTool("agent_contract_send_proposal", {
    deliverableSummary: "Produce one signed JSON and Markdown evidence pack",
    formats: ["json", "markdown"],
    deliveryHours: 12,
    price: "10",
    verificationMethod: "checksum-and-required-sections/v1",
  });

  assert.equal(calls.length, 2);
  assert.equal(calls[0].url, `http://127.0.0.1:3017/api/a2a/sessions/${SESSION_ID}/agents/buyer/card`);
  assert.equal(calls[0].init.headers.authorization, "Bearer provider-capability-secret");
  assert.equal(calls[1].url.endsWith(`/agents/buyer/message:send`), true);
  assert.equal(calls[1].init.headers["content-type"], "application/a2a+json");
  const message = task.history[0];
  assert.equal(message.metadata.clockchainTrust.senderAddress, PROVIDER.address);
  assert.equal(message.metadata.clockchainTrust.senderErc8004AgentId, "9453");
  assert.equal(message.metadata.clockchainTrust.continuationDigest, CONTINUATION_DIGEST);
  assert.equal(message.parts[0].data.proposal.providerPartyId, "provider:proofworks");
  const { signature, ...unsignedBinding } = message.metadata.clockchainTrust;
  assert.equal(await verifyMessage({
    address: PROVIDER.address,
    message: adapter.canonicalJson({
      ...unsignedBinding,
      messageId: message.messageId,
      contextId: message.contextId,
    }),
    signature,
  }), true);
  assert.equal(JSON.stringify(task).includes(PROVIDER_KEY), false);
  assert.equal(JSON.stringify(task).includes("provider-capability-secret"), false);
});

test("buyer derives a nonbinding acknowledgment from the exact stored proposal", async (t) => {
  const walletPath = await walletFile(t, BUYER_KEY);
  const proposalMessage = {
    messageId: "99999999-aaaa-4bbb-8ccc-dddddddddddd",
    contextId: SESSION_ID,
    role: "ROLE_USER",
    parts: [{ data: { kind: "firm_proposal", proposal: {
      schema: "agent-contract/v1",
      proposalId: "proposal:stored",
      opportunityId: "opportunity:1",
      providerPartyId: "provider:proofworks",
      deliverableSummary: "Produce one evidence pack",
      formats: ["json"],
      deliveryHours: 12,
      price: "10",
      verificationMethod: "checksum-and-required-sections/v1",
      predecessorDigest: null,
    } } }],
    metadata: { clockchainTrust: {
      schema: "agent-contract.a2a-trust-binding/v1",
      sessionId: SESSION_ID,
      certificateDigest: CERTIFICATE_DIGEST,
      continuationDigest: CONTINUATION_DIGEST,
      senderRole: "provider",
      senderAddress: PROVIDER.address,
      senderErc8004AgentId: "9453",
      recipientRole: "buyer",
      objectDigest: `0x${"b".repeat(64)}`,
      predecessorMessageDigest: null,
      authorityDecisionDigest: `0x${"c".repeat(64)}`,
      sentAt: NOW,
      signature: `0x${"d".repeat(130)}`,
    } },
  };
  const proposalTask = {
    id: "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
    contextId: SESSION_ID,
    status: { state: "TASK_STATE_SUBMITTED", timestamp: NOW },
    history: [proposalMessage],
  };
  const fetchImpl = async (url, init) => {
    if (String(url).endsWith("/agents/buyer/inbox")) return Response.json([proposalTask]);
    const body = JSON.parse(init.body);
    return Response.json({
      id: "bbbbbbbb-cccc-4ddd-8eee-ffffffffffff",
      contextId: SESSION_ID,
      status: { state: "TASK_STATE_COMPLETED", timestamp: NOW },
      history: [body.message],
    }, { status: 201 });
  };
  const adapter = await createAgentContractA2AAdapter(baseConfig("buyer", walletPath, fetchImpl));

  const task = await adapter.callTool("agent_contract_acknowledge_proposal", {
    taskId: proposalTask.id,
    decision: "received_for_review",
  });

  const acknowledgment = task.history[0];
  assert.equal(acknowledgment.parts[0].data.binding, false);
  assert.equal(acknowledgment.parts[0].data.decision, "received_for_review");
  assert.equal(acknowledgment.metadata.clockchainTrust.senderAddress, BUYER.address);
  assert.equal(
    acknowledgment.metadata.clockchainTrust.predecessorMessageDigest,
    adapter.canonicalDigest(proposalMessage),
  );
  assert.equal(
    acknowledgment.parts[0].data.proposalDigest,
    adapter.canonicalDigest(proposalMessage.parts[0].data.proposal),
  );
});

test("rejects wrong-role tools, arbitrary origins, wallet substitution, and unsafe HTTP errors", async (t) => {
  const providerWallet = await walletFile(t, PROVIDER_KEY);
  const buyerWallet = await walletFile(t, BUYER_KEY);
  const provider = await createAgentContractA2AAdapter(baseConfig("provider", providerWallet, async () => Response.json([])));
  const buyer = await createAgentContractA2AAdapter(baseConfig("buyer", buyerWallet, async () => Response.json([])));

  await assert.rejects(
    provider.callTool("agent_contract_acknowledge_proposal", { taskId: SESSION_ID, decision: "received_for_review" }),
    /role/i,
  );
  await assert.rejects(
    buyer.callTool("agent_contract_send_proposal", {}),
    /role/i,
  );
  await assert.rejects(
    createAgentContractA2AAdapter(baseConfig("provider", providerWallet, async () => Response.json([]), {
      baseUrl: "https://example.com",
    })),
    /loopback/i,
  );
  await assert.rejects(
    createAgentContractA2AAdapter(baseConfig("provider", buyerWallet, async () => Response.json([]))),
    /wallet/i,
  );

  const secretBody = "server-secret-body-must-not-escape";
  const failing = await createAgentContractA2AAdapter(baseConfig("provider", providerWallet, async () => new Response(secretBody, { status: 500 })));
  await assert.rejects(
    failing.callTool("agent_contract_discover_counterparty", {}),
    (error) => error instanceof Error && error.message.includes("500") && !error.message.includes(secretBody),
  );
});
