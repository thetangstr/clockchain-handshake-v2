import { generateKeyPairSync, randomUUID } from "node:crypto";
import { join } from "node:path";

import { createPublicClient, createWalletClient, http, parseEther } from "viem";
import { sepolia } from "viem/chains";

import * as relay from "../relay/client.mjs";
import { RPC_URL } from "../core/constants.mjs";
import { openFundingWallet } from "../core/funding/wallet.mjs";
import { ERC8004_ABI } from "../core/registration.mjs";
import { awaitRoleMessages } from "../roles/host.mjs";
import { DISCOVERY_SCHEMA, postNext } from "../roles/session.mjs";
import {
  AGENT_HANDSHAKE_REGISTRY_ADDRESS,
  agentDescriptorDigest,
  rawAgentOperatorPublicKey,
} from "./descriptor.mjs";

const DEFAULT_RELAY = "http://44.249.47.220:8080";
const DEFAULT_REPOSITORY = "https://github.com/thetangstr/clockchain-handshake-v2.git";
const DEFAULT_TERMS = Object.freeze({
  reference: "NS-1847",
  statement: "Two stakeholder agents may communicate about shipment NS-1847.",
  validForMinutes: "45",
});
const PARTY_WINDOW_MILLISECONDS = 45 * 60_000;
const FUND = parseEther("0.01");

function termsFromEnvironment(env) {
  if (!env.AGENT_HANDSHAKE_TERMS) return DEFAULT_TERMS;
  const parsed = JSON.parse(env.AGENT_HANDSHAKE_TERMS);
  if (
    parsed === null || typeof parsed !== "object" || Array.isArray(parsed) ||
    Object.keys(parsed).length !== 3 || typeof parsed.reference !== "string" ||
    typeof parsed.statement !== "string" || !/^[1-9][0-9]*$/.test(String(parsed.validForMinutes))
  ) throw new Error("AGENT_HANDSHAKE_TERMS_INVALID");
  return Object.freeze({
    reference: parsed.reference,
    statement: parsed.statement,
    validForMinutes: String(parsed.validForMinutes),
  });
}

export async function loadAgentHandshakeSession({
  env = process.env,
  now = Date.now,
  relayClient = relay,
} = {}) {
  const relayUrl = env.HANDSHAKE_RELAY ?? DEFAULT_RELAY;
  const repositorySha = env.HANDSHAKE_SHA ?? "0".repeat(40);
  if (!/^[0-9a-f]{40}$/.test(repositorySha)) throw new Error("HANDSHAKE_SHA_INVALID");
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const privateKeyPem = privateKey.export({ format: "pem", type: "pkcs8" });
  const expectedPublicKey = rawAgentOperatorPublicKey(publicKey);
  const sessionId = randomUUID();
  const issuedAtMs = now();
  const discovery = {
    schema: DISCOVERY_SCHEMA,
    sessionId,
    subjectRun: "stakeholder",
    protocolVersion: "1",
    relayUrl,
    kitRepoUrl: env.HANDSHAKE_KIT_REPO ?? DEFAULT_REPOSITORY,
    repositorySha,
    operatorPublicKey: expectedPublicKey,
    issuedAtMs: String(issuedAtMs),
    expiresAtMs: String(issuedAtMs + PARTY_WINDOW_MILLISECONDS),
    paymentMoved: false,
  };
  await relayClient.createSession({ relayUrl, sessionId, discovery });
  return Object.freeze({
    expectedPublicKey,
    keyId: env.AGENT_HANDSHAKE_KEY_ID ?? "generic-host-1",
    privateKeyPem,
    relayUrl,
    repositorySha,
    sessionId,
    terms: termsFromEnvironment(env),
  });
}

function anchorReport(message) {
  const entries = message?.body?.transitions;
  if (!Array.isArray(entries) || entries.length !== 3) throw new Error("AGENT_HANDSHAKE_ANCHORS_INVALID");
  return Object.freeze({
    receipts: Object.freeze(entries.map((entry, index) => Object.freeze({
      blockHeight: String(entry?.onChain?.blockHeight ?? ""),
      blockTimeRaw: String(entry?.blockTimeRaw ?? ""),
      digest: String(entry?.digest ?? ""),
      kind: ["proposal", "acceptance", "acknowledgment"][index],
      ledgerId: String(entry?.onChain?.ledgerId ?? ""),
    }))),
    transitions: Object.freeze(entries.map((entry) => entry.message)),
  });
}

export async function createAgentHandshakeHostPorts(session, overrides = {}) {
  const relayClient = overrides.relayClient ?? relay;
  const publicClient = overrides.publicClient ?? createPublicClient({ chain: sepolia, transport: http(RPC_URL) });
  const envelopeKey = relayClient.generateEnvelopeKeyPair?.() ?? relay.generateEnvelopeKeyPair();
  const identityMessages = {};
  let after = "0";
  let buffer = [];

  const defaultWaitForMessage = async (kind, role) => {
    const result = await awaitRoleMessages({
      after,
      buffer,
      budgetMs: PARTY_WINDOW_MILLISECONDS,
      expectedBindings: kind === "party_ready" ? { [role]: identityMessages[role] } : null,
      kind,
      relayClient,
      relayUrl: session.relayUrl,
      roles: [role],
      sessionId: session.sessionId,
      waitMs: 20_000,
    });
    after = result.after;
    buffer = result.buffer;
    const message = result.messages[role];
    if (kind === "identity_ready") identityMessages[role] = message;
    return message;
  };
  const waitForMessage = overrides.waitForMessage ?? defaultWaitForMessage;

  let walletPromise = null;
  const defaultFundSeat = async ({ address, role }) => {
    walletPromise ??= openFundingWallet({
      keystorePath: process.env.CLOCKCHAIN_FUNDING_KEYSTORE ?? join(process.cwd(), "keys/funding-wallet.json"),
    });
    const treasury = await walletPromise;
    const wallet = createWalletClient({ account: treasury.account, chain: sepolia, transport: http(RPC_URL) });
    const hash = await wallet.sendTransaction({ to: address, value: FUND });
    await publicClient.waitForTransactionReceipt({ hash, timeout: 180_000 });
    await postNext(relayClient, {
      body: { externalActionPerformed: false, funded: address.toLowerCase(), role },
      keyPair: envelopeKey,
      kind: "funding_record",
      relayUrl: session.relayUrl,
      role: "host",
      sessionId: session.sessionId,
    });
  };
  const fundSeat = overrides.fundSeat ?? defaultFundSeat;
  const defaultPostHostMessage = (kind, body) => postNext(relayClient, {
    body,
    keyPair: envelopeKey,
    kind,
    relayUrl: session.relayUrl,
    role: "host",
    sessionId: session.sessionId,
  });
  const postHostMessage = overrides.postHostMessage ?? defaultPostHostMessage;

  return Object.freeze({
    announceParties: async () => {},
    awaitAcceptance: async () => (await waitForMessage("agent_acceptance", "responder")).body.acceptanceEnvelope,
    awaitAnchors: async () => anchorReport(await waitForMessage("agent_anchor_report", "initiator")),
    awaitEvidence: async (role) => (await waitForMessage("agent_evidence", role)).body.evidenceEnvelope,
    awaitIdentity: async (role) => (await waitForMessage("identity_ready", role)).body,
    awaitPartyReady: async (role) => (await waitForMessage("party_ready", role)).body,
    awaitProposal: async () => (await waitForMessage("agent_proposal", "initiator")).body.proposalEnvelope,
    fundIdentity: fundSeat,
    publishDescriptor: async (descriptorEnvelope) => postHostMessage("agent_handshake_required", {
      descriptorEnvelope,
      externalActionPerformed: false,
      sessionDigest: agentDescriptorDigest(descriptorEnvelope.descriptor),
    }),
    publishResult: overrides.putResult ?? ((envelope) => relayClient.putResult({
      envelope,
      relayUrl: session.relayUrl,
      retryBudgetMs: 30_000,
      sessionId: session.sessionId,
    })),
    publishSnapshot: overrides.putSnapshot ?? ((snapshot) => relayClient.putSnapshot({
      relayUrl: session.relayUrl,
      retryBudgetMs: 5_000,
      sessionId: session.sessionId,
      snapshot,
    })),
    resolveOwner: overrides.resolveOwner ?? ((agentId) => publicClient.readContract({
      abi: ERC8004_ABI,
      address: AGENT_HANDSHAKE_REGISTRY_ADDRESS,
      args: [BigInt(agentId)],
      functionName: "ownerOf",
    })),
  });
}
