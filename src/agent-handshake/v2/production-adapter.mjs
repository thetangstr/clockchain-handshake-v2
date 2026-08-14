import { generateKeyPairSync, randomUUID } from "node:crypto";

import {
  createPublicClient,
  createWalletClient,
  decodeEventLog,
  http,
  parseAbiItem,
  parseEther,
} from "viem";
import { sepolia } from "viem/chains";

import * as relay from "../../relay/client.mjs";
import { RPC_URL } from "../../core/constants.mjs";
import { openFundingWallet } from "../../core/funding/wallet.mjs";
import { ERC8004_ABI } from "../../core/registration.mjs";
import { awaitRoleMessages } from "../../roles/host.mjs";
import { postNext } from "../../roles/session.mjs";
import {
  createFileFundingBudgetStore,
  createFundingBudget,
} from "./funding-budget.mjs";
import { agentHandshakeV2DescriptorDigest } from "./descriptor.mjs";
import { createHostSessionKeyCertificate, rawEd25519PublicKey } from "./host-key-certificate.mjs";
import { loadHostRoot } from "./host-root.mjs";
import { verifyAgentHandshakeV2IdentityClaimEnvelope } from "./identity-claim.mjs";
import {
  agentHandshakeV2StatementDigest,
  validateAgentHandshakeV2Terms,
} from "./terms.mjs";
import { createAgentHandshakeV2Monitor } from "../../monitor/agent-snapshot-v2-producer.mjs";

const DEFAULT_RELAY = "http://44.249.47.220:8080";
const DEFAULT_REPOSITORY = "https://github.com/thetangstr/clockchain-handshake-v2.git";
const SESSION_MILLISECONDS = 10 * 60_000;
const INVITATION_MILLISECONDS = 120_000;
const FUND = parseEther("0.01");
const TRANSFER_EVENT = parseAbiItem(
  "event Transfer(address indexed from, address indexed to, uint256 indexed tokenId)",
);
function positiveInteger(value, fallback) {
  const parsed = Number(value ?? fallback);
  if (!Number.isSafeInteger(parsed) || parsed < 1) {
    throw new Error("AGENT_HANDSHAKE_V2_FUNDING_CONFIGURATION_INVALID");
  }
  return parsed;
}

function fundingAlertCents(value, fallback) {
  const parsed = Number(value ?? fallback);
  const cents = Math.round(parsed * 100);
  if (!Number.isFinite(parsed) || parsed <= 0 || cents / 100 !== parsed) {
    throw new Error("AGENT_HANDSHAKE_V2_FUNDING_CONFIGURATION_INVALID");
  }
  return cents;
}

export async function loadAgentHandshakeV2Session({
  env = process.env,
  loadRoot = loadHostRoot,
  now = Date.now,
  publicClient: publicClientOverride,
  relayClient = relay,
} = {}) {
  const repositorySha = env.HANDSHAKE_SHA;
  if (typeof repositorySha !== "string" || !/^[0-9a-f]{40}$/.test(repositorySha)) {
    throw new Error("HANDSHAKE_SHA_INVALID");
  }
  const root = await loadRoot({ env });
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const privateKeyPem = privateKey.export({ format: "pem", type: "pkcs8" });
  const expectedPublicKey = rawEd25519PublicKey(publicKey);
  const sessionId = randomUUID();
  const sessionOpenedAtMs = now();
  if (!Number.isSafeInteger(sessionOpenedAtMs)) throw new Error("HANDSHAKE_CLOCK_INVALID");
  const sessionDeadlineMs = sessionOpenedAtMs + SESSION_MILLISECONDS;
  const invitationExpiresAtMs = sessionOpenedAtMs + INVITATION_MILLISECONDS;
  const hostSessionKeyCertificate = createHostSessionKeyCertificate({
    certificate: {
      schema: "clockchain.host-session-key/v1",
      rootKid: root.keyId,
      sessionId,
      repositorySha,
      sessionPublicKey: expectedPublicKey,
      validFromMs: String(sessionOpenedAtMs),
      validUntilMs: String(sessionDeadlineMs),
    },
    root,
  });
  const relayUrl = env.HANDSHAKE_RELAY ?? DEFAULT_RELAY;
  const publicClient = publicClientOverride ?? createPublicClient({
    chain: sepolia,
    transport: http(env.SEPOLIA_RPC_URL ?? RPC_URL),
  });
  const sessionOpenedBlock = String(await publicClient.getBlockNumber());
  const discovery = Object.freeze({
    schema: "clockchain.agent-handshake-discovery/v2",
    protocol: "clockchain.agent-handshake/v2",
    sessionId,
    repositorySha,
    kitRepoUrl: env.HANDSHAKE_KIT_REPO ?? DEFAULT_REPOSITORY,
    relayUrl,
    createdAtMs: String(sessionOpenedAtMs),
    invitationExpiresAtMs: String(invitationExpiresAtMs),
    sessionDeadlineMs: String(sessionDeadlineMs),
    sessionOpenedBlock,
    hostSessionKeyCertificate,
    externalBusinessActionPerformed: false,
  });
  await relayClient.createSession({ relayUrl, sessionId, discovery });
  return Object.freeze({
    expectedPublicKey,
    hostSessionKeyCertificate,
    invitationExpiresAtMs,
    keyId: env.AGENT_HANDSHAKE_V2_KEY_ID ?? "session-host",
    privateKeyPem,
    protocol: "clockchain.agent-handshake/v2",
    relayUrl,
    repositorySha,
    sessionDeadlineMs,
    sessionId,
    sessionOpenedAtMs,
    sessionOpenedBlock,
  });
}

export async function createAgentHandshakeV2HostPorts(_session, overrides = {}) {
  const session = _session;
  const now = overrides.now ?? Date.now;
  const relayClient = overrides.relayClient ?? relay;
  const publicClient = overrides.publicClient ?? createPublicClient({
    chain: sepolia,
    transport: http(process.env.SEPOLIA_RPC_URL ?? RPC_URL),
  });
  const envelopeKey =
    relayClient.generateEnvelopeKeyPair?.() ?? relay.generateEnvelopeKeyPair();
  let after = "0";
  let buffer = [];

  const defaultWaitForMessage = async (
    kind,
    role,
    deadlineMs = session.sessionDeadlineMs,
  ) => {
    const result = await awaitRoleMessages({
      after,
      buffer,
      budgetMs: Math.max(0, deadlineMs - now()),
      expectedBindings: null,
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
    if (relayClient.verifyEnvelope(message) !== true) {
      throw new Error("AGENT_HANDSHAKE_V2_RELAY_ENVELOPE_INVALID");
    }
    return message;
  };
  const waitForMessage = overrides.waitForMessage ?? defaultWaitForMessage;
  const postHostMessage = overrides.postHostMessage ?? ((kind, body) =>
    postNext(relayClient, {
      body,
      keyPair: envelopeKey,
      kind,
      relayUrl: session.relayUrl,
      role: "host",
      sessionId: session.sessionId,
    }));
  let monitor = overrides.monitor ?? null;
  let selectedInvitation = null;
  function monitorPort() {
    if (monitor === null) throw new Error("AGENT_HANDSHAKE_V2_INVITATION_INVALID");
    return monitor;
  }
  function ensureMonitor(invitation) {
    monitor ??= createAgentHandshakeV2Monitor({
      now,
      publish: (snapshot) => relayClient.putSnapshot({
        relayUrl: session.relayUrl,
        retryBudgetMs: 30_000,
        sessionId: session.sessionId,
        snapshot,
      }),
      session: Object.freeze({
        ...session,
        invitationCreatedAtMs: invitation.createdAtMs,
        terms: invitation.terms,
      }),
    });
    return monitor;
  }

  const store = overrides.fundingStore ?? createFileFundingBudgetStore({
    path: process.env.AGENT_HANDSHAKE_V2_FUNDING_LEDGER ??
      "/var/lib/clockchain/private/v2-funding-ledger.jsonl",
  });
  const fundingBudget = overrides.fundingBudget ?? createFundingBudget({
    ...store,
    alertDayCents: fundingAlertCents(
      process.env.AGENT_HANDSHAKE_V2_FUNDING_ALERT_DAILY_ETH,
      "0.80",
    ),
    alertHourCents: fundingAlertCents(
      process.env.AGENT_HANDSHAKE_V2_FUNDING_ALERT_HOURLY_ETH,
      "0.16",
    ),
    onAlert: (usage) => console.warn(JSON.stringify({
      event: "agent_handshake_v2_funding_budget_alert",
      ...usage,
    })),
    queueLimit: positiveInteger(
      process.env.AGENT_HANDSHAKE_V2_FUNDING_QUEUE_LIMIT,
      "16",
    ),
  });
  let walletPromise = null;
  const defaultFundIdentity = async ({ address, role }) => {
    walletPromise ??= openFundingWallet({
      keystorePath: process.env.CLOCKCHAIN_FUNDING_KEYSTORE ??
        "/var/lib/clockchain/private/funding-wallet.json",
    });
    const treasury = await walletPromise;
    const wallet = createWalletClient({
      account: treasury.account,
      chain: sepolia,
      transport: http(process.env.SEPOLIA_RPC_URL ?? RPC_URL),
    });
    const hash = await wallet.sendTransaction({ to: address, value: FUND });
    const receipt = await publicClient.waitForTransactionReceipt({
      hash,
      timeout: 180_000,
    });
    await postHostMessage("agent_v2_funding_record", {
      address,
      amountEth: "0.01",
      blockNumber: String(receipt.blockNumber),
      externalBusinessActionPerformed: false,
      role,
      transactionHash: hash,
    });
  };

  async function transferLogs(args) {
    return publicClient.getLogs({
      address: "0x8004a818bfb912233c491871b3d84c89a494bd9e",
      event: TRANSFER_EVENT,
      fromBlock: 0n,
      ...args,
    });
  }

  const defaultFindExistingIdentity = async (address) => {
    const logs = await transferLogs({ args: { to: address } });
    for (const entry of [...logs].reverse()) {
      const agentId = entry.args.tokenId;
      const owner = await publicClient.readContract({
        abi: ERC8004_ABI,
        address: "0x8004a818bfb912233c491871b3d84c89a494bd9e",
        args: [agentId],
        functionName: "ownerOf",
      });
      if (String(owner).toLowerCase() === address) {
        return Object.freeze({
          agentId: String(agentId),
          owner: address,
          registrationBlock: String(entry.blockNumber),
        });
      }
    }
    return null;
  };
  const defaultResolveRegistration = async (party) => {
    const registration = party?.erc8004;
    if (
      registration === null || typeof registration !== "object" ||
      typeof party?.sessionKeyAddress !== "string"
    ) throw new Error("AGENT_HANDSHAKE_V2_REGISTRATION_MISSING");
    const tokenId = BigInt(registration.agentId);
    const owner = String(await publicClient.readContract({
      abi: ERC8004_ABI,
      address: "0x8004a818bfb912233c491871b3d84c89a494bd9e",
      args: [tokenId],
      functionName: "ownerOf",
    })).toLowerCase();
    const receipt = await publicClient.getTransactionReceipt({
      hash: registration.registrationTx,
    });
    const registryAddress = registration.registryAddress.toLowerCase();
    const minted = receipt.logs.some((log) => {
      if (String(log.address).toLowerCase() !== registryAddress) return false;
      try {
        const decoded = decodeEventLog({
          abi: [TRANSFER_EVENT],
          data: log.data,
          topics: log.topics,
        });
        return (
          decoded.eventName === "Transfer" &&
          String(decoded.args.from).toLowerCase() ===
            "0x0000000000000000000000000000000000000000" &&
          String(decoded.args.to).toLowerCase() === owner &&
          decoded.args.tokenId === tokenId
        );
      } catch {
        return false;
      }
    });
    if (
      receipt.status !== "success" ||
      String(receipt.to).toLowerCase() !== registryAddress ||
      String(receipt.blockNumber) !== registration.registrationBlock ||
      owner !== party.sessionKeyAddress ||
      !minted
    ) throw new Error("AGENT_HANDSHAKE_V2_REGISTRATION_MISSING");
    return Object.freeze({
      owner,
      registrationBlock: String(receipt.blockNumber),
    });
  };
  const anchorReport = (message) => {
    const entries = message?.body?.transitions;
    if (!Array.isArray(entries) || entries.length !== 3) {
      throw new Error("AGENT_HANDSHAKE_V2_ANCHORS_INVALID");
    }
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
  };

  return Object.freeze({
    awaitCommitmentCheckpoint: async (role) =>
      (await waitForMessage("agent_v2_commitment_checkpoint", role)).body.checkpoint,
    awaitAcceptance: async () =>
      (await waitForMessage("agent_v2_acceptance", "responder")).body.acceptanceEnvelope,
    awaitAnchors: async () =>
      anchorReport(await waitForMessage("agent_v2_anchor_report", "initiator")),
    awaitEvidence: async (role) =>
      (await waitForMessage("agent_v2_evidence", role)).body.evidenceEnvelope,
    awaitInvitationClaimed: async () => {
      const createdMessage = await waitForMessage(
        "agent_v2_invitation_created",
        "initiator",
        session.invitationExpiresAtMs,
      );
      const createdBody = createdMessage.body;
      if (
        createdBody === null || typeof createdBody !== "object" ||
        Array.isArray(createdBody) ||
        Object.keys(createdBody).sort().join(",") !==
          "createdAtMs,externalBusinessActionPerformed,statementDigest,terms" ||
        typeof createdBody.createdAtMs !== "string" ||
        !/^(?:0|[1-9][0-9]*)$/.test(createdBody.createdAtMs) ||
        typeof createdBody.statementDigest !== "string" ||
        !/^[0-9a-f]{64}$/.test(createdBody.statementDigest) ||
        createdBody.externalBusinessActionPerformed !== false
      ) throw new Error("AGENT_HANDSHAKE_V2_INVITATION_INVALID");
      let terms;
      try { terms = validateAgentHandshakeV2Terms(createdBody.terms); }
      catch { throw new Error("AGENT_HANDSHAKE_V2_INVITATION_INVALID"); }
      const createdAtMs = Number(createdBody.createdAtMs);
      if (
        !Number.isSafeInteger(createdAtMs) ||
        createdAtMs < session.sessionOpenedAtMs ||
        createdAtMs >= session.invitationExpiresAtMs ||
        createdBody.statementDigest !== agentHandshakeV2StatementDigest(terms)
      ) throw new Error("AGENT_HANDSHAKE_V2_INVITATION_INVALID");
      const message = await waitForMessage(
        "agent_v2_invitation_claimed",
        "responder",
        session.invitationExpiresAtMs,
      );
      const body = message.body;
      if (
        body === null || typeof body !== "object" || Array.isArray(body) ||
        Object.keys(body).sort().join(",") !==
          "claimedAtMs,externalBusinessActionPerformed" ||
        typeof body.claimedAtMs !== "string" ||
        !/^(?:0|[1-9][0-9]*)$/.test(body.claimedAtMs) ||
        body.externalBusinessActionPerformed !== false
      ) throw new Error("AGENT_HANDSHAKE_V2_INVITATION_CLAIM_INVALID");
      const claimedAtMs = Number(body.claimedAtMs);
      if (
        !Number.isSafeInteger(claimedAtMs) ||
        claimedAtMs < createdAtMs ||
        claimedAtMs >= session.invitationExpiresAtMs
      ) throw new Error("AGENT_HANDSHAKE_V2_INVITATION_CLAIM_INVALID");
      selectedInvitation = Object.freeze({
        claimedAtMs,
        createdAtMs,
        statementDigest: createdBody.statementDigest,
        terms,
      });
      return selectedInvitation;
    },
    awaitIdentityClaim: async (role) => {
      const message = await waitForMessage("agent_v2_identity_claim", role);
      const verified = await verifyAgentHandshakeV2IdentityClaimEnvelope(
        message.body,
        {
          expectedRepositorySha: session.repositorySha,
          expectedRole: role,
          expectedSessionId: session.sessionId,
          expectedStatementDigest: selectedInvitation?.statementDigest,
        },
      );
      await monitorPort().identityClaimed(role, verified.claim);
      return Object.freeze({
        policyDigest: verified.claim.policyDigest,
        sessionKeyAddress: verified.claim.sessionKeyAddress,
      });
    },
    awaitPartyReady: async (role) =>
      (await waitForMessage("agent_v2_party_ready", role)).body,
    awaitProposal: async () =>
      (await waitForMessage("agent_v2_proposal", "initiator")).body.proposalEnvelope,
    findExistingIdentity:
      overrides.findExistingIdentity ?? defaultFindExistingIdentity,
    fundIdentity: overrides.fundIdentity ?? defaultFundIdentity,
    publishDescriptor: async (descriptorEnvelope) =>
      postHostMessage("agent_v2_handshake_required", {
        descriptorEnvelope,
        externalBusinessActionPerformed: false,
        sessionDigest:
          agentHandshakeV2DescriptorDigest(descriptorEnvelope.descriptor),
      }),
    publishResult: overrides.publishResult ?? ((envelope) =>
      relayClient.putResult({
        envelope,
        relayUrl: session.relayUrl,
        retryBudgetMs: 30_000,
        sessionId: session.sessionId,
      })),
    publishInitial: async (invitation) => {
      if (
        selectedInvitation === null ||
        JSON.stringify(invitation) !== JSON.stringify(selectedInvitation)
      ) throw new Error("AGENT_HANDSHAKE_V2_INVITATION_INVALID");
      const activeMonitor = ensureMonitor(selectedInvitation);
      await activeMonitor.start();
      await activeMonitor.invitationClaimed(selectedInvitation.claimedAtMs);
    },
    partiesReady: (parties) => monitorPort().partiesReady(parties),
    proposalSigned: (envelope) => monitorPort().proposalSigned(envelope),
    acceptanceSigned: (envelope) => monitorPort().acceptanceSigned(envelope),
    anchorsRecorded: (report) => monitorPort().anchorsRecorded(report),
    evidenceReceived: (role, envelope) => monitorPort().evidenceReceived(role, envelope),
    checkerStage: (stage) => monitorPort().checkerStage(stage),
    failed: (reasonCode) => monitorPort().failed(reasonCode),
    certificateIssued: (envelope) => monitorPort().certificateIssued(envelope),
    reserveFunding: (input) => fundingBudget.reserve(input),
    resolveRegistration:
      overrides.resolveRegistration ?? defaultResolveRegistration,
  });
}
