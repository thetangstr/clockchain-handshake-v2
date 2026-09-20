import { generateKeyPairSync, randomUUID } from "node:crypto";

import {
  createPublicClient,
  createWalletClient,
  http,
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
// invitationExpiresAtMs is the MINT cutoff: the session stops accepting new
// invitations then and an unclaimed session rotates. The responder's claim
// window is mint-relative (the coordinator publishes it as claimExpiresAtMs
// on agent_v2_invitation_created), so the claim wait below extends its bound
// to the minted expiry once that message is observed — a claim still can
// never outlive the host's observation, but a late-window mint keeps its
// full runway instead of inheriting only the remaining slice.
const INVITATION_MILLISECONDS = 120_000;
// Older coordinators minted the claim window without publishing it (either
// mint-relative at +120s or pinned to the session invitation expiry); when an
// invitation_created carries no claimExpiresAtMs the host derives an upper
// bound from its createdAtMs so the observation window still covers whatever
// window that mint actually produced.
const LEGACY_INVITATION_CLAIM_WINDOW_MS = 120_000;
// The host observes a few seconds past the minted claim expiry so a claim
// accepted at the edge still lands while the relay log is being read; the
// claimedAtMs check inside awaitInvitationClaimed stays the authority on
// whether the claim was in-window.
const INVITATION_CLAIM_OBSERVE_GRACE_MS = 5_000;
const FUND = parseEther("0.01");
const REGISTRY_ADDRESS = "0x8004a818bfb912233c491871b3d84c89a494bd9e";
const REGISTERED_EVENT = ERC8004_ABI.find(
  (entry) => entry.type === "event" && entry.name === "Registered",
);
const DEFAULT_TERMS = Object.freeze({
  reference: "NS-1847",
  statement: "Northstar Logistics and Harbor Supply authorize these two independently controlled agents to communicate about shipment reference NS-1847 for 90 seconds.",
  validForSeconds: "90",
  identityPolicy: Object.freeze({
    erc8004: "required_fresh",
    chainId: "eip155:11155111",
    registryAddress: "0x8004a818bfb912233c491871b3d84c89a494bd9e",
  }),
});

function termsFromEnvironment(env) {
  if (!env.AGENT_HANDSHAKE_V2_TERMS) return DEFAULT_TERMS;
  let parsed;
  try { parsed = JSON.parse(env.AGENT_HANDSHAKE_V2_TERMS); } catch { throw new Error("AGENT_HANDSHAKE_V2_TERMS_INVALID"); }
  return validateAgentHandshakeV2Terms(parsed);
}

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
  const terms = termsFromEnvironment(env);
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
    terms,
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
    terms,
  });
}

export async function createAgentHandshakeV2HostPorts(_session, overrides = {}) {
  const session = _session;
  const relayClient = overrides.relayClient ?? relay;
  const publicClient = overrides.publicClient ?? createPublicClient({
    chain: sepolia,
    transport: http(process.env.SEPOLIA_RPC_URL ?? RPC_URL),
  });
  const envelopeKey =
    relayClient.generateEnvelopeKeyPair?.() ?? relay.generateEnvelopeKeyPair();
  let after = "0";
  let buffer = [];
  // The minted responder claim window, learned from agent_v2_invitation_created
  // on the session log (or derived from its createdAtMs for coordinators that
  // predate claimExpiresAtMs). Drives both the extended observation bound below
  // and the claimedAtMs validity check in awaitInvitationClaimed.
  let mintedClaimExpMs = null;
  const extendClaimDeadline = (message) => {
    if (
      message?.kind !== "agent_v2_invitation_created" ||
      message?.role !== "initiator" ||
      message.body === null ||
      typeof message.body !== "object" ||
      Array.isArray(message.body)
    ) return null;
    const explicit = Number(message.body.claimExpiresAtMs);
    const minted = Number(message.body.createdAtMs);
    const derived = Number.isSafeInteger(explicit)
      ? explicit
      : Number.isSafeInteger(minted)
        ? minted + LEGACY_INVITATION_CLAIM_WINDOW_MS
        : null;
    const openedMs = Number.isSafeInteger(session.sessionOpenedAtMs)
      ? session.sessionOpenedAtMs
      : 0;
    if (derived === null || derived <= openedMs) return null;
    mintedClaimExpMs = Math.min(derived, session.sessionDeadlineMs);
    return Math.min(
      session.sessionDeadlineMs,
      mintedClaimExpMs + INVITATION_CLAIM_OBSERVE_GRACE_MS,
    );
  };

  const defaultWaitForMessage = async (kind, role) => {
    // invitationExpiresAtMs is the mint cutoff, so it bounds only the START of
    // the claim wait: an unminted session exits and the supervisor rotates a
    // fresh "current" session. Once the invitation_created message is seen the
    // wait extends to the minted claim expiry, so a late-window mint still gets
    // its full responder runway; every later wait keeps the session deadline.
    const isClaimWait = kind === "agent_v2_invitation_claimed";
    const boundMs = isClaimWait &&
      Number.isSafeInteger(session.invitationExpiresAtMs)
      ? Math.min(session.sessionDeadlineMs, session.invitationExpiresAtMs)
      : session.sessionDeadlineMs;
    const result = await awaitRoleMessages({
      after,
      buffer,
      budgetMs: Math.max(0, boundMs - Date.now()),
      expectedBindings: null,
      extendDeadline: isClaimWait ? extendClaimDeadline : null,
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
  const monitor = overrides.monitor ?? createAgentHandshakeV2Monitor({
    now: overrides.now ?? Date.now,
    publish: (snapshot) => relayClient.putSnapshot({
      relayUrl: session.relayUrl,
      retryBudgetMs: 30_000,
      sessionId: session.sessionId,
      snapshot,
    }),
    session,
  });

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

  const ownerOf = async (tokenId) => String(await publicClient.readContract({
    abi: ERC8004_ABI,
    address: REGISTRY_ADDRESS,
    args: [tokenId],
    functionName: "ownerOf",
  })).toLowerCase();

  // eth_getLogs providers cap the block range per call (the live RPC rejects
  // anything over 50,000), so the existing-identity scan walks the official
  // Registered event backwards from the head in inclusive chunks of at most
  // 50,000 blocks — newest first — all the way to genesis. There is no
  // recent-window cap: an identity minted long ago must still be found.
  const LOG_SCAN_CHUNK_BLOCKS = 50_000n;
  const defaultFindExistingIdentity = async (address) => {
    const owner = String(address).toLowerCase();
    let to = await publicClient.getBlockNumber();
    for (;;) {
      const from = to > LOG_SCAN_CHUNK_BLOCKS - 1n
        ? to - (LOG_SCAN_CHUNK_BLOCKS - 1n)
        : 0n;
      const logs = await publicClient.getLogs({
        address: REGISTRY_ADDRESS,
        args: { owner },
        event: REGISTERED_EVENT,
        fromBlock: from,
        toBlock: to,
      });
      for (const entry of [...logs].reverse()) {
        const agentId = entry.args?.agentId;
        const block = String(entry.blockNumber);
        if (agentId === undefined || !/^(?:0|[1-9][0-9]*)$/.test(block)) continue;
        // ownerOf can revert for a burned or otherwise unreadable token;
        // that candidate is simply not currently owned — keep scanning.
        let current;
        try {
          current = await ownerOf(agentId);
        } catch {
          continue;
        }
        if (current === owner) {
          return Object.freeze({
            agentId: String(agentId),
            owner,
            registrationBlock: block,
          });
        }
      }
      if (from === 0n) return null;
      to = from - 1n;
    }
  };
  // The caller supplies the party's claimed owner and registration block; the
  // claim is authoritative only if the exact block contains the official
  // Registered(agentId, owner) event and ownerOf still matches. No history
  // scan is needed — the claim pins the block — so the lookup stays inside
  // every provider's range limit.
  const defaultResolveRegistration = async (agentId, expected) => {
    const tokenId = BigInt(agentId);
    const owner = String(expected?.expectedOwner ?? "").toLowerCase();
    const block = String(expected?.registrationBlock ?? "");
    if (
      !/^0x[0-9a-f]{40}$/.test(owner) ||
      !/^(?:0|[1-9][0-9]*)$/.test(block)
    ) throw new Error("AGENT_HANDSHAKE_V2_REGISTRATION_MISSING");
    const height = BigInt(block);
    const logs = await publicClient.getLogs({
      address: REGISTRY_ADDRESS,
      args: { agentId: tokenId, owner },
      event: REGISTERED_EVENT,
      fromBlock: height,
      toBlock: height,
    });
    if (
      !logs.some((entry) =>
        entry.args?.agentId === tokenId &&
        String(entry.args?.owner).toLowerCase() === owner
      )
    ) throw new Error("AGENT_HANDSHAKE_V2_REGISTRATION_MISSING");
    if ((await ownerOf(tokenId)) !== owner) {
      throw new Error("AGENT_HANDSHAKE_V2_REGISTRATION_MISSING");
    }
    return Object.freeze({ owner, registrationBlock: block });
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
    awaitAcceptance: async () =>
      (await waitForMessage("agent_v2_acceptance", "responder")).body.acceptanceEnvelope,
    awaitAnchors: async () =>
      anchorReport(await waitForMessage("agent_v2_anchor_report", "initiator")),
    awaitEvidence: async (role) =>
      (await waitForMessage("agent_v2_evidence", role)).body.evidenceEnvelope,
    awaitInvitationClaimed: async () => {
      const message = await waitForMessage("agent_v2_invitation_claimed", "responder");
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
      // The minted claim window is authoritative: a claim is in-window when it
      // lands before the expiry that mint published on invitation_created, not
      // the session's invitationExpiresAtMs (that is only the mint cutoff).
      const claimDeadlineMs = mintedClaimExpMs ?? session.invitationExpiresAtMs;
      if (
        !Number.isSafeInteger(claimedAtMs) ||
        claimedAtMs < session.sessionOpenedAtMs ||
        claimedAtMs >= claimDeadlineMs
      ) throw new Error("AGENT_HANDSHAKE_V2_INVITATION_CLAIM_INVALID");
      await monitor.invitationClaimed(claimedAtMs);
      return claimedAtMs;
    },
    awaitIdentityClaim: async (role) => {
      const message = await waitForMessage("agent_v2_identity_claim", role);
      const verified = await verifyAgentHandshakeV2IdentityClaimEnvelope(
        message.body,
        {
          expectedRepositorySha: session.repositorySha,
          expectedRole: role,
          expectedSessionId: session.sessionId,
          expectedStatementDigest: agentHandshakeV2StatementDigest(session.terms),
        },
      );
      await monitor.identityClaimed(role, verified.claim);
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
    publishInitial: () => monitor.start(),
    partiesReady: (parties) => monitor.partiesReady(parties),
    proposalSigned: (envelope) => monitor.proposalSigned(envelope),
    acceptanceSigned: (envelope) => monitor.acceptanceSigned(envelope),
    anchorsRecorded: (report) => monitor.anchorsRecorded(report),
    evidenceReceived: (role, envelope) => monitor.evidenceReceived(role, envelope),
    checkerStage: (stage) => monitor.checkerStage(stage),
    failed: (reasonCode) => monitor.failed(reasonCode),
    certificateIssued: (envelope) => monitor.certificateIssued(envelope),
    reserveFunding: (input) => fundingBudget.reserve(input),
    resolveRegistration:
      overrides.resolveRegistration ?? defaultResolveRegistration,
  });
}
