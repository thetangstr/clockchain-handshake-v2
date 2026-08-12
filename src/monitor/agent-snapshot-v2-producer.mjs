import { digestHex } from "../core/canonical.mjs";
import {
  agentHandshakeV2ProposalDigest,
} from "../agent-handshake/v2/protocol.mjs";
import {
  ed25519PublicKeyFingerprint,
  hostSessionKeyCertificateDigest,
} from "../agent-handshake/v2/host-key-certificate.mjs";
import { buildAgentHandshakeV2Snapshot } from "./agent-snapshot-v2.mjs";

const ROLES = Object.freeze(["initiator", "responder"]);

function role(value) {
  if (!ROLES.includes(value)) throw new Error("AGENT_HANDSHAKE_V2_MONITOR_INVALID");
  return value;
}

export function createAgentHandshakeV2Monitor({ now = Date.now, publish, session } = {}) {
  if (typeof now !== "function" || typeof publish !== "function" || session?.protocol !== "clockchain.agent-handshake/v2") {
    throw new Error("AGENT_HANDSHAKE_V2_MONITOR_INVALID");
  }
  const certificate = session.hostSessionKeyCertificate;
  const root = certificate.rootSignature;
  const state = {
    schema: "clockchain.agent-handshake-snapshot/v2",
    protocol: session.protocol,
    sessionId: session.sessionId,
    repositorySha: session.repositorySha,
    hostTrust: {
      rootKid: root.keyId,
      rootFingerprint: ed25519PublicKeyFingerprint(root.publicKey),
      sessionPublicKey: certificate.certificate.sessionPublicKey,
      sessionKeyCertificateDigest: hostSessionKeyCertificateDigest(certificate),
    },
    timing: {
      createdAtMs: session.sessionOpenedAtMs,
      invitationExpiresAtMs: session.invitationExpiresAtMs,
      sessionDeadlineMs: session.sessionDeadlineMs,
      agreementValidForSeconds: session.terms.validForSeconds,
    },
    invitation: { createdAtMs: null, responderClaimedAtMs: null },
    terms: {
      reference: session.terms.reference,
      statement: session.terms.statement,
      identityPolicy: session.terms.identityPolicy,
    },
    policies: { initiator: null, responder: null },
    parties: { initiator: null, responder: null },
    statements: { proposalDigest: null, acceptanceDigest: null },
    receipts: { proposal: null, acceptance: null, acknowledgment: null },
    evidence: { initiator: null, responder: null },
    checker: { stage: "WAITING", lastSeenMs: session.sessionOpenedAtMs },
    certificate: null,
    freshness: {
      initiator: null,
      responder: null,
      host: { lastSeenMs: session.sessionOpenedAtMs },
      checker: { lastSeenMs: session.sessionOpenedAtMs },
    },
    failure: null,
    externalBusinessActionPerformed: false,
  };

  async function flush() {
    const atMs = now();
    state.freshness.host = { lastSeenMs: atMs };
    await publish(buildAgentHandshakeV2Snapshot(structuredClone(state)));
  }

  return Object.freeze({
    start: flush,
    async invitationCreated(createdAtMs) {
      if (
        !Number.isSafeInteger(createdAtMs) ||
        state.invitation.createdAtMs !== null ||
        createdAtMs < state.timing.createdAtMs ||
        createdAtMs >= state.timing.invitationExpiresAtMs
      ) throw new Error("AGENT_HANDSHAKE_V2_MONITOR_INVALID");
      state.invitation.createdAtMs = createdAtMs;
      await flush();
    },
    async invitationClaimed(claimedAtMs) {
      if (
        !Number.isSafeInteger(claimedAtMs) ||
        state.invitation.createdAtMs === null ||
        claimedAtMs < state.invitation.createdAtMs ||
        claimedAtMs >= state.timing.invitationExpiresAtMs
      ) throw new Error("AGENT_HANDSHAKE_V2_MONITOR_INVALID");
      state.invitation.responderClaimedAtMs = claimedAtMs;
      await flush();
    },
    async identityClaimed(rawRole, claim) {
      const name = role(rawRole);
      const atMs = now();
      state.policies[name] = { digest: claim.policyDigest, committedAtMs: atMs };
      state.freshness[name] = { lastSeenMs: atMs };
      await flush();
    },
    async partiesReady(parties) {
      state.parties = Object.fromEntries(ROLES.map((name) => [name, {
        sessionKeyAddress: parties[name].sessionKeyAddress,
        erc8004: structuredClone(parties[name].erc8004),
      }]));
      const atMs = now();
      state.freshness.initiator = { lastSeenMs: atMs };
      state.freshness.responder = { lastSeenMs: atMs };
      await flush();
    },
    async proposalSigned(envelope) {
      state.statements.proposalDigest = agentHandshakeV2ProposalDigest(envelope);
      state.freshness.initiator = { lastSeenMs: now() };
      await flush();
    },
    async acceptanceSigned(envelope) {
      state.statements.acceptanceDigest = digestHex(envelope.payload);
      state.freshness.responder = { lastSeenMs: now() };
      await flush();
    },
    async anchorsRecorded(report) {
      for (const receipt of report.receipts) {
        state.receipts[receipt.kind] = {
          ...receipt,
          explorerUrl: `https://clockchain.network/ledger/${receipt.ledgerId}`,
        };
      }
      await flush();
    },
    async evidenceReceived(rawRole, envelope) {
      const name = role(rawRole);
      const atMs = now();
      state.evidence[name] = { digest: digestHex(envelope), receivedAtMs: atMs };
      state.freshness[name] = { lastSeenMs: atMs };
      await flush();
    },
    async checkerStage(stage) {
      if (!["WAITING", "VERIFYING", "VERIFIED", "FAILED"].includes(stage)) {
        throw new Error("AGENT_HANDSHAKE_V2_MONITOR_INVALID");
      }
      const atMs = now();
      state.checker = { stage, lastSeenMs: atMs };
      state.freshness.checker = { lastSeenMs: atMs };
      await flush();
    },
    async failed(reasonCode) {
      if (typeof reasonCode !== "string" || !/^[A-Z][A-Z0-9_]{0,63}$/.test(reasonCode)) {
        throw new Error("AGENT_HANDSHAKE_V2_MONITOR_INVALID");
      }
      const atMs = now();
      state.failure = { reasonCode };
      state.checker = { stage: "FAILED", lastSeenMs: atMs };
      state.freshness.checker = { lastSeenMs: atMs };
      await flush();
    },
    async certificateIssued(envelope) {
      const atMs = Number(envelope.result.issuedAtMs);
      state.certificate = {
        digest: digestHex(envelope),
        issuedAtMs: atMs,
        outcome: envelope.result.outcome,
      };
      state.checker = { stage: "VERIFIED", lastSeenMs: atMs };
      state.freshness.checker = { lastSeenMs: atMs };
      await flush();
    },
  });
}
