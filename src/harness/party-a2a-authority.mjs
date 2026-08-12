import { types } from "node:util";
import { gzipSync } from "node:zlib";

import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";

import { signA2AAgentCard, verifyA2AAgentCard, a2aAgentCardDigest } from "../a2a/agent-card.mjs";
import { addressFromPublicKey } from "../a2a/auth.mjs";
import {
  commitmentCheckpointDigest,
  signAgentHandshakeV2CommitmentCheckpoint,
  verifyAgentHandshakeV2CommitmentCheckpoint,
} from "../agent-handshake/v2/commitment-checkpoint.mjs";
import { localPolicyDigest } from "../agent-handshake/v2/policy.mjs";
import {
  verifyAgentHandshakeV2Acceptance,
  verifyAgentHandshakeV2Proposal,
} from "../agent-handshake/v2/protocol.mjs";
import { agentHandshakeV2StatementDigest } from "../agent-handshake/v2/terms.mjs";
import { digestHex } from "../core/canonical.mjs";
import {
  inspectWalletPublicKey,
  signExactBytes,
} from "../core/wallet-bridge.mjs";
import { validateAgentHandshakeV2Terms } from "../agent-handshake/v2/terms.mjs";

const ERROR_MESSAGE = "Party A2A authority failed safely.";
const ROLES = Object.freeze(["initiator", "responder"]);
const DIGEST = /^[0-9a-f]{64}$/;
const SHA = /^[0-9a-f]{40}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const ADDRESS = /^0x[0-9a-f]{40}$/;
const DECIMAL = /^(?:0|[1-9][0-9]*)$/;
const URL = /^https:\/\/[A-Za-z0-9._~:/?#[\]@!$&'()*+,;=%-]{1,240}$/;

function fail() {
  throw new Error(ERROR_MESSAGE);
}

function sanitize(error) {
  if (error?.message === ERROR_MESSAGE) throw error;
  fail();
}

function exact(value, keys) {
  try {
    if (
      value === null ||
      typeof value !== "object" ||
      Array.isArray(value) ||
      types.isProxy(value) ||
      ![Object.prototype, null].includes(Object.getPrototypeOf(value))
    ) fail();
    const descriptors = Object.getOwnPropertyDescriptors(value);
    const actual = Reflect.ownKeys(descriptors);
    if (actual.length !== keys.length || actual.some((key) => typeof key !== "string" || !keys.includes(key))) fail();
    const result = {};
    for (const key of keys) {
      const descriptor = descriptors[key];
      if (descriptor?.enumerable !== true || !Object.hasOwn(descriptor, "value")) fail();
      result[key] = descriptor.value;
    }
    return result;
  } catch (error) {
    sanitize(error);
  }
}

function optional(value, required, optionalKeys = []) {
  try {
    if (
      value === null ||
      typeof value !== "object" ||
      Array.isArray(value) ||
      types.isProxy(value) ||
      ![Object.prototype, null].includes(Object.getPrototypeOf(value))
    ) fail();
    const descriptors = Object.getOwnPropertyDescriptors(value);
    const allowed = [...required, ...optionalKeys];
    const actual = Reflect.ownKeys(descriptors);
    if (actual.some((key) => typeof key !== "string" || !allowed.includes(key))) fail();
    for (const key of required) if (!Object.hasOwn(descriptors, key)) fail();
    const result = {};
    for (const key of actual) {
      const descriptor = descriptors[key];
      if (descriptor?.enumerable !== true || !Object.hasOwn(descriptor, "value")) fail();
      result[key] = descriptor.value;
    }
    return result;
  } catch (error) {
    sanitize(error);
  }
}

function role(value) {
  if (!ROLES.includes(value)) fail();
  return value;
}

function runtime(value) {
  const item = exact(value, ["endpoint", "runtimeId", "taskId", "tlsCertificateSha256", "workloadAttestationDigest"]);
  if (
    typeof item.runtimeId !== "string" ||
    item.runtimeId.length < 1 ||
    item.runtimeId.length > 128 ||
    !/^[A-Za-z0-9._:-]+$/.test(item.runtimeId) ||
    typeof item.taskId !== "string" ||
    item.taskId.length < 1 ||
    item.taskId.length > 128 ||
    !/^[A-Za-z0-9._:-]+$/.test(item.taskId) ||
    typeof item.endpoint !== "string" ||
    !URL.test(item.endpoint) ||
    typeof item.workloadAttestationDigest !== "string" ||
    !DIGEST.test(item.workloadAttestationDigest) ||
    typeof item.tlsCertificateSha256 !== "string" ||
    !DIGEST.test(item.tlsCertificateSha256)
  ) fail();
  return Object.freeze({ ...item });
}

function assertDigest(value) {
  if (typeof value !== "string" || !DIGEST.test(value)) fail();
  return value;
}

function assertDecimal(value) {
  if (typeof value !== "string" || !DECIMAL.test(value)) fail();
  return value;
}

function assertToken(value) {
  if (typeof value !== "string" || value.length < 1 || value.length > 128 || !/^[A-Za-z0-9._:-]+$/.test(value)) fail();
  return value;
}

function bytesHex(raw) {
  return `0x${Buffer.from(raw).toString("hex")}`;
}

function gzipBase64Url(raw) {
  return gzipSync(Buffer.from(raw), { level: 9 }).toString("base64url");
}

function supportedArtifacts() {
  return Object.freeze(["invitation", "proposal", "counterproposal", "acceptance"]);
}

function cardInput({ address, publicKey, a2aPublicKey, role: localRole, sessionId, runtime: localRuntime, peerCardDigest, issuedAtMs, expiresAtMs, nonce, jti }) {
  return Object.freeze({
    schema: "clockchain.a2a-agent-card/v1",
    version: 1,
    sessionId,
    role: localRole,
    partySignerAddress: address,
    partySignerPublicKey: publicKey,
    a2aCardPublicKey: a2aPublicKey,
    workloadAttestationDigest: localRuntime.workloadAttestationDigest,
    runtimeId: localRuntime.runtimeId,
    taskId: localRuntime.taskId,
    endpoint: localRuntime.endpoint,
    peerCardDigest,
    issuedAtMs,
    expiresAtMs,
    nonce,
    jti,
    supportedArtifacts: supportedArtifacts(),
  });
}

async function bridgeSigner({ raw, statePath, platform, runIcacls }) {
  const signed = await signExactBytes({
    statePath,
    platform,
    runIcacls,
    bytesHex: bytesHex(raw),
  });
  return signed.signatureHex;
}

export async function createPartyA2AAuthority(optionsInput = {}) {
  try {
    const options = optional(optionsInput, [
      "nowMs", "peerRuntime", "platform", "policyDigest", "repositorySha", "role", "runtime", "sessionId", "statePath", "terms",
    ], ["runIcacls"]);
    const localRole = role(options.role);
    const sessionId = options.sessionId;
    if (typeof sessionId !== "string" || !UUID.test(sessionId)) fail();
    if (typeof options.repositorySha !== "string" || !SHA.test(options.repositorySha)) fail();
    const policyDigest = assertDigest(options.policyDigest);
    const terms = validateAgentHandshakeV2Terms(options.terms);
    const expectedPolicyDigest = localPolicyDigest({
      schema: "clockchain.agent-handshake-policy/v1",
      protocol: "clockchain.agent-handshake/v2",
      role: localRole,
      mcpOrigin: "https://mcp.clockchain.network",
      reference: terms.reference,
      statementDigest: agentHandshakeV2StatementDigest(terms),
      maxValidForSeconds: terms.validForSeconds,
      identityPolicy: terms.identityPolicy,
      externalBusinessActionsAllowed: false,
    });
    if (policyDigest !== expectedPolicyDigest) fail();
    const localRuntime = runtime(options.runtime);
    const remoteRuntime = runtime(options.peerRuntime);
    if (localRuntime.runtimeId === remoteRuntime.runtimeId || localRuntime.workloadAttestationDigest === remoteRuntime.workloadAttestationDigest) fail();
    if (typeof options.nowMs !== "function") fail();
    const wallet = await inspectWalletPublicKey({
      statePath: options.statePath,
      platform: options.platform,
      runIcacls: options.runIcacls,
    });
    if (typeof wallet.address !== "string" || !ADDRESS.test(wallet.address) || typeof wallet.publicKey !== "string") fail();
    const a2aAccount = privateKeyToAccount(generatePrivateKey());
    if (a2aAccount.address.toLowerCase() === wallet.address.toLowerCase()) fail();
    if (addressFromPublicKey(a2aAccount.publicKey) === wallet.address.toLowerCase()) fail();
    let destroyed = false;
    const publicBindingValue = Object.freeze({
      schema: "clockchain.party-a2a-authority-binding/v1",
      sessionId,
      role: localRole,
      policyDigest,
      repositorySha: options.repositorySha,
      runtime: localRuntime,
      peerRuntime: remoteRuntime,
      partySignerAddress: wallet.address.toLowerCase(),
      partySignerPublicKey: wallet.publicKey,
      a2aCardPublicKey: a2aAccount.publicKey,
    });

    function ensureActive() {
      if (destroyed) fail();
    }

    async function signCard(card) {
      ensureActive();
      return signA2AAgentCard({
        card,
        signMessage: (raw) => bridgeSigner({
          raw,
          statePath: options.statePath,
          platform: options.platform,
          runIcacls: options.runIcacls,
        }),
      });
    }

    function validateWindow(input) {
      const item = exact(input, ["expiresAtMs", "jti", "nonce"]);
      assertDecimal(item.expiresAtMs);
      assertToken(item.nonce);
      assertToken(item.jti);
      const now = options.nowMs();
      const expires = Number(item.expiresAtMs);
      if (!Number.isSafeInteger(now) || !Number.isSafeInteger(expires) || now >= expires || expires - now > 30_000) fail();
      return Object.freeze({ ...item, issuedAtMs: String(now) });
    }

    async function signCheckpoint({ artifactDigest, artifactType, expiresAtMs, issuedAtMs, previousCheckpointDigest, sequence }) {
      ensureActive();
      const checkpoint = {
        schema: "clockchain.agent-handshake-commitment-checkpoint/v1",
        version: 1,
        protocol: "clockchain.agent-handshake/v2",
        sessionId,
        role: localRole,
        artifactType,
        artifactDigest,
        sequence,
        previousCheckpointDigest: previousCheckpointDigest === null ? null : assertDigest(previousCheckpointDigest),
        issuedAtMs,
        expiresAtMs,
        signerAddress: wallet.address.toLowerCase(),
      };
      return signAgentHandshakeV2CommitmentCheckpoint({
        checkpoint,
        signMessage: async (raw) => {
          const signed = await signExactBytes({
            statePath: options.statePath,
            platform: options.platform,
            runIcacls: options.runIcacls,
            bytesGzipBase64Url: gzipBase64Url(raw),
          });
          return signed.signatureHex;
        },
      });
    }

    return Object.freeze({
      publicBinding() {
        ensureActive();
        return publicBindingValue;
      },
      async signResponderCard(input) {
        try {
          ensureActive();
          if (localRole !== "responder") fail();
          const window = validateWindow(input);
          return await signCard(cardInput({
            address: wallet.address.toLowerCase(),
            publicKey: wallet.publicKey,
            a2aPublicKey: a2aAccount.publicKey,
            role: localRole,
            sessionId,
            runtime: localRuntime,
            peerCardDigest: null,
            ...window,
          }));
        } catch (error) {
          sanitize(error);
        }
      },
      async signInitiatorCard(input) {
        try {
          ensureActive();
          if (localRole !== "initiator") fail();
          const item = exact(input, ["expiresAtMs", "jti", "nonce", "responderCard"]);
          const window = validateWindow({ expiresAtMs: item.expiresAtMs, jti: item.jti, nonce: item.nonce });
          const responderCard = await verifyA2AAgentCard({
            card: item.responderCard,
            expectedSessionId: sessionId,
            expectedRole: "responder",
            nowMs: options.nowMs(),
          });
          if (
            responderCard.runtimeId !== remoteRuntime.runtimeId ||
            responderCard.taskId !== remoteRuntime.taskId ||
            responderCard.workloadAttestationDigest !== remoteRuntime.workloadAttestationDigest ||
            responderCard.endpoint !== remoteRuntime.endpoint
          ) fail();
          return await signCard(cardInput({
            address: wallet.address.toLowerCase(),
            publicKey: wallet.publicKey,
            a2aPublicKey: a2aAccount.publicKey,
            role: localRole,
            sessionId,
            runtime: localRuntime,
            peerCardDigest: a2aAgentCardDigest(responderCard),
            ...window,
          }));
        } catch (error) {
          sanitize(error);
        }
      },
      async signProposalCheckpoint(input) {
        try {
          ensureActive();
          if (localRole !== "initiator") fail();
          const item = exact(input, ["proposalEnvelope"]);
          const now = options.nowMs();
          if (!Number.isSafeInteger(now)) fail();
          const proposal = await verifyAgentHandshakeV2Proposal({
            envelope: item.proposalEnvelope,
            expectedRepositorySha: options.repositorySha,
            expectedSessionId: sessionId,
            expectedTerms: terms,
            nowMs: options.nowMs(),
          });
          if (proposal.payload.initiator.policyDigest !== policyDigest || proposal.payload.initiator.sessionKeyAddress !== wallet.address.toLowerCase()) fail();
          return await signCheckpoint({
            artifactDigest: digestHex(item.proposalEnvelope),
            artifactType: "proposal",
            expiresAtMs: proposal.payload.expiresAtMs,
            issuedAtMs: String(now),
            previousCheckpointDigest: null,
            sequence: "1",
          });
        } catch (error) {
          sanitize(error);
        }
      },
      async signAcceptanceCheckpoint(input) {
        try {
          ensureActive();
          if (localRole !== "responder") fail();
          const item = exact(input, ["acceptanceEnvelope", "proposalCheckpoint", "proposalEnvelope"]);
          const now = options.nowMs();
          if (!Number.isSafeInteger(now)) fail();
          const acceptance = await verifyAgentHandshakeV2Acceptance({
            envelope: item.acceptanceEnvelope,
          proposalEnvelope: item.proposalEnvelope,
          expectedRepositorySha: options.repositorySha,
          expectedSessionId: sessionId,
          expectedTerms: terms,
          nowMs: options.nowMs(),
          });
          if (acceptance.payload.responder.policyDigest !== policyDigest || acceptance.payload.responder.sessionKeyAddress !== wallet.address.toLowerCase()) fail();
          const proposalSigner = acceptance.payload.initiator.sessionKeyAddress;
          await verifyAgentHandshakeV2CommitmentCheckpoint({
            checkpoint: item.proposalCheckpoint,
            expectedSessionId: sessionId,
            expectedRole: "initiator",
            expectedSignerAddress: proposalSigner,
            expectedArtifactType: "proposal",
            expectedArtifactDigest: digestHex(item.proposalEnvelope),
            expectedSequence: "1",
            expectedPreviousCheckpointDigest: null,
            nowMs: now,
          });
          return await signCheckpoint({
            artifactDigest: digestHex(item.acceptanceEnvelope),
            artifactType: "acceptance",
            expiresAtMs: acceptance.payload.expiresAtMs,
            issuedAtMs: String(now),
            previousCheckpointDigest: commitmentCheckpointDigest(item.proposalCheckpoint),
            sequence: "2",
          });
        } catch (error) {
          sanitize(error);
        }
      },
      async destroy() {
        destroyed = true;
        return Object.freeze({ destroyed: true });
      },
    });
  } catch (error) {
    sanitize(error);
  }
}
