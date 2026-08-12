import { types } from "node:util";

import { validateIdentityPolicy } from "../agent-handshake/v2/terms.mjs";

export const AGENT_HANDSHAKE_V2_SNAPSHOT_SCHEMA =
  "clockchain.agent-handshake-snapshot/v2";

const SNAPSHOT_KEYS = Object.freeze([
  "schema",
  "protocol",
  "sessionId",
  "repositorySha",
  "hostTrust",
  "timing",
  "invitation",
  "terms",
  "policies",
  "parties",
  "statements",
  "receipts",
  "evidence",
  "checker",
  "certificate",
  "freshness",
  "failure",
  "externalBusinessActionPerformed",
]);
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const SHA = /^[0-9a-f]{40}$/;
const DIGEST = /^[0-9a-f]{64}$/;
const DECIMAL = /^(?:0|[1-9][0-9]*)$/;
const ADDRESS = /^0x[0-9a-f]{40}$/;
const TRANSACTION = /^0x[0-9a-f]{64}$/;
const BASE64 = /^[A-Za-z0-9+/]+={0,2}$/;
const KID = /^[a-z0-9][a-z0-9-]{0,63}$/;

export class AgentHandshakeV2SnapshotError extends Error {
  constructor() {
    super("Agent handshake v2 snapshot validation failed.");
    this.name = "AgentHandshakeV2SnapshotError";
    this.category = "monitor-snapshot";
    this.code = "AGENT_HANDSHAKE_V2_SNAPSHOT_INVALID";
  }
}

function invalid() {
  throw new AgentHandshakeV2SnapshotError();
}

function exact(value, keys) {
  try {
    if (
      value === null ||
      typeof value !== "object" ||
      Array.isArray(value) ||
      types.isProxy(value) ||
      ![Object.prototype, null].includes(Object.getPrototypeOf(value))
    ) invalid();
    const actual = Reflect.ownKeys(value);
    if (
      actual.length !== keys.length ||
      actual.some((key) => typeof key !== "string" || !keys.includes(key))
    ) invalid();
    const result = {};
    for (const key of keys) {
      const property = Object.getOwnPropertyDescriptor(value, key);
      if (property?.enumerable !== true || !Object.hasOwn(property, "value")) invalid();
      result[key] = property.value;
    }
    return result;
  } catch (error) {
    if (error instanceof AgentHandshakeV2SnapshotError) throw error;
    invalid();
  }
}

function safeMs(value) {
  if (!Number.isSafeInteger(value) || value < 0) invalid();
  return value;
}

function nullable(value, parser) {
  return value === null ? null : parser(value);
}

function hostTrust(value) {
  const item = exact(value, [
    "rootKid",
    "rootFingerprint",
    "sessionPublicKey",
    "sessionKeyCertificateDigest",
  ]);
  if (
    !KID.test(item.rootKid) ||
    !DIGEST.test(item.rootFingerprint) ||
    typeof item.sessionPublicKey !== "string" ||
    !BASE64.test(item.sessionPublicKey) ||
    Buffer.from(item.sessionPublicKey, "base64").length !== 32 ||
    !DIGEST.test(item.sessionKeyCertificateDigest)
  ) invalid();
  return Object.freeze(item);
}

function timing(value) {
  const item = exact(value, [
    "createdAtMs",
    "invitationExpiresAtMs",
    "sessionDeadlineMs",
    "agreementValidForSeconds",
  ]);
  safeMs(item.createdAtMs);
  safeMs(item.invitationExpiresAtMs);
  safeMs(item.sessionDeadlineMs);
  if (
    item.invitationExpiresAtMs <= item.createdAtMs ||
    item.sessionDeadlineMs <= item.invitationExpiresAtMs ||
    item.invitationExpiresAtMs - item.createdAtMs !== 120_000 ||
    item.sessionDeadlineMs - item.createdAtMs !== 10 * 60_000 ||
    item.agreementValidForSeconds !== "90"
  ) invalid();
  return Object.freeze(item);
}

function invitation(value, timingFacts) {
  const item = exact(value, ["createdAtMs", "responderClaimedAtMs"]);
  if (item.createdAtMs === null) {
    if (item.responderClaimedAtMs !== null) invalid();
    return Object.freeze(item);
  }
  safeMs(item.createdAtMs);
  if (item.createdAtMs < timingFacts.createdAtMs ||
    item.createdAtMs >= timingFacts.invitationExpiresAtMs) invalid();
  if (item.responderClaimedAtMs !== null) {
    safeMs(item.responderClaimedAtMs);
    if (
      item.responderClaimedAtMs < item.createdAtMs ||
      item.responderClaimedAtMs >= timingFacts.invitationExpiresAtMs
    ) invalid();
  }
  return Object.freeze(item);
}

function terms(value) {
  const item = exact(value, ["reference", "statement", "identityPolicy"]);
  if (
    typeof item.reference !== "string" ||
    item.reference.length === 0 ||
    typeof item.statement !== "string" ||
    item.statement.length === 0
  ) invalid();
  let identityPolicy;
  try { identityPolicy = validateIdentityPolicy(item.identityPolicy); } catch { invalid(); }
  return Object.freeze({
    reference: item.reference,
    statement: item.statement,
    identityPolicy,
  });
}

function policy(value) {
  const item = exact(value, ["digest", "committedAtMs"]);
  if (!DIGEST.test(item.digest)) invalid();
  safeMs(item.committedAtMs);
  return Object.freeze(item);
}

function registration(value, identityPolicy) {
  const item = exact(value, [
    "agentId",
    "chainId",
    "registryAddress",
    "reference",
    "registrationTx",
    "registrationBlock",
  ]);
  if (
    !DECIMAL.test(item.agentId) ||
    item.chainId !== identityPolicy.chainId ||
    item.registryAddress !== identityPolicy.registryAddress ||
    item.reference !== item.chainId + ":" + item.registryAddress + ":" + item.agentId ||
    !TRANSACTION.test(item.registrationTx) ||
    !DECIMAL.test(item.registrationBlock)
  ) invalid();
  return Object.freeze(item);
}

function party(value, identityPolicy) {
  const item = exact(value, ["sessionKeyAddress", "erc8004"]);
  if (!ADDRESS.test(item.sessionKeyAddress)) invalid();
  const erc8004 = identityPolicy.erc8004 === "not_required"
    ? item.erc8004 === null ? null : invalid()
    : item.erc8004 === null ? invalid() : registration(item.erc8004, identityPolicy);
  return Object.freeze({
    sessionKeyAddress: item.sessionKeyAddress,
    erc8004,
  });
}

function statements(value) {
  const item = exact(value, ["proposalDigest", "acceptanceDigest"]);
  for (const key of ["proposalDigest", "acceptanceDigest"]) {
    if (item[key] !== null && !DIGEST.test(item[key])) invalid();
  }
  return Object.freeze(item);
}

function receipt(value, kind) {
  const item = exact(value, [
    "blockHeight",
    "blockTimeRaw",
    "digest",
    "explorerUrl",
    "kind",
    "ledgerId",
  ]);
  if (
    item.kind !== kind ||
    !DECIMAL.test(item.blockHeight) ||
    typeof item.blockTimeRaw !== "string" ||
    item.blockTimeRaw.length === 0 ||
    !DIGEST.test(item.digest) ||
    typeof item.explorerUrl !== "string" ||
    !/^https:\/\//.test(item.explorerUrl) ||
    !UUID.test(item.ledgerId)
  ) invalid();
  return Object.freeze(item);
}

function evidence(value) {
  const item = exact(value, ["digest", "receivedAtMs"]);
  if (!DIGEST.test(item.digest)) invalid();
  safeMs(item.receivedAtMs);
  return Object.freeze(item);
}

function checker(value) {
  const item = exact(value, ["stage", "lastSeenMs"]);
  if (!["WAITING", "VERIFYING", "VERIFIED", "FAILED"].includes(item.stage)) invalid();
  safeMs(item.lastSeenMs);
  return Object.freeze(item);
}

function certificate(value) {
  const item = exact(value, ["digest", "issuedAtMs", "outcome"]);
  if (!DIGEST.test(item.digest) || item.outcome !== "VERIFIED") invalid();
  safeMs(item.issuedAtMs);
  return Object.freeze(item);
}

function heartbeat(value) {
  const item = exact(value, ["lastSeenMs"]);
  safeMs(item.lastSeenMs);
  return Object.freeze(item);
}

function failure(value) {
  const item = exact(value, ["reasonCode"]);
  if (
    typeof item.reasonCode !== "string" ||
    !/^[A-Z][A-Z0-9_]{0,63}$/.test(item.reasonCode)
  ) invalid();
  return Object.freeze(item);
}

function snapshot(value) {
  const item = exact(value, SNAPSHOT_KEYS);
  if (
    item.schema !== AGENT_HANDSHAKE_V2_SNAPSHOT_SCHEMA ||
    item.protocol !== "clockchain.agent-handshake/v2" ||
    !UUID.test(item.sessionId) ||
    !SHA.test(item.repositorySha) ||
    item.externalBusinessActionPerformed !== false
  ) invalid();
  const timingFacts = timing(item.timing);
  const termsFacts = terms(item.terms);
  const policiesObject = exact(item.policies, ["initiator", "responder"]);
  const partiesObject = exact(item.parties, ["initiator", "responder"]);
  const receiptsObject = exact(item.receipts, [
    "proposal",
    "acceptance",
    "acknowledgment",
  ]);
  const evidenceObject = exact(item.evidence, ["initiator", "responder"]);
  const freshnessObject = exact(item.freshness, [
    "initiator",
    "responder",
    "host",
    "checker",
  ]);
  const policies = Object.freeze({
    initiator: nullable(policiesObject.initiator, policy),
    responder: nullable(policiesObject.responder, policy),
  });
  const parties = Object.freeze({
    initiator: nullable(
      partiesObject.initiator,
      (entry) => party(entry, termsFacts.identityPolicy),
    ),
    responder: nullable(
      partiesObject.responder,
      (entry) => party(entry, termsFacts.identityPolicy),
    ),
  });
  if (
    parties.initiator !== null &&
    parties.responder !== null &&
    (
      parties.initiator.sessionKeyAddress === parties.responder.sessionKeyAddress ||
      (
        parties.initiator.erc8004 !== null &&
        parties.responder.erc8004 !== null &&
        parties.initiator.erc8004.agentId === parties.responder.erc8004.agentId
      )
    )
  ) invalid();
  return Object.freeze({
    schema: item.schema,
    protocol: item.protocol,
    sessionId: item.sessionId,
    repositorySha: item.repositorySha,
    hostTrust: hostTrust(item.hostTrust),
    timing: timingFacts,
    invitation: invitation(item.invitation, timingFacts),
    terms: termsFacts,
    policies,
    parties,
    statements: statements(item.statements),
    receipts: Object.freeze({
      proposal: nullable(receiptsObject.proposal, (entry) => receipt(entry, "proposal")),
      acceptance: nullable(receiptsObject.acceptance, (entry) => receipt(entry, "acceptance")),
      acknowledgment: nullable(
        receiptsObject.acknowledgment,
        (entry) => receipt(entry, "acknowledgment"),
      ),
    }),
    evidence: Object.freeze({
      initiator: nullable(evidenceObject.initiator, evidence),
      responder: nullable(evidenceObject.responder, evidence),
    }),
    checker: checker(item.checker),
    certificate: nullable(item.certificate, certificate),
    freshness: Object.freeze({
      initiator: nullable(freshnessObject.initiator, heartbeat),
      responder: nullable(freshnessObject.responder, heartbeat),
      host: nullable(freshnessObject.host, heartbeat),
      checker: nullable(freshnessObject.checker, heartbeat),
    }),
    failure: nullable(item.failure, failure),
    externalBusinessActionPerformed: false,
  });
}

export function validateAgentHandshakeV2Snapshot(value) {
  snapshot(value);
  return true;
}

export function buildAgentHandshakeV2Snapshot(value) {
  return snapshot(value);
}
