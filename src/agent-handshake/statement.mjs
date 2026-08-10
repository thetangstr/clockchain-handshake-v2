import { types } from "node:util";

import { recoverMessageAddress } from "viem";

import { canonicalBytes, digestHex } from "../core/canonical.mjs";
import {
  AGENT_HANDSHAKE_ACCEPTANCE_ENVELOPE_SCHEMA,
  AGENT_HANDSHAKE_ACCEPTANCE_SCHEMA,
  AGENT_HANDSHAKE_PROPOSAL_ENVELOPE_SCHEMA,
  AGENT_HANDSHAKE_PROPOSAL_SCHEMA,
  AGENT_HANDSHAKE_PROTOCOL,
  AGENT_HANDSHAKE_REFERENCE_MAX,
  AGENT_HANDSHAKE_STATEMENT_MAX,
  AGENT_HANDSHAKE_VALIDITY_MAX_MINUTES,
} from "./constants.mjs";

export {
  AGENT_HANDSHAKE_ACCEPTANCE_ENVELOPE_SCHEMA,
  AGENT_HANDSHAKE_ACCEPTANCE_SCHEMA,
  AGENT_HANDSHAKE_PROPOSAL_ENVELOPE_SCHEMA,
  AGENT_HANDSHAKE_PROPOSAL_SCHEMA,
} from "./constants.mjs";

const TERMS_KEYS = Object.freeze([
  "reference",
  "statement",
  "validForMinutes",
]);
const PARTY_KEYS = Object.freeze(["address", "agentId"]);
const PROPOSAL_KEYS = Object.freeze([
  "expiresAtMs",
  "externalActionPerformed",
  "initiator",
  "issuedAtMs",
  "protocol",
  "reference",
  "repositorySha",
  "responder",
  "schema",
  "sessionId",
  "statement",
  "statementDigest",
  "subjectRun",
  "validForMinutes",
]);
const ACCEPTANCE_KEYS = Object.freeze([
  "decision",
  "expiresAtMs",
  "externalActionPerformed",
  "initiator",
  "issuedAtMs",
  "proposalDigest",
  "protocol",
  "reference",
  "repositorySha",
  "responder",
  "schema",
  "sessionId",
  "statementDigest",
  "subjectRun",
]);
const PROPOSAL_ENVELOPE_KEYS = Object.freeze([
  "proposal",
  "schema",
  "signature",
]);
const ACCEPTANCE_ENVELOPE_KEYS = Object.freeze([
  "acceptance",
  "schema",
  "signature",
]);
const SIGNATURE_KEYS = Object.freeze(["address", "algorithm", "value"]);

const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const ADDRESS_PATTERN = /^0x[0-9a-f]{40}$/;
const DECIMAL_PATTERN = /^(?:0|[1-9][0-9]*)$/;
const SHA_PATTERN = /^[0-9a-f]{40}$/;
const DIGEST_PATTERN = /^[0-9a-f]{64}$/;
const SIGNATURE_PATTERN = /^0x[0-9a-f]{130}$/;
const PRINTABLE_PATTERN = /^[ -~]+$/;

export class AgentHandshakeStatementError extends Error {
  constructor() {
    super("Agent handshake statement validation failed.");
    this.name = "AgentHandshakeStatementError";
    this.category = "verification";
    this.code = "AGENT_HANDSHAKE_STATEMENT_INVALID";
  }
}

function invalid() {
  throw new AgentHandshakeStatementError();
}

function snapshot(value, keys) {
  try {
    if (
      value === null ||
      typeof value !== "object" ||
      Array.isArray(value) ||
      types.isProxy(value) ||
      ![Object.prototype, null].includes(Object.getPrototypeOf(value))
    ) invalid();
    const ownKeys = Reflect.ownKeys(value);
    if (
      ownKeys.length !== keys.length ||
      ownKeys.some((key) => typeof key !== "string" || !keys.includes(key))
    ) invalid();
    const result = Object.create(null);
    for (const key of keys) {
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (
        !descriptor ||
        descriptor.enumerable !== true ||
        !Object.hasOwn(descriptor, "value")
      ) invalid();
      result[key] = descriptor.value;
    }
    return result;
  } catch (error) {
    if (error instanceof AgentHandshakeStatementError) throw error;
    invalid();
  }
}

function printable(value, max) {
  return (
    typeof value === "string" &&
    value.length > 0 &&
    value.length <= max &&
    PRINTABLE_PATTERN.test(value) &&
    value.trim() === value
  );
}

function decimal(value) {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length > 16 ||
    !DECIMAL_PATTERN.test(value)
  ) invalid();
  try {
    if (BigInt(value) > BigInt(Number.MAX_SAFE_INTEGER)) invalid();
  } catch {
    invalid();
  }
}

function party(value) {
  const result = snapshot(value, PARTY_KEYS);
  if (!ADDRESS_PATTERN.test(result.address)) invalid();
  decimal(result.agentId);
  return Object.freeze(result);
}

function termsSnapshot(value) {
  const result = snapshot(value, TERMS_KEYS);
  if (
    !printable(result.reference, AGENT_HANDSHAKE_REFERENCE_MAX) ||
    !printable(result.statement, AGENT_HANDSHAKE_STATEMENT_MAX)
  ) invalid();
  decimal(result.validForMinutes);
  const minutes = BigInt(result.validForMinutes);
  if (minutes < 1n || minutes > BigInt(AGENT_HANDSHAKE_VALIDITY_MAX_MINUTES)) {
    invalid();
  }
  return Object.freeze(result);
}

function signature(value) {
  const result = snapshot(value, SIGNATURE_KEYS);
  if (
    !ADDRESS_PATTERN.test(result.address) ||
    result.algorithm !== "eip191" ||
    !SIGNATURE_PATTERN.test(result.value)
  ) invalid();
  return Object.freeze(result);
}

function proposalSnapshot(value) {
  const result = snapshot(value, PROPOSAL_KEYS);
  const initiator = party(result.initiator);
  const responder = party(result.responder);
  decimal(result.issuedAtMs);
  decimal(result.expiresAtMs);
  const terms = termsSnapshot({
    reference: result.reference,
    statement: result.statement,
    validForMinutes: result.validForMinutes,
  });
  if (
    result.schema !== AGENT_HANDSHAKE_PROPOSAL_SCHEMA ||
    result.protocol !== AGENT_HANDSHAKE_PROTOCOL ||
    result.externalActionPerformed !== false ||
    result.subjectRun !== "stakeholder" ||
    !SHA_PATTERN.test(result.repositorySha) ||
    !UUID_PATTERN.test(result.sessionId) ||
    !DIGEST_PATTERN.test(result.statementDigest) ||
    result.statementDigest !== agentHandshakeStatementDigest(terms) ||
    initiator.address === responder.address ||
    BigInt(result.issuedAtMs) >= BigInt(result.expiresAtMs) ||
    BigInt(result.expiresAtMs) !==
      BigInt(result.issuedAtMs) + BigInt(terms.validForMinutes) * 60_000n
  ) invalid();
  return Object.freeze({ ...result, initiator, responder });
}

function acceptanceSnapshot(value) {
  const result = snapshot(value, ACCEPTANCE_KEYS);
  const initiator = party(result.initiator);
  const responder = party(result.responder);
  decimal(result.issuedAtMs);
  decimal(result.expiresAtMs);
  if (
    result.schema !== AGENT_HANDSHAKE_ACCEPTANCE_SCHEMA ||
    result.protocol !== AGENT_HANDSHAKE_PROTOCOL ||
    result.decision !== "ACCEPTED" ||
    result.externalActionPerformed !== false ||
    result.subjectRun !== "stakeholder" ||
    !printable(result.reference, AGENT_HANDSHAKE_REFERENCE_MAX) ||
    !SHA_PATTERN.test(result.repositorySha) ||
    !UUID_PATTERN.test(result.sessionId) ||
    !DIGEST_PATTERN.test(result.proposalDigest) ||
    !DIGEST_PATTERN.test(result.statementDigest) ||
    initiator.address === responder.address ||
    BigInt(result.issuedAtMs) >= BigInt(result.expiresAtMs)
  ) invalid();
  return Object.freeze({ ...result, initiator, responder });
}

function proposalEnvelopeSnapshot(value) {
  const result = snapshot(value, PROPOSAL_ENVELOPE_KEYS);
  if (result.schema !== AGENT_HANDSHAKE_PROPOSAL_ENVELOPE_SCHEMA) invalid();
  return Object.freeze({
    proposal: proposalSnapshot(result.proposal),
    schema: result.schema,
    signature: signature(result.signature),
  });
}

function acceptanceEnvelopeSnapshot(value) {
  const result = snapshot(value, ACCEPTANCE_ENVELOPE_KEYS);
  if (result.schema !== AGENT_HANDSHAKE_ACCEPTANCE_ENVELOPE_SCHEMA) invalid();
  return Object.freeze({
    acceptance: acceptanceSnapshot(result.acceptance),
    schema: result.schema,
    signature: signature(result.signature),
  });
}

function assertNowMs(nowMs) {
  if (!Number.isSafeInteger(nowMs) || nowMs < 0) invalid();
}

function expectedContext({ expectedTerms, expectedSessionId, expectedRepositorySha }) {
  const terms = termsSnapshot(expectedTerms);
  if (!UUID_PATTERN.test(expectedSessionId) || !SHA_PATTERN.test(expectedRepositorySha)) {
    invalid();
  }
  return { expectedRepositorySha, expectedSessionId, terms };
}

async function recoveredAddress(message, value) {
  try {
    return (await recoverMessageAddress({
      message: { raw: canonicalBytes(message) },
      signature: value,
    })).toLowerCase();
  } catch {
    invalid();
  }
}

export function validateAgentHandshakeTerms(value) {
  return Object.freeze({ ...termsSnapshot(value) });
}

export function agentHandshakeStatementDigest(value) {
  return digestHex(termsSnapshot(value));
}

export function agentHandshakeProposalDigest(envelope) {
  return digestHex(proposalEnvelopeSnapshot(envelope).proposal);
}

export function agentHandshakeAcceptanceDigest(envelope) {
  return digestHex(acceptanceEnvelopeSnapshot(envelope).acceptance);
}

export async function signAgentHandshakeProposal({ proposal, signMessage }) {
  const signedProposal = proposalSnapshot(proposal);
  if (typeof signMessage !== "function") invalid();
  let value;
  try {
    value = await signMessage(canonicalBytes(signedProposal));
  } catch {
    invalid();
  }
  return Object.freeze({
    proposal: signedProposal,
    schema: AGENT_HANDSHAKE_PROPOSAL_ENVELOPE_SCHEMA,
    signature: signature({
      address: signedProposal.initiator.address,
      algorithm: "eip191",
      value,
    }),
  });
}

export async function verifyAgentHandshakeProposal({
  envelope,
  expectedTerms,
  expectedSessionId,
  expectedRepositorySha,
  nowMs,
}) {
  const verified = proposalEnvelopeSnapshot(envelope);
  const expected = expectedContext({
    expectedRepositorySha,
    expectedSessionId,
    expectedTerms,
  });
  assertNowMs(nowMs);
  if (
    verified.proposal.sessionId !== expected.expectedSessionId ||
    verified.proposal.repositorySha !== expected.expectedRepositorySha ||
    verified.proposal.reference !== expected.terms.reference ||
    verified.proposal.statement !== expected.terms.statement ||
    verified.proposal.validForMinutes !== expected.terms.validForMinutes ||
    nowMs < Number(verified.proposal.issuedAtMs) ||
    nowMs >= Number(verified.proposal.expiresAtMs) ||
    verified.signature.address !== verified.proposal.initiator.address
  ) invalid();
  if (
    await recoveredAddress(verified.proposal, verified.signature.value) !==
    verified.proposal.initiator.address
  ) invalid();
  return verified;
}

export async function signAgentHandshakeAcceptance({
  acceptance,
  proposalEnvelope,
  signMessage,
}) {
  const proposal = proposalEnvelopeSnapshot(proposalEnvelope);
  const signedAcceptance = acceptanceSnapshot(acceptance);
  if (
    signedAcceptance.proposalDigest !== agentHandshakeProposalDigest(proposal) ||
    signedAcceptance.sessionId !== proposal.proposal.sessionId ||
    signedAcceptance.repositorySha !== proposal.proposal.repositorySha ||
    signedAcceptance.reference !== proposal.proposal.reference ||
    signedAcceptance.statementDigest !== proposal.proposal.statementDigest ||
    canonicalBytes(signedAcceptance.initiator).compare(canonicalBytes(proposal.proposal.initiator)) !== 0 ||
    canonicalBytes(signedAcceptance.responder).compare(canonicalBytes(proposal.proposal.responder)) !== 0 ||
    BigInt(signedAcceptance.issuedAtMs) < BigInt(proposal.proposal.issuedAtMs) ||
    BigInt(signedAcceptance.expiresAtMs) > BigInt(proposal.proposal.expiresAtMs) ||
    typeof signMessage !== "function"
  ) invalid();
  let value;
  try {
    value = await signMessage(canonicalBytes(signedAcceptance));
  } catch {
    invalid();
  }
  return Object.freeze({
    acceptance: signedAcceptance,
    schema: AGENT_HANDSHAKE_ACCEPTANCE_ENVELOPE_SCHEMA,
    signature: signature({
      address: signedAcceptance.responder.address,
      algorithm: "eip191",
      value,
    }),
  });
}

export async function verifyAgentHandshakeAcceptance({
  envelope,
  proposalEnvelope,
  expectedTerms,
  expectedSessionId,
  expectedRepositorySha,
  nowMs,
}) {
  const proposal = await verifyAgentHandshakeProposal({
    envelope: proposalEnvelope,
    expectedRepositorySha,
    expectedSessionId,
    expectedTerms,
    nowMs,
  });
  const verified = acceptanceEnvelopeSnapshot(envelope);
  assertNowMs(nowMs);
  if (
    verified.acceptance.proposalDigest !== agentHandshakeProposalDigest(proposal) ||
    verified.acceptance.sessionId !== proposal.proposal.sessionId ||
    verified.acceptance.repositorySha !== proposal.proposal.repositorySha ||
    verified.acceptance.reference !== proposal.proposal.reference ||
    verified.acceptance.statementDigest !== proposal.proposal.statementDigest ||
    verified.acceptance.expiresAtMs !== proposal.proposal.expiresAtMs ||
    canonicalBytes(verified.acceptance.initiator).compare(canonicalBytes(proposal.proposal.initiator)) !== 0 ||
    canonicalBytes(verified.acceptance.responder).compare(canonicalBytes(proposal.proposal.responder)) !== 0 ||
    nowMs < Number(verified.acceptance.issuedAtMs) ||
    nowMs >= Number(verified.acceptance.expiresAtMs) ||
    verified.signature.address !== verified.acceptance.responder.address
  ) invalid();
  if (
    await recoveredAddress(verified.acceptance, verified.signature.value) !==
    verified.acceptance.responder.address
  ) invalid();
  return verified;
}
