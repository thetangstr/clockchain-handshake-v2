import { canonicalBytes } from "../core/canonical.mjs";
import {
  agentDescriptorDigest,
  verifyAgentDescriptorEnvelope,
} from "./descriptor.mjs";
import { verifyAgentHandshakeEvidence } from "./evidence.mjs";
import {
  agentTransitionDigest,
  validateAgentTransitionChain,
} from "./protocol.mjs";
import {
  agentHandshakeStatementDigest,
  verifyAgentHandshakeAcceptance,
} from "./statement.mjs";

export const AGENT_HANDSHAKE_VERDICT_SCHEMA =
  "clockchain.agent-handshake-verdict/v1";

const ADDRESS_PATTERN = /^0x[0-9a-f]{40}$/;
const DECIMAL_PATTERN = /^(?:0|[1-9][0-9]*)$/;
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const RECEIPT_KEYS = Object.freeze([
  "blockHeight",
  "blockTimeRaw",
  "digest",
  "kind",
  "ledgerId",
]);
const RECEIPT_KINDS = Object.freeze([
  "proposal",
  "acceptance",
  "acknowledgment",
]);

export class AgentHandshakeVerdictError extends Error {
  constructor() {
    super("Agent handshake independent verification failed.");
    this.name = "AgentHandshakeVerdictError";
    this.category = "verification";
    this.code = "AGENT_HANDSHAKE_VERIFICATION_FAILED";
  }
}

function fail() {
  throw new AgentHandshakeVerdictError();
}

function same(left, right) {
  return canonicalBytes(left).equals(canonicalBytes(right));
}

function receipt(value, index, expectedDigest) {
  if (
    value === null ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    Object.keys(value).length !== RECEIPT_KEYS.length ||
    Object.keys(value).some((key) => !RECEIPT_KEYS.includes(key)) ||
    value.kind !== RECEIPT_KINDS[index] ||
    !DECIMAL_PATTERN.test(value.blockHeight) ||
    typeof value.blockTimeRaw !== "string" ||
    value.blockTimeRaw.length === 0 ||
    value.digest !== expectedDigest ||
    !UUID_PATTERN.test(value.ledgerId)
  ) fail();
  return Object.freeze(Object.fromEntries(RECEIPT_KEYS.map((key) => [key, value[key]])));
}

function receipts(value, transitions) {
  if (!Array.isArray(value) || value.length !== 3) fail();
  const verified = value.map((entry, index) =>
    receipt(entry, index, agentTransitionDigest(transitions[index])),
  );
  if (
    BigInt(verified[0].blockHeight) >= BigInt(verified[1].blockHeight) ||
    BigInt(verified[1].blockHeight) >= BigInt(verified[2].blockHeight)
  ) fail();
  return Object.freeze(verified);
}

async function owner(resolveOwner, party) {
  if (typeof resolveOwner !== "function") fail();
  let value;
  try {
    value = await resolveOwner(party.agentId);
  } catch {
    fail();
  }
  if (typeof value !== "string" || !ADDRESS_PATTERN.test(value.toLowerCase())) fail();
  return value.toLowerCase();
}

function assertDescriptorBindings(descriptor, proposal) {
  if (
    descriptor.sessionId !== proposal.sessionId ||
    descriptor.repositorySha !== proposal.repositorySha ||
    descriptor.reference !== proposal.reference ||
    descriptor.statementDigest !== proposal.statementDigest ||
    descriptor.expiresAtMs !== proposal.expiresAtMs ||
    !same(descriptor.initiator, proposal.initiator) ||
    !same(descriptor.responder, proposal.responder)
  ) fail();
}

export async function verifyAgentHandshakeAuthorization(input) {
  try {
    const acceptance = await verifyAgentHandshakeAcceptance({
      envelope: input.acceptanceEnvelope,
      expectedRepositorySha: input.expectedRepositorySha,
      expectedSessionId: input.expectedSessionId,
      expectedTerms: input.expectedTerms,
      nowMs: input.nowMs,
      proposalEnvelope: input.proposalEnvelope,
    });
    const descriptorEnvelope = verifyAgentDescriptorEnvelope(
      input.descriptorEnvelope,
      { expectedPublicKey: input.expectedPublicKey },
    );
    const proposal = input.proposalEnvelope.proposal;
    const descriptor = descriptorEnvelope.descriptor;
    assertDescriptorBindings(descriptor, proposal);
    if (
      acceptance.acceptance.statementDigest !==
        agentHandshakeStatementDigest(input.expectedTerms)
    ) fail();

    const sessionDigest = agentDescriptorDigest(descriptor);
    const transitions = validateAgentTransitionChain(input.transitions);
    for (const transition of transitions) {
      if (
        transition.sessionDigest !== sessionDigest ||
        transition.statementDigest !== descriptor.statementDigest ||
        transition.reference !== descriptor.reference ||
        transition.expiresAtMs !== descriptor.expiresAtMs ||
        !same(transition.initiator, descriptor.initiator) ||
        !same(transition.responder, descriptor.responder)
      ) fail();
    }
    const verifiedReceipts = receipts(input.receipts, transitions);
    const transitionDigests = transitions.map(agentTransitionDigest);
    if (
      input.evidence === null ||
      typeof input.evidence !== "object" ||
      input.evidence.initiator === null ||
      input.evidence.responder === null
    ) fail();
    for (const role of ["initiator", "responder"]) {
      await verifyAgentHandshakeEvidence({
        envelope: input.evidence[role],
        expectedParty: descriptor[role],
        expectedReference: descriptor.reference,
        expectedRepositorySha: descriptor.repositorySha,
        expectedRole: role,
        expectedSessionDigest: sessionDigest,
        expectedStatementDigest: descriptor.statementDigest,
        expectedTransitionDigests: transitionDigests,
      });
    }
    const initiatorOwner = await owner(input.resolveOwner, descriptor.initiator);
    const responderOwner = await owner(input.resolveOwner, descriptor.responder);
    if (
      initiatorOwner !== descriptor.initiator.address ||
      responderOwner !== descriptor.responder.address ||
      initiatorOwner === responderOwner
    ) fail();

    return Object.freeze({
      externalActionPerformed: false,
      outcome: "VERIFIED",
      reference: descriptor.reference,
      repositorySha: descriptor.repositorySha,
      schema: AGENT_HANDSHAKE_VERDICT_SCHEMA,
      sessionDigest,
      statementDigest: descriptor.statementDigest,
      transitions: verifiedReceipts,
    });
  } catch (error) {
    if (error instanceof AgentHandshakeVerdictError) throw error;
    fail();
  }
}
