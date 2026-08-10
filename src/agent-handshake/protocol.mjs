import { types } from "node:util";

import { canonicalBytes, digestHex } from "../core/canonical.mjs";
import {
  AGENT_HANDSHAKE_PROTOCOL,
  AGENT_HANDSHAKE_REFERENCE_MAX,
} from "./constants.mjs";

export const AGENT_HANDSHAKE_TRANSITION_SCHEMA =
  "clockchain.agent-handshake-transition/v1";

const TRANSITION_KEYS = Object.freeze([
  "expiresAtMs",
  "externalActionPerformed",
  "initiator",
  "kind",
  "predecessor",
  "protocol",
  "reference",
  "responder",
  "schema",
  "sequence",
  "sessionDigest",
  "statementDigest",
]);
const PARTY_KEYS = Object.freeze(["address", "agentId"]);
const ADDRESS_PATTERN = /^0x[0-9a-f]{40}$/;
const DECIMAL_PATTERN = /^(?:0|[1-9][0-9]*)$/;
const DIGEST_PATTERN = /^[0-9a-f]{64}$/;
const PRINTABLE_PATTERN = /^[ -~]+$/;
const KINDS = Object.freeze({
  ACCEPTED: Object.freeze({ sequence: "2", predecessor: true }),
  ACKNOWLEDGED: Object.freeze({ sequence: "3", predecessor: true }),
  PROPOSED: Object.freeze({ sequence: "1", predecessor: false }),
});

export class AgentHandshakeProtocolError extends Error {
  constructor(code = "AGENT_HANDSHAKE_TRANSITION_INVALID") {
    super("Agent handshake transition validation failed.");
    this.name = "AgentHandshakeProtocolError";
    this.category = "verification";
    this.code = code;
  }
}

function invalid(code) {
  throw new AgentHandshakeProtocolError(code);
}

function record(value, keys) {
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
    const result = {};
    for (const key of keys) {
      const property = Object.getOwnPropertyDescriptor(value, key);
      if (
        property?.enumerable !== true ||
        !Object.hasOwn(property, "value")
      ) invalid();
      result[key] = property.value;
    }
    return result;
  } catch (error) {
    if (error instanceof AgentHandshakeProtocolError) throw error;
    invalid();
  }
}

function decimal(value) {
  return (
    typeof value === "string" &&
    value.length <= 16 &&
    DECIMAL_PATTERN.test(value)
  );
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

function party(value) {
  const result = record(value, PARTY_KEYS);
  if (
    !ADDRESS_PATTERN.test(result.address) ||
    !decimal(result.agentId)
  ) invalid();
  return Object.freeze(result);
}

function same(left, right) {
  return canonicalBytes(left).equals(canonicalBytes(right));
}

function transition(value) {
  const result = record(value, TRANSITION_KEYS);
  const kind = KINDS[result.kind];
  const initiator = party(result.initiator);
  const responder = party(result.responder);
  if (
    !kind ||
    result.schema !== AGENT_HANDSHAKE_TRANSITION_SCHEMA ||
    result.protocol !== AGENT_HANDSHAKE_PROTOCOL ||
    result.externalActionPerformed !== false ||
    result.sequence !== kind.sequence ||
    (kind.predecessor
      ? !DIGEST_PATTERN.test(result.predecessor)
      : result.predecessor !== null) ||
    !printable(result.reference, AGENT_HANDSHAKE_REFERENCE_MAX) ||
    !decimal(result.expiresAtMs) ||
    !DIGEST_PATTERN.test(result.sessionDigest) ||
    !DIGEST_PATTERN.test(result.statementDigest) ||
    initiator.address === responder.address
  ) invalid();
  return Object.freeze({ ...result, initiator, responder });
}

function binding(value, kind, sequence, predecessor) {
  return transition({
    expiresAtMs: value.expiresAtMs,
    externalActionPerformed: false,
    initiator: value.initiator,
    kind,
    predecessor,
    protocol: AGENT_HANDSHAKE_PROTOCOL,
    reference: value.reference,
    responder: value.responder,
    schema: AGENT_HANDSHAKE_TRANSITION_SCHEMA,
    sequence,
    sessionDigest: value.sessionDigest,
    statementDigest: value.statementDigest,
  });
}

function assertPrevious(input, previous, expectedKind) {
  const verified = transition(previous);
  if (
    verified.kind !== expectedKind ||
    input.predecessor !== agentTransitionDigest(verified) ||
    input.expiresAtMs !== verified.expiresAtMs ||
    input.reference !== verified.reference ||
    input.sessionDigest !== verified.sessionDigest ||
    input.statementDigest !== verified.statementDigest ||
    !same(input.initiator, verified.initiator) ||
    !same(input.responder, verified.responder)
  ) invalid("AGENT_HANDSHAKE_PREDECESSOR_INVALID");
  return verified;
}

export function createAgentProposal(input) {
  return binding(input, "PROPOSED", "1", null);
}

export function createAgentAcceptance(input, proposed) {
  assertPrevious(input, proposed, "PROPOSED");
  return binding(input, "ACCEPTED", "2", input.predecessor);
}

export function createAgentAcknowledgment(input, accepted) {
  assertPrevious(input, accepted, "ACCEPTED");
  return binding(input, "ACKNOWLEDGED", "3", input.predecessor);
}

export function validateAgentTransition(value) {
  return transition(value);
}

export function agentTransitionDigest(value) {
  return digestHex(transition(value));
}

export function validateAgentTransitionChain(value) {
  if (!Array.isArray(value) || value.length !== 3) {
    invalid("AGENT_HANDSHAKE_CHAIN_INVALID");
  }
  const [proposed, accepted, acknowledged] = value.map(transition);
  if (
    proposed.kind !== "PROPOSED" ||
    accepted.kind !== "ACCEPTED" ||
    acknowledged.kind !== "ACKNOWLEDGED" ||
    accepted.predecessor !== agentTransitionDigest(proposed) ||
    acknowledged.predecessor !== agentTransitionDigest(accepted)
  ) invalid("AGENT_HANDSHAKE_CHAIN_INVALID");
  for (const later of [accepted, acknowledged]) {
    if (
      later.expiresAtMs !== proposed.expiresAtMs ||
      later.reference !== proposed.reference ||
      later.sessionDigest !== proposed.sessionDigest ||
      later.statementDigest !== proposed.statementDigest ||
      !same(later.initiator, proposed.initiator) ||
      !same(later.responder, proposed.responder)
    ) invalid("AGENT_HANDSHAKE_CHAIN_INVALID");
  }
  return Object.freeze([proposed, accepted, acknowledged]);
}
