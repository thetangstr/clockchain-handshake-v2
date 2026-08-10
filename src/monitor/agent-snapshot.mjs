export const AGENT_HANDSHAKE_SNAPSHOT_SCHEMA =
  "clockchain.agent-handshake-snapshot/v1";

export const AGENT_HANDSHAKE_STAGES = Object.freeze([
  "SESSION_STARTED",
  "IDENTITIES_REGISTERED",
  "STATEMENT_PROPOSED",
  "STATEMENT_ACCEPTED",
  "PROPOSED",
  "ACCEPTED",
  "ACKNOWLEDGED",
  "EVIDENCE_RECEIVED",
  "VERIFYING",
  "CERTIFIED",
]);

const SNAPSHOT_KEYS = Object.freeze([
  "anchors",
  "currentStage",
  "externalActionPerformed",
  "funding",
  "heartbeat",
  "identities",
  "reasonCode",
  "reference",
  "schema",
  "sessionId",
  "stageHistory",
  "statement",
  "subjectRun",
  "updatedAtMs",
  "verdict",
]);
const IDENTITY_KEYS = Object.freeze([
  "address",
  "agentId",
  "chainId",
  "reference",
  "registryAddress",
]);
const ANCHOR_KEYS = Object.freeze([
  "actor",
  "blockHeight",
  "blockTime",
  "explorerUrl",
  "kind",
  "ledgerId",
  "receipt",
  "terms",
]);
const TERMS_KEYS = Object.freeze([
  "expiresAtMs",
  "predecessor",
  "reference",
  "sequence",
  "sessionDigest",
  "statementDigest",
]);
const VERDICT_KEYS = Object.freeze([
  "externalActionPerformed",
  "outcome",
  "reference",
  "sessionDigest",
  "statementDigest",
]);
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const ADDRESS_PATTERN = /^0x[0-9a-f]{40}$/;
const DECIMAL_PATTERN = /^(?:0|[1-9][0-9]*)$/;
const DIGEST_PATTERN = /^[0-9a-f]{64}$/;
const REGISTRY = "0x8004a818bfb912233c491871b3d84c89a494bd9e";
const CHAIN_ID = "11155111";
const KINDS = Object.freeze(["proposal", "acceptance", "acknowledgment"]);
const ACTORS = Object.freeze(["initiator", "responder", "clockchain"]);

export class AgentHandshakeSnapshotError extends Error {
  constructor() {
    super("Agent handshake snapshot validation failed.");
    this.name = "AgentHandshakeSnapshotError";
    this.category = "monitor-snapshot";
    this.code = "AGENT_HANDSHAKE_SNAPSHOT_INVALID";
  }
}

function invalid() {
  throw new AgentHandshakeSnapshotError();
}

function exact(value, keys) {
  if (
    value === null ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    Object.keys(value).length !== keys.length ||
    Object.keys(value).some((key) => !keys.includes(key))
  ) invalid();
  return value;
}

function identity(value) {
  exact(value, IDENTITY_KEYS);
  if (
    !ADDRESS_PATTERN.test(value.address) ||
    !DECIMAL_PATTERN.test(value.agentId) ||
    value.chainId !== CHAIN_ID ||
    value.registryAddress !== REGISTRY ||
    value.reference !== `eip155:${CHAIN_ID}:${REGISTRY}:${value.agentId}`
  ) invalid();
  return Object.freeze(Object.fromEntries(IDENTITY_KEYS.map((key) => [key, value[key]])));
}

function heartbeat(value) {
  if (value === null) return null;
  exact(value, ["lastSeenMs"]);
  if (!Number.isSafeInteger(value.lastSeenMs) || value.lastSeenMs < 0) invalid();
  return Object.freeze({ lastSeenMs: value.lastSeenMs });
}

function anchor(value, index) {
  if (value === null) return null;
  exact(value, ANCHOR_KEYS);
  exact(value.terms, TERMS_KEYS);
  const expectedActor = ACTORS[index];
  if (
    value.kind !== KINDS[index] ||
    value.actor !== expectedActor ||
    !DECIMAL_PATTERN.test(value.blockHeight) ||
    !Number.isSafeInteger(value.blockTime) ||
    value.blockTime < 0 ||
    typeof value.explorerUrl !== "string" ||
    !/^https?:\/\//.test(value.explorerUrl) ||
    !UUID_PATTERN.test(value.ledgerId) ||
    value.receipt === null ||
    typeof value.receipt !== "object" ||
    Array.isArray(value.receipt) ||
    value.terms.reference.length === 0 ||
    !DECIMAL_PATTERN.test(value.terms.expiresAtMs) ||
    value.terms.sequence !== String(index + 1) ||
    !DIGEST_PATTERN.test(value.terms.sessionDigest) ||
    !DIGEST_PATTERN.test(value.terms.statementDigest) ||
    (index === 0
      ? value.terms.predecessor !== null
      : !DIGEST_PATTERN.test(value.terms.predecessor))
  ) invalid();
  return Object.freeze({
    actor: value.actor,
    blockHeight: value.blockHeight,
    blockTime: value.blockTime,
    explorerUrl: value.explorerUrl,
    kind: value.kind,
    ledgerId: value.ledgerId,
    receipt: Object.freeze({ ...value.receipt }),
    terms: Object.freeze(Object.fromEntries(TERMS_KEYS.map((key) => [key, value.terms[key]]))),
  });
}

function snapshot(value) {
  exact(value, SNAPSHOT_KEYS);
  exact(value.anchors, ["acceptance", "acknowledgment", "proposal"]);
  exact(value.heartbeat, ["checker", "initiator", "responder"]);
  if (
    value.schema !== AGENT_HANDSHAKE_SNAPSHOT_SCHEMA ||
    value.externalActionPerformed !== false ||
    !AGENT_HANDSHAKE_STAGES.includes(value.currentStage) ||
    !UUID_PATTERN.test(value.sessionId) ||
    value.subjectRun !== "stakeholder" ||
    typeof value.reference !== "string" ||
    value.reference.length === 0 ||
    typeof value.statement !== "string" ||
    value.statement.length === 0 ||
    !Number.isSafeInteger(value.updatedAtMs) ||
    value.updatedAtMs < 0 ||
    value.reasonCode !== null
  ) invalid();

  let identities = null;
  if (value.identities !== null) {
    exact(value.identities, ["initiator", "responder"]);
    const initiator = identity(value.identities.initiator);
    const responder = identity(value.identities.responder);
    if (initiator.address === responder.address || initiator.agentId === responder.agentId) invalid();
    identities = Object.freeze({ initiator, responder });
  }
  let funding = null;
  if (value.funding !== null) {
    exact(value.funding, ["atMs", "funded"]);
    if (
      !Number.isSafeInteger(value.funding.atMs) ||
      value.funding.atMs < 0 ||
      value.funding.funded !== true
    ) invalid();
    funding = Object.freeze({ ...value.funding });
  }
  if (!Array.isArray(value.stageHistory) || value.stageHistory.length === 0) invalid();
  let prior = -1;
  const stageHistory = Object.freeze(value.stageHistory.map((entry) => {
    exact(entry, ["atMs", "status"]);
    if (
      !Number.isSafeInteger(entry.atMs) ||
      entry.atMs < prior ||
      entry.atMs > value.updatedAtMs ||
      !AGENT_HANDSHAKE_STAGES.includes(entry.status)
    ) invalid();
    prior = entry.atMs;
    return Object.freeze({ atMs: entry.atMs, status: entry.status });
  }));
  if (stageHistory.at(-1).status !== value.currentStage) invalid();

  const anchors = Object.freeze({
    acceptance: anchor(value.anchors.acceptance, 1),
    acknowledgment: anchor(value.anchors.acknowledgment, 2),
    proposal: anchor(value.anchors.proposal, 0),
  });
  let verdict = null;
  if (value.verdict !== null) {
    exact(value.verdict, VERDICT_KEYS);
    if (
      value.currentStage !== "CERTIFIED" ||
      value.verdict.outcome !== "VERIFIED" ||
      value.verdict.externalActionPerformed !== false ||
      value.verdict.reference !== value.reference ||
      !DIGEST_PATTERN.test(value.verdict.sessionDigest) ||
      !DIGEST_PATTERN.test(value.verdict.statementDigest) ||
      Object.values(anchors).some((entry) => entry === null)
    ) invalid();
    verdict = Object.freeze({ ...value.verdict });
  } else if (value.currentStage === "CERTIFIED") {
    invalid();
  }
  return Object.freeze({
    anchors,
    currentStage: value.currentStage,
    externalActionPerformed: false,
    funding,
    heartbeat: Object.freeze({
      checker: heartbeat(value.heartbeat.checker),
      initiator: heartbeat(value.heartbeat.initiator),
      responder: heartbeat(value.heartbeat.responder),
    }),
    identities,
    reasonCode: null,
    reference: value.reference,
    schema: value.schema,
    sessionId: value.sessionId,
    stageHistory,
    statement: value.statement,
    subjectRun: "stakeholder",
    updatedAtMs: value.updatedAtMs,
    verdict,
  });
}

export function validateAgentHandshakeSnapshot(value) {
  snapshot(value);
  return true;
}

export function buildAgentHandshakeSnapshot(value) {
  return snapshot({
    anchors: value.anchors,
    currentStage: value.currentStage,
    externalActionPerformed: false,
    funding: value.funding,
    heartbeat: value.heartbeat,
    identities: value.identities,
    reasonCode: value.reasonCode,
    reference: value.reference,
    schema: AGENT_HANDSHAKE_SNAPSHOT_SCHEMA,
    sessionId: value.sessionId,
    stageHistory: value.stageHistory,
    statement: value.statement,
    subjectRun: value.subjectRun,
    updatedAtMs: value.updatedAtMs,
    verdict: value.verdict,
  });
}
