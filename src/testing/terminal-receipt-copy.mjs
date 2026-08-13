const ROLE_LABELS = Object.freeze({
  initiator: "PAYER",
  responder: "REQUESTOR",
});
const RECEIPTS = Object.freeze([
  Object.freeze({ key: "proposal", label: "Proposal" }),
  Object.freeze({ key: "acceptance", label: "Acceptance" }),
  Object.freeze({ key: "acknowledgment", label: "Acknowledgment" }),
]);

const ADDRESS_PATTERN = /^0x[0-9a-fA-F]{40}$/u;
const HASH_PATTERN = /^(?:0x)?[0-9a-fA-F]{64}$/u;
const DECIMAL_PATTERN = /^(?:0|[1-9][0-9]*)$/u;
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;

export class TerminalReceiptCopyError extends Error {
  constructor() {
    super("Terminal receipt copy could not be formatted.");
    this.name = "TerminalReceiptCopyError";
  }
}

function fail() {
  throw new TerminalReceiptCopyError();
}

function record(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) fail();
  return value;
}

function exactString(value, pattern) {
  if (typeof value !== "string" || !pattern.test(value)) fail();
  return value;
}

function printable(value) {
  if (typeof value !== "string" || !/^[\x20-\x7e]+$/u.test(value)) fail();
  return value;
}

function issuedAt(value) {
  if (!Number.isSafeInteger(value) || value < 0) fail();
  const iso = new Date(value).toISOString();
  return `${iso.slice(0, 10)} ${iso.slice(11, 19)} UTC`;
}

export function formatTerminalReceiptCopy(evidence, role) {
  const roleLabel = ROLE_LABELS[role];
  if (roleLabel === undefined) fail();

  const root = record(evidence);
  if (root.schema !== "clockchain.fresh-agent-canary-evidence/v1") fail();
  const monitor = record(root.monitor);
  const party = record(record(root.roles)[role]);
  const identity = record(party.erc8004);
  const certificate = record(monitor.certificate);
  const receiptMap = record(monitor.receipts);

  const sessionId = exactString(monitor.sessionId, UUID_PATTERN);
  const agentId = exactString(identity.agentId, DECIMAL_PATTERN);
  const address = exactString(party.address, ADDRESS_PATTERN);
  const registrationTx = exactString(identity.registrationTx, /^0x[0-9a-fA-F]{64}$/u);
  const registrationBlock = exactString(identity.registrationBlock, DECIMAL_PATTERN);
  const certificateDigest = exactString(certificate.digest, HASH_PATTERN);
  if (certificate.outcome !== "VERIFIED") fail();
  if (party.certificateVerified !== true) fail();
  if (party.externalBusinessActionPerformed !== false) fail();
  if (party.certificateDigest !== certificateDigest) fail();

  const receiptLines = [];
  for (const [index, expected] of RECEIPTS.entries()) {
    const receipt = record(receiptMap[expected.key]);
    if (receipt.kind !== expected.key) fail();
    const ledgerId = printable(receipt.ledgerId);
    const digest = exactString(receipt.digest, HASH_PATTERN);
    const blockHeight = exactString(receipt.blockHeight, DECIMAL_PATTERN);
    receiptLines.push(
      `Receipt ${index + 1} — ${expected.label}`,
      `Ledger entry: ${ledgerId}`,
      `Receipt digest: ${digest}`,
      `Block: ${blockHeight}`,
      "",
    );
  }

  return [
    `HANDSHAKE COMPLETE — ${roleLabel} COPY`,
    "",
    "Identity",
    `ERC-8004 agent: #${agentId}`,
    `Controller address: ${address}`,
    `Registration transaction: ${registrationTx}`,
    `Registration block: ${registrationBlock}`,
    "",
    "Signed closing certificate — VERIFIED",
    `Certificate digest: ${certificateDigest}`,
    `Issued: ${issuedAt(certificate.issuedAtMs)}`,
    `Session: ${sessionId}`,
    "",
    ...receiptLines,
    "No external business action occurred.",
    "",
  ].join("\n");
}
