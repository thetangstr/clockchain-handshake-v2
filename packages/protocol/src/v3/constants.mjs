export const HANDSHAKE_V3_PROTOCOL_VERSION = "3.0";
export const HANDSHAKE_V3_SCHEMA_VERSION = "3.0.0-draft.2";
export const HANDSHAKE_V3_DOMAIN_SEPARATOR = "CLOCKCHAIN_AGENT_HANDSHAKE_V3";
export const HANDSHAKE_V3_CANONICALIZATION = "RFC8785";
export const HANDSHAKE_V3_SIGNING_PAYLOAD_SCHEMA_ID =
  "https://schemas.clockchain.network/agent-handshake/v3/signing-payload.schema.json";

export const HANDSHAKE_V3_STATES = Object.freeze([
  "INVITED",
  "CLAIMED",
  "POLICY_READY",
  "PARTIES_BOUND",
  "PROPOSAL_PENDING",
  "ACCEPTANCE_PENDING",
  "ANCHORING",
  "CERTIFICATE_ISSUED",
  "CONTINUATION_ISSUED",
  "COMPLETED",
  "FAILED_CLOSED",
  "CANCELLED",
  "EXPIRED",
  "REVOKED",
]);

export const HANDSHAKE_V3_TERMINAL_STATES = Object.freeze([
  "COMPLETED",
  "FAILED_CLOSED",
  "CANCELLED",
  "EXPIRED",
  "REVOKED",
]);

export const HANDSHAKE_V3_NONTERMINAL_STATES = Object.freeze(
  HANDSHAKE_V3_STATES.filter((state) => !HANDSHAKE_V3_TERMINAL_STATES.includes(state)),
);

export const HANDSHAKE_V3_ROLES = Object.freeze(["INITIATOR", "RESPONDER"]);
export const HANDSHAKE_V3_ACTORS = Object.freeze(["INITIATOR", "RESPONDER", "CLOCKCHAIN", "OPERATOR", "SYSTEM"]);
export const HANDSHAKE_V3_SIGNING_ALGORITHMS = Object.freeze(["ES256K", "EdDSA", "ES256"]);
export const HANDSHAKE_V3_NEXT_ACTIONS = Object.freeze([
  "WAIT",
  "SIGN_AND_SUBMIT",
  "SUBMIT_CHECKPOINT",
  "FETCH_RESULT",
  "STOP_AFTER_VERIFICATION",
  "TERMINAL",
]);

export const HANDSHAKE_V3_ROLE_TOOLS = Object.freeze([
  "agent_handshake_session_join",
  "agent_handshake_session_next",
  "agent_handshake_session_submit_checkpoint",
  "agent_handshake_session_submit",
  "agent_handshake_session_cancel",
  "agent_handshake_session_resume",
]);

export const HANDSHAKE_V3_INITIATOR_REQUIRED_TOOLS = Object.freeze([...HANDSHAKE_V3_ROLE_TOOLS]);
export const HANDSHAKE_V3_RESPONDER_REQUIRED_TOOLS = Object.freeze([...HANDSHAKE_V3_ROLE_TOOLS]);

export const HANDSHAKE_V3_NEXT_ACTION_BY_STATE = Object.freeze({
  INVITED: "WAIT",
  CLAIMED: "WAIT",
  POLICY_READY: "WAIT",
  PARTIES_BOUND: "WAIT",
  PROPOSAL_PENDING: "SIGN_AND_SUBMIT",
  ACCEPTANCE_PENDING: "SUBMIT_CHECKPOINT",
  ANCHORING: "WAIT",
  CERTIFICATE_ISSUED: "FETCH_RESULT",
  CONTINUATION_ISSUED: "STOP_AFTER_VERIFICATION",
  COMPLETED: "TERMINAL",
  FAILED_CLOSED: "TERMINAL",
  CANCELLED: "TERMINAL",
  EXPIRED: "TERMINAL",
  REVOKED: "TERMINAL",
});

export const HANDSHAKE_V3_OPERATOR_TOOLS = Object.freeze([
  "agent_handshake_operator_request",
]);

export const HANDSHAKE_V3_ERROR_CODES = Object.freeze([
  "AUTHENTICATION_REQUIRED",
  "TOKEN_INVALID",
  "TOKEN_EXPIRED",
  "TOKEN_REVOKED",
  "SENDER_CONSTRAINT_INVALID",
  "AUDIENCE_INVALID",
  "SCOPE_DENIED",
  "TENANT_DENIED",
  "PRINCIPAL_DENIED",
  "INVITATION_NOT_FOUND",
  "INVITATION_EXPIRED",
  "INVITATION_CLAIMED",
  "INVITATION_REVOKED",
  "ROLE_DENIED",
  "POLICY_DIGEST_MISMATCH",
  "SIGNATURE_INVALID",
  "IDEMPOTENCY_CONFLICT",
  "STATE_VERSION_CONFLICT",
  "TRANSITION_DENIED",
  "SESSION_CANCELLED",
  "SESSION_EXPIRED",
  "SESSION_REVOKED",
  "SESSION_FAILED_CLOSED",
  "CLOCKCHAIN_PENDING",
  "CLOCKCHAIN_UNAVAILABLE",
  "CLOCKCHAIN_RECEIPT_INVALID",
  "CONTINUATION_UNAVAILABLE",
  "RESULT_VERIFICATION_FAILED",
  "HANDSHAKE_VERSION_UNSUPPORTED",
  "SCHEMA_INVALID",
  "RATE_LIMITED",
  "INTERNAL_SAFE_FAILURE",
]);

export class HandshakeV3Error extends Error {
  constructor(message, code) {
    super(message);
    this.name = new.target.name;
    this.category = "handshake-v3";
    this.code = code;
  }
}

export function fail(code, message = "Handshake v3 value is invalid.") {
  throw new HandshakeV3Error(message, code);
}

export const HANDSHAKE_V3_CONTRACT_PROVENANCE = Object.freeze({
  schema: "clockchain.handshake-protocol-v3-contract-provenance/v1",
  approvedProtocolSourceCommit: "d2cdedb705cf6855657381a908e47f71df959145",
  contractSchemaPath: "packages/protocol/schemas/standalone-handshake-v3-contract.schema.json",
  contractSchemaOriginalPath: "docs/superpowers/specs/standalone-handshake-v3-contract.schema.json",
  contractSchemaSha256: "4d58b53caabc04570da17ac4cd712112c6863d86318a50303f28cfc7c90c468c",
  contractFixturesPath: "packages/protocol/fixtures/standalone-handshake-v3-contract-fixtures.json",
  contractFixturesOriginalPath: "docs/superpowers/specs/standalone-handshake-v3-contract-fixtures.json",
  contractFixturesSha256: "96ca5f773bdc3b02bdc3d7cd1326b1352ae13e007614a8f09f0f244018ab60bb",
  packageName: "@clockchain/handshake-protocol",
  runtimeBoundary: "no MCP server, HTTP gateway, OAuth/JWKS validator, tenant store, persistence, Supervisor, Agent Contract delivery, or demo controller",
});
