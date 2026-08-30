export const HANDSHAKE_V3_PROTOCOL_VERSION = "3.0";
export const HANDSHAKE_V3_SCHEMA_VERSION = "3.0.0-draft.3";
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
  "JOIN_SESSION",
  "SIGN_AND_SUBMIT",
  "SUBMIT_CHECKPOINT",
  "FETCH_RESULT",
  "VERIFY_RESULT",
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

export const HANDSHAKE_V3_TRANSITION_ACTIONS = Object.freeze([
  "CLAIM_INVITATION",
  "PREPARE_POLICY",
  "BIND_PARTIES",
  "SUBMIT_PROPOSAL",
  "SUBMIT_ACCEPTANCE",
  "CONFIRM_ANCHOR",
  "ISSUE_CERTIFICATE",
  "ISSUE_CONTINUATION",
  "COMPLETE",
  "FAIL_CLOSED",
  "CANCEL",
  "EXPIRE",
  "REVOKE",
]);

export const HANDSHAKE_V3_ALLOWED_TRANSITIONS_BY_STATE = Object.freeze({
  INVITED: Object.freeze(["CLAIM_INVITATION", "FAIL_CLOSED", "CANCEL", "EXPIRE", "REVOKE"]),
  CLAIMED: Object.freeze(["PREPARE_POLICY", "FAIL_CLOSED", "CANCEL", "EXPIRE", "REVOKE"]),
  POLICY_READY: Object.freeze(["BIND_PARTIES", "FAIL_CLOSED", "CANCEL", "EXPIRE", "REVOKE"]),
  PARTIES_BOUND: Object.freeze(["SUBMIT_PROPOSAL", "FAIL_CLOSED", "CANCEL", "EXPIRE", "REVOKE"]),
  PROPOSAL_PENDING: Object.freeze(["SUBMIT_ACCEPTANCE", "FAIL_CLOSED", "CANCEL", "EXPIRE", "REVOKE"]),
  ACCEPTANCE_PENDING: Object.freeze(["CONFIRM_ANCHOR", "FAIL_CLOSED", "CANCEL", "EXPIRE", "REVOKE"]),
  ANCHORING: Object.freeze(["ISSUE_CERTIFICATE", "FAIL_CLOSED", "CANCEL", "EXPIRE", "REVOKE"]),
  CERTIFICATE_ISSUED: Object.freeze(["ISSUE_CONTINUATION", "FAIL_CLOSED", "CANCEL", "EXPIRE", "REVOKE"]),
  CONTINUATION_ISSUED: Object.freeze(["COMPLETE", "FAIL_CLOSED", "CANCEL", "EXPIRE", "REVOKE"]),
  COMPLETED: Object.freeze(["REVOKE"]),
  FAILED_CLOSED: Object.freeze([]),
  CANCELLED: Object.freeze([]),
  EXPIRED: Object.freeze([]),
  REVOKED: Object.freeze([]),
});

export const HANDSHAKE_V3_NEXT_ACTION_BY_STATE = Object.freeze({
  INVITED: "JOIN_SESSION",
  CLAIMED: "JOIN_SESSION",
  POLICY_READY: "TERMINAL",
  PARTIES_BOUND: "SIGN_AND_SUBMIT",
  PROPOSAL_PENDING: "SIGN_AND_SUBMIT",
  ACCEPTANCE_PENDING: "SUBMIT_CHECKPOINT",
  ANCHORING: "WAIT",
  CERTIFICATE_ISSUED: "WAIT",
  CONTINUATION_ISSUED: "FETCH_RESULT",
  COMPLETED: "FETCH_RESULT",
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
  contractSchemaSha256: "335bc187c2f76de83f6d71df2cb6db7a39937693be0d9c814bec7d60ed378d81",
  contractFixturesPath: "packages/protocol/fixtures/standalone-handshake-v3-contract-fixtures.json",
  contractFixturesOriginalPath: "docs/superpowers/specs/standalone-handshake-v3-contract-fixtures.json",
  contractFixturesSha256: "4a15a47a9183730dbc0b79641dfa984d7b628866078bbbb3686d252fb10f2b13",
  packageName: "@clockchain/handshake-protocol",
  runtimeBoundary: "no MCP server, HTTP gateway, OAuth/JWKS validator, tenant store, persistence, Supervisor, Agent Contract delivery, or demo controller",
});
