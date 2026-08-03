// Shared error vocabulary for the relay's server and client halves.
//
// The relay is deliberately the dumbest component in the system: it moves
// bytes and holds no authority. Its own internal error codes below
// (UNKNOWN_SESSION, MALFORMED_ENVELOPE, SEQ_CONFLICT, BODY_TOO_LARGE,
// EVIDENCE_TOO_LARGE, UNKNOWN_ROLE, ...) are NOT the frozen public protocol
// reason set (RENDEZVOUS_UNAVAILABLE, EXPIRED, MISSING, ...) -- those name
// protocol-level failures raised elsewhere (roles, verifier). The client
// half of the relay translates the handful of cases the shared contract
// calls out explicitly:
//   - a connection that never succeeds within the wait budget -> RENDEZVOUS_UNAVAILABLE
//   - an HTTP 429 / explicit rate signal              -> RATE_BLOCKED
//   - a role_claim rejected because the role is taken -> ROLE_ALREADY_BOUND
// and passes every other relay-reported code straight through on `.code`.
export class RelayError extends Error {
  constructor(message, code, { status, detail } = {}) {
    super(message);
    this.name = "RelayError";
    this.code = code;
    this.status = status;
    this.detail = detail;
  }
}
