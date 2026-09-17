// Session-scoped monitor for the fresh-agent canary.
//
// The public monitor proxy only serves the coordinator's *current* session,
// which any other party can rotate, and it sits behind the research site's
// auth boundary. For canary evidence the authoritative confirmation source is
// the relay's own session-scoped endpoints:
//   <base>/v1/sessions/{sessionId}/snapshot
//   <base>/v1/sessions/{sessionId}/result
//   <base>/v1/runs
// The monitor URL must carry the literal token {sessionId}; any other value
// is rejected. Only session-scoped relay endpoints can provide the signed
// result envelope needed to bind the certificateDigest to the trusted proof —
// the auth-protected current-session proxy cannot, and is intentionally not
// a valid canary monitor source.
//
// The relay data only confirms visibility and chronology for a session whose
// certificate was already produced by the trusted local verify-certificate
// completion. It never establishes success on its own: the caller binds the
// returned certificateDigest to the trusted terminal proofs.
//
// Digest domains differ between relay views: snapshot.certificate.digest is
// the digest of the full signed result envelope, while the trusted terminal
// proof's certificateDigest is the digest of envelope.result only. The
// monitor therefore fetches the signed result envelope, requires its envelope
// digest to equal snapshot.certificate.digest, and returns the result-object
// digest so the caller can bind it to the trusted proof.

import { buildAgentHandshakeV2Snapshot } from "../monitor/agent-snapshot-v2.mjs";
import {
  agentHandshakeV2ResultDigest,
  validateAgentHandshakeV2ResultEnvelope,
} from "../agent-handshake/v2/result.mjs";
import { digestHex } from "../core/canonical.mjs";

const SESSION_TOKEN = "{sessionId}";
const ANCHOR_KINDS = Object.freeze(["proposal", "acceptance", "acknowledgment"]);
const RUN_KEYS = Object.freeze(["anchors", "outcome", "reasonCode", "sessionId", "stage", "startedAtMs"]);
const DEFAULT_TIMEOUT_MS = 120_000;
const DEFAULT_INTERVAL_MS = 1_000;

function invalid() {
  throw new Error("invalid");
}

function isRecord(value) {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

export function sessionMonitorEndpoints(endpoint) {
  if (typeof endpoint !== "string" || !endpoint.includes(SESSION_TOKEN)) return null;
  const parts = endpoint.split(SESSION_TOKEN);
  if (parts.length !== 2) invalid();
  const [before, after] = parts;
  if (after !== "/snapshot" || !before.endsWith("/sessions/")) invalid();
  try {
    new URL(before + "x" + after);
  } catch {
    invalid();
  }
  return {
    snapshotFor(sessionId) {
      return before + encodeURIComponent(sessionId) + after;
    },
    resultFor(sessionId) {
      return before + encodeURIComponent(sessionId) + "/result";
    },
    runs: before.slice(0, before.length - "/sessions/".length) + "/runs",
  };
}

// Strictly parse a v2 snapshot and require the certified-terminal contract:
// exact session, VERIFIED checker, VERIFIED certificate, null failure, false
// external action (enforced by the parser), and all three receipt anchors.
export function certifiedV2Snapshot(value, sessionId) {
  let snapshot;
  try {
    snapshot = buildAgentHandshakeV2Snapshot(value);
  } catch {
    return null;
  }
  if (
    snapshot.sessionId !== sessionId ||
    snapshot.checker.stage !== "VERIFIED" ||
    snapshot.certificate === null ||
    snapshot.failure !== null ||
    ANCHOR_KINDS.some((kind) => snapshot.receipts[kind] === null)
  ) return null;
  return snapshot;
}

function matchingCertifiedRun(run, snapshot) {
  if (!isRecord(run)) return false;
  const keys = Object.keys(run);
  if (keys.length !== RUN_KEYS.length || RUN_KEYS.some((key) => !(key in run))) return false;
  if (
    run.sessionId !== snapshot.sessionId ||
    run.stage !== "CERTIFIED" ||
    run.outcome !== "VERIFIED" ||
    run.reasonCode !== null ||
    !Number.isSafeInteger(run.startedAtMs) || run.startedAtMs < 0
  ) return false;
  if (!isRecord(run.anchors)) return false;
  const anchorKeys = Object.keys(run.anchors);
  if (anchorKeys.length !== ANCHOR_KINDS.length || ANCHOR_KINDS.some((kind) => !(kind in run.anchors))) return false;
  return ANCHOR_KINDS.every((kind) => run.anchors[kind] === snapshot.receipts[kind].blockHeight);
}

// The run history entry must be an exact record for the same session with
// anchors equal to the certified snapshot's receipt block heights.
export function certifiedRunRecorded(body, snapshot) {
  return isRecord(body) &&
    body.ok === true &&
    body.paymentMoved === false &&
    Array.isArray(body.runs) &&
    body.runs.some((run) => matchingCertifiedRun(run, snapshot));
}

// Strictly validate the signed result envelope for the certified session:
// exact session, VERIFIED outcome, no external action, envelope digest equal
// to the snapshot's certificate digest, and anchors corresponding to the
// exact snapshot receipts. Returns the parsed-equivalent result object.
export function certifiedV2Result(value, snapshot, sessionId) {
  try {
    validateAgentHandshakeV2ResultEnvelope(value);
  } catch {
    return null;
  }
  const result = value.result;
  if (
    result.sessionId !== sessionId ||
    result.sessionId !== snapshot.sessionId ||
    result.outcome !== "VERIFIED" ||
    result.externalBusinessActionPerformed !== false ||
    agentHandshakeV2ResultDigest(value) !== snapshot.certificate.digest
  ) return null;
  const anchorsCorrespond = result.anchors.every((anchor) => {
    const receipt = snapshot.receipts[anchor.kind];
    return isRecord(receipt) &&
      receipt.blockHeight === anchor.blockHeight &&
      receipt.blockTimeRaw === anchor.blockTimeRaw &&
      receipt.digest === anchor.digest &&
      receipt.ledgerId === anchor.ledgerId;
  });
  return anchorsCorrespond ? result : null;
}

// The run-level acceptance contract: relay evidence may only confirm the
// session and certificate the trusted local terminal proofs already produced.
// Anything less — wrong session, missing or mismatched digest, or a chronology
// that does not end CERTIFIED — fails closed.
export function monitorEvidenceMatches(monitorResult, { sessionId, certificateDigest } = {}) {
  return isRecord(monitorResult) &&
    monitorResult.sessionId === sessionId &&
    monitorResult.certificateDigest === certificateDigest &&
    Array.isArray(monitorResult.chronology) &&
    monitorResult.chronology.at(-1) === "CERTIFIED";
}

export async function monitorSession({
  endpoint,
  sessionId,
  fetchImpl = fetch,
  sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms)),
  timeoutMs = DEFAULT_TIMEOUT_MS,
  intervalMs = DEFAULT_INTERVAL_MS,
}) {
  const endpoints = sessionMonitorEndpoints(endpoint);
  if (endpoints === null) invalid();
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const snapshotResponse = await fetchImpl(endpoints.snapshotFor(sessionId), { cache: "no-store" });
      if (snapshotResponse.ok) {
        const snapshot = certifiedV2Snapshot(await snapshotResponse.json(), sessionId);
        if (snapshot !== null) {
          const runsResponse = await fetchImpl(endpoints.runs, { cache: "no-store" });
          const resultResponse = await fetchImpl(endpoints.resultFor(sessionId), { cache: "no-store" });
          if (
            runsResponse.ok && resultResponse.ok &&
            certifiedRunRecorded(await runsResponse.json(), snapshot)
          ) {
            const result = certifiedV2Result(await resultResponse.json(), snapshot, sessionId);
            if (result !== null) {
              return {
                chronology: Object.freeze(["CERTIFIED"]),
                sessionId,
                certificateDigest: digestHex(result),
              };
            }
          }
        }
      }
    } catch {
      // transient fetch/parse failure — keep polling until the deadline
    }
    await sleep(intervalMs);
  }
  invalid();
}
