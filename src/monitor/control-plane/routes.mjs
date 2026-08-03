// src/monitor/control-plane/routes.mjs
//
// The operator control plane's HTTP surface.
//
// LOOPBACK ONLY. This handler must be mounted on a server bound to 127.0.0.1
// (or ::1) by the operator process, never on a public interface. Per the plan
// (P2 clarification): "the operator control plane binds loopback only; a
// localhost UI on the operator's own machine is not a cross-machine inbound
// path and is P2-compliant." The remote-address check below is
// defense-in-depth, not the enforcement point -- do not remove it, and do not
// "fix" the bind address to 0.0.0.0 to make this reachable from another
// machine. Either change reopens the inbound-connection class the whole
// relay/outbound design exists to avoid.
//
// Routes (see docs/monitor snapshot shape assumptions below):
//   GET  /control/snapshot   -> the current run snapshot, verbatim, as JSON.
//   POST /control/reverify   -> body {"anchorKind": "proposal"|"acceptance"|
//                               "acknowledgment"}. Performs a REAL read-only
//                               Clockchain cross-party check through the
//                               injected client and returns the fresh result
//                               with a server-side timestamp. This never
//                               mutates anything; it is the "prove the
//                               receipts are real" showpiece.
//   POST /control/start      -> the ONLY route that starts a run.
//   POST /control/abort      -> the ONLY route that aborts a run.
//
// This module shows what the run and the chain say, and forwards exactly two
// operator intents (start, abort). It never imports a Clockchain client or a
// snapshot builder directly -- both arrive as injected dependencies -- so the
// control plane structurally cannot become an authority: swap the injected
// clockchain for a fake in a test, or for the real MCP client in production,
// and this module's behaviour is unchanged either way.
//
// Snapshot shape this module reads defensively (see monitor/snapshot.mjs,
// which owns the authoritative definition; every read below tolerates a
// missing or differently-shaped field rather than throwing):
//   {
//     sessionId, subjectRun, paymentMoved: false,
//     currentStage: { status, at },
//     stageHistory: [{ status, at, reasonCode? }, ...],
//     anchors: [
//       { kind: "proposal"|"acceptance"|"acknowledgment",
//         blockHeight, ledgerId, blockTime, anchoredHash, receipt, explorerUrl,
//         digestChain },
//       ...
//     ],
//     funding: { addresses: [...], journal: {...} },
//     roles: { <roleName>: { status, lastSeenMs }, ... },
//     preflight: { ok, checkedAt, ... },
//     verdict: null | <verdict.mjs published verdict shape>,
//   }
//
// The operator mounts this handler for the /control/* prefix and serves the
// sibling index.html / app.mjs / styles.css as plain static files itself --
// this module answers `false` for any path it does not recognise so a static
// file server can be layered underneath it in the same request pipeline.

import {
  McpRateLimitedError,
  McpVerificationError,
  assertCrossPartyVerification,
} from "../../core/clockchain.mjs";
import { reasonMessage } from "./messages.mjs";

const ANCHOR_KINDS = Object.freeze([
  "proposal",
  "acceptance",
  "acknowledgment",
]);
// Generous enough for {"anchorKind":"acknowledgment"} plus JSON padding, far
// too small for anything a loopback caller has a legitimate reason to send.
const MAX_BODY_BYTES = 4096;

function isLoopbackAddress(address) {
  return (
    address === "127.0.0.1" ||
    address === "::1" ||
    address === "::ffff:127.0.0.1"
  );
}

function isPlainObject(value) {
  if (value === null || typeof value !== "object") {
    return false;
  }
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function sendJson(res, statusCode, body) {
  const payload = Buffer.from(JSON.stringify(body), "utf8");
  res.writeHead(statusCode, {
    "cache-control": "no-store",
    "content-length": String(payload.length),
    "content-type": "application/json; charset=utf-8",
  });
  res.end(payload);
}

// Reads the request body up to MAX_BODY_BYTES and parses it as JSON. Returns
// `{}` for an empty body (a bare POST with no body is not malformed), `null`
// to signal "the caller sent bytes that are not a JSON object" so callers can
// answer 400 without a raw parser error ever reaching a response body.
async function readJsonBody(req) {
  const chunks = [];
  let total = 0;
  for await (const chunk of req) {
    total += chunk.length;
    if (total > MAX_BODY_BYTES) {
      return null;
    }
    chunks.push(chunk);
  }
  if (total === 0) {
    return {};
  }
  try {
    const parsed = JSON.parse(Buffer.concat(chunks).toString("utf8"));
    return isPlainObject(parsed) ? parsed : null;
  } catch {
    return null;
  }
}

function findAnchor(snapshot, anchorKind) {
  const anchors = Array.isArray(snapshot?.anchors)
    ? snapshot.anchors
    : [];
  return (
    anchors.find((entry) => entry?.kind === anchorKind) ?? null
  );
}

// Fresh Clockchain read-only errors are normalized to one of the frozen
// public reason codes before they ever reach a response body -- this
// dashboard is denser than the public page, but it still never repeats a raw
// internal Clockchain error code (e.g. "MCP_CROSS_PARTY_BINDING_MISMATCH")
// at a viewer; it repeats the plain business sentence for the nearest
// registered code instead.
function reverifyFailureReason(error) {
  if (error instanceof McpRateLimitedError) {
    return "RATE_BLOCKED";
  }
  if (error instanceof McpVerificationError) {
    if (error.code === "MCP_CROSS_PARTY_NOT_ON_CHAIN") {
      return "ANCHOR_UNVERIFIED";
    }
    return "BINDING_MISMATCH";
  }
  return "FAILED";
}

/**
 * Build the control-plane request handler.
 *
 * @param {object} dependencies
 * @param {() => (object | Promise<object>)} dependencies.getSnapshot
 *   Returns the current run snapshot. Injected so this module never imports
 *   monitor/snapshot.mjs directly.
 * @param {{ verifyCrossParty: (args: object) => Promise<object> }} dependencies.clockchain
 *   A Clockchain client exposing at least `verifyCrossParty`, matching the
 *   shape `createMcpClient()` returns in src/core/clockchain.mjs. Injected --
 *   this module never imports or constructs a client itself, so it cannot
 *   become an authority over what "verified" means.
 * @param {() => (void | Promise<void>)} dependencies.onStart
 *   Invoked by POST /control/start only.
 * @param {() => (void | Promise<void>)} dependencies.onAbort
 *   Invoked by POST /control/abort only.
 * @param {() => string} [dependencies.now]
 *   Returns the current time as an ISO-8601 string; injectable for tests.
 * @returns {(req, res) => Promise<boolean>}
 *   A request handler compatible with node:http's (IncomingMessage,
 *   ServerResponse) pair. Resolves `true` if it handled the request (wrote a
 *   response) and `false` if the path did not match a control-plane route, so
 *   the operator can layer a static file server underneath it.
 */
export function createControlPlaneRoutes(dependencies = {}) {
  const {
    clockchain,
    getSnapshot,
    now = () => new Date().toISOString(),
    onAbort,
    onStart,
  } = dependencies;

  if (typeof getSnapshot !== "function") {
    throw new TypeError(
      "createControlPlaneRoutes requires a getSnapshot() dependency.",
    );
  }
  if (
    !clockchain ||
    typeof clockchain.verifyCrossParty !== "function"
  ) {
    throw new TypeError(
      "createControlPlaneRoutes requires an injected clockchain client exposing verifyCrossParty().",
    );
  }
  if (typeof onStart !== "function") {
    throw new TypeError(
      "createControlPlaneRoutes requires an onStart() dependency.",
    );
  }
  if (typeof onAbort !== "function") {
    throw new TypeError(
      "createControlPlaneRoutes requires an onAbort() dependency.",
    );
  }
  if (typeof now !== "function") {
    throw new TypeError(
      "createControlPlaneRoutes' now() dependency must be a function.",
    );
  }

  async function handleSnapshot(req, res) {
    if (req.method !== "GET") {
      sendJson(res, 405, { error: "METHOD_NOT_ALLOWED" });
      return;
    }
    let snapshot;
    try {
      snapshot = await getSnapshot();
    } catch {
      sendJson(res, 500, { error: "SNAPSHOT_UNAVAILABLE" });
      return;
    }
    sendJson(res, 200, snapshot);
  }

  async function handleReverify(req, res) {
    if (req.method !== "POST") {
      sendJson(res, 405, { error: "METHOD_NOT_ALLOWED" });
      return;
    }
    const body = await readJsonBody(req);
    if (body === null) {
      sendJson(res, 400, { error: "MALFORMED_BODY" });
      return;
    }
    const { anchorKind } = body;
    if (!ANCHOR_KINDS.includes(anchorKind)) {
      sendJson(res, 400, { error: "UNKNOWN_ANCHOR_KIND" });
      return;
    }

    let snapshot;
    try {
      snapshot = await getSnapshot();
    } catch {
      sendJson(res, 500, { error: "SNAPSHOT_UNAVAILABLE" });
      return;
    }
    const anchor = findAnchor(snapshot, anchorKind);
    if (anchor === null) {
      sendJson(res, 404, { anchorKind, error: "ANCHOR_NOT_FOUND" });
      return;
    }

    const verifiedAt = now();
    const expected = {
      anchoredHash: anchor.anchoredHash,
      blockHeight: anchor.blockHeight,
      ledgerId: anchor.ledgerId,
    };
    try {
      // The live, read-only re-verify call. Nothing here writes to
      // Clockchain: verify_cross_party is a keyless read, which is the whole
      // point -- a viewer can watch this call happen and know it was not
      // staged.
      const result = await clockchain.verifyCrossParty({
        blockHeight: anchor.blockHeight,
        hash: anchor.anchoredHash,
        ledgerId: anchor.ledgerId,
      });
      assertCrossPartyVerification(result, expected);
      sendJson(res, 200, {
        anchorKind,
        match: true,
        onChain: result.onChain,
        verifiedAt,
      });
    } catch (error) {
      sendJson(res, 200, {
        anchorKind,
        match: false,
        reason: reasonMessage(reverifyFailureReason(error)),
        verifiedAt,
      });
    }
  }

  async function handleStart(req, res) {
    if (req.method !== "POST") {
      sendJson(res, 405, { error: "METHOD_NOT_ALLOWED" });
      return;
    }
    try {
      await onStart();
      sendJson(res, 200, { ok: true });
    } catch {
      sendJson(res, 500, { error: "START_FAILED", ok: false });
    }
  }

  async function handleAbort(req, res) {
    if (req.method !== "POST") {
      sendJson(res, 405, { error: "METHOD_NOT_ALLOWED" });
      return;
    }
    try {
      await onAbort();
      sendJson(res, 200, { ok: true });
    } catch {
      sendJson(res, 500, { error: "ABORT_FAILED", ok: false });
    }
  }

  return async function controlPlaneRequestHandler(req, res) {
    // Defense-in-depth loopback guard -- see the file-level comment. The bind
    // address is the real enforcement point; this only refuses to answer a
    // request that reached this process from anywhere else.
    const remoteAddress = req.socket?.remoteAddress;
    if (!isLoopbackAddress(remoteAddress)) {
      sendJson(res, 403, { error: "LOOPBACK_ONLY" });
      return true;
    }

    let pathname;
    try {
      pathname = new URL(req.url, "http://control-plane.invalid").pathname;
    } catch {
      sendJson(res, 400, { error: "MALFORMED_URL" });
      return true;
    }

    if (pathname === "/control/snapshot") {
      await handleSnapshot(req, res);
      return true;
    }
    if (pathname === "/control/reverify") {
      await handleReverify(req, res);
      return true;
    }
    if (pathname === "/control/start") {
      await handleStart(req, res);
      return true;
    }
    if (pathname === "/control/abort") {
      await handleAbort(req, res);
      return true;
    }
    return false;
  };
}
