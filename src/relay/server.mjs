// The rendezvous relay's server half.
//
// This is deliberately the dumbest component in the system: both parties
// connect OUTBOUND to it (no participant machine ever accepts an inbound
// connection -- see the P2 binding rule), it moves bytes, and it holds zero
// authority. It validates exactly four things and nothing else: the session
// exists, the request body is within its size bound, the envelope has the
// right shape, and per-session message sequence numbers are monotonic. It
// never inspects, verifies, or trusts a signature -- that is the parties'
// job (src/relay/client.mjs), and pretending otherwise here would make the
// relay an authority it is not allowed to be.
//
// Storage is one append-only JSONL journal file per session. On restart the
// constructor re-reads every journal in the state directory and rebuilds the
// in-memory index from it; that is the whole persistence story, including
// evidence uploads and the discovery document (both are just journal record
// types).
import { createServer } from "node:http";
import {
  appendFile,
  mkdir,
  readFile,
  readdir,
} from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { randomUUID } from "node:crypto";

import { PARTY_ROLES } from "../core/evidence.mjs";
import { validateSnapshot } from "../monitor/snapshot.mjs";
import { RelayError } from "./errors.mjs";

export const SESSION_ID_PATTERN = /^[A-Za-z0-9_-]{1,128}$/;
const SEQ_PATTERN = /^(?:0|[1-9][0-9]*)$/;
const TOKEN_PATTERN = /^[!-~]{1,64}$/;
const BASE64_PATTERN = /^[A-Za-z0-9+/]*={0,2}$/;
const SENDER_KEY_BASE64_LENGTH = 44; // raw 32-byte Ed25519 public key
const SIGNATURE_BASE64_LENGTH = 88; // raw 64-byte Ed25519 signature
const ENVELOPE_KEYS = Object.freeze([
  "sessionId",
  "seq",
  "role",
  "kind",
  "body",
  "senderKey",
  "sig",
]);
const JOURNAL_SUFFIX = ".jsonl";

// Named, bounded sizes. These are relay-level design decisions, not part of
// the frozen protocol reason set -- the shared contract fixes the evidence
// per-part limits (json/markdown/marker), everything else here is a generous
// but concrete bound chosen to keep the relay from ever buffering an
// unbounded body.
export const MAX_MESSAGE_BODY_BYTES = 262_144; // 256 KiB per envelope
export const MAX_SESSION_CREATE_BYTES = 131_072; // 128 KiB (sessionId + discovery doc)
export const MAX_EVIDENCE_REQUEST_BYTES = 8 * 1024 * 1024; // coarse pre-decode guard
export const EVIDENCE_PART_LIMITS = Object.freeze({
  json: 1024 * 1024,
  markdown: 2 * 1024 * 1024,
  marker: 2048,
});
// A monitor snapshot (see src/monitor/snapshot.mjs) is a handful of small
// fields plus three anchor receipts -- same order of magnitude as one
// message envelope, so it shares that bound.
export const MAX_SNAPSHOT_BODY_BYTES = 262_144; // 256 KiB
const DEFAULT_WAIT_MS = 25_000;
const MAX_WAIT_MS = 25_000;

// Static serving for the stakeholder audience page (see
// src/monitor/stakeholder/*). This relay is the only thing already reachable
// by an audience member, so it is the simplest place to serve a read-only
// page from -- GET only, files copied verbatim, nothing here can mutate a
// run. The URL shape mirrors the page's own relative imports:
//   GET /monitor/{sid}        -> stakeholder/index.html (any second segment
//                                 that isn't a known asset name is treated as
//                                 a session id -- the page itself is what
//                                 validates whether that session exists)
//   GET /monitor/app.mjs      -> stakeholder/app.mjs
//   GET /monitor/messages.mjs -> stakeholder/messages.mjs
//   GET /monitor/styles.css   -> stakeholder/styles.css
//   GET /snapshot.mjs         -> monitor/snapshot.mjs (app.mjs's own
//                                 "../snapshot.mjs" import, resolved from
//                                 wherever app.mjs is served)
const MONITOR_DIR = dirname(fileURLToPath(import.meta.url));
const STAKEHOLDER_DIR = join(MONITOR_DIR, "..", "monitor", "stakeholder");
const SNAPSHOT_MODULE_PATH = join(MONITOR_DIR, "..", "monitor", "snapshot.mjs");
const STAKEHOLDER_INDEX_FILE = join(STAKEHOLDER_DIR, "index.html");
const STAKEHOLDER_STATIC_FILES = Object.freeze({
  "app.mjs": {
    contentType: "text/javascript; charset=utf-8",
    file: join(STAKEHOLDER_DIR, "app.mjs"),
  },
  "messages.mjs": {
    contentType: "text/javascript; charset=utf-8",
    file: join(STAKEHOLDER_DIR, "messages.mjs"),
  },
  "styles.css": {
    contentType: "text/css; charset=utf-8",
    file: join(STAKEHOLDER_DIR, "styles.css"),
  },
});

function isPlainObject(value) {
  return (
    value !== null &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    Object.getPrototypeOf(value) === Object.prototype
  );
}

function hasExactKeys(value, expectedKeys) {
  if (!isPlainObject(value)) {
    return false;
  }
  const keys = Object.keys(value);
  return (
    keys.length === expectedKeys.length &&
    expectedKeys.every((key) => Object.hasOwn(value, key))
  );
}

function writeJson(res, status, payload) {
  const bytes = Buffer.from(JSON.stringify(payload), "utf8");
  res.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "content-length": String(bytes.length),
  });
  res.end(bytes);
}

function parseJsonBody(buffer) {
  if (buffer.length === 0) {
    return undefined;
  }
  try {
    return JSON.parse(buffer.toString("utf8"));
  } catch {
    throw new RelayError(
      "Request body is not valid JSON.",
      "MALFORMED_REQUEST",
      { status: 400 },
    );
  }
}

// Reject oversize bodies with a named reason before reading them fully: a
// Content-Length that already exceeds the bound is known to be a rejection
// the moment headers arrive, and a streamed body that exceeds the bound
// mid-flight is known to be a rejection the moment it crosses the line.
// Either way the decision is made without ever buffering the oversize
// payload -- bytes past that point are drained and discarded, not
// retained -- but the socket itself is left alone: destroying it before the
// client has finished writing the request produces a connection reset on
// their end instead of the 413 response they are owed.
function readBoundedBody(req, maxBytes, oversizeCode) {
  return new Promise((resolve, reject) => {
    let rejection = null;

    const declared = req.headers["content-length"];
    if (declared !== undefined) {
      const declaredBytes = Number(declared);
      if (Number.isFinite(declaredBytes) && declaredBytes > maxBytes) {
        rejection = new RelayError(
          "Request body exceeds the allowed size.",
          oversizeCode,
          { status: 413 },
        );
      }
    }

    const chunks = [];
    let total = 0;

    req.on("data", (chunk) => {
      if (rejection) {
        // Already rejecting: keep draining so the client's write completes
        // normally, but stop retaining bytes we will never use.
        return;
      }
      total += chunk.length;
      if (total > maxBytes) {
        rejection = new RelayError(
          "Request body exceeds the allowed size.",
          oversizeCode,
          { status: 413 },
        );
        chunks.length = 0;
        return;
      }
      chunks.push(chunk);
    });
    req.on("end", () => {
      if (rejection) {
        reject(rejection);
        return;
      }
      resolve(Buffer.concat(chunks));
    });
    req.on("error", () => {
      reject(
        new RelayError("Failed to read the request body.", "BODY_READ_ERROR", {
          status: 400,
        }),
      );
    });
  });
}

function throwMalformedEnvelope() {
  throw new RelayError(
    "Envelope does not match the required shape.",
    "MALFORMED_ENVELOPE",
    { status: 400 },
  );
}

function validateEnvelopeShape(body, expectedSessionId) {
  if (!hasExactKeys(body, ENVELOPE_KEYS)) {
    throwMalformedEnvelope();
  }
  const { sessionId, seq, role, kind, body: payload, senderKey, sig } = body;
  if (sessionId !== expectedSessionId) {
    throwMalformedEnvelope();
  }
  if (typeof seq !== "string" || !SEQ_PATTERN.test(seq) || seq.length > 20) {
    throwMalformedEnvelope();
  }
  if (typeof role !== "string" || !TOKEN_PATTERN.test(role)) {
    throwMalformedEnvelope();
  }
  if (typeof kind !== "string" || !TOKEN_PATTERN.test(kind)) {
    throwMalformedEnvelope();
  }
  if (payload === undefined) {
    throwMalformedEnvelope();
  }
  if (
    typeof senderKey !== "string" ||
    senderKey.length !== SENDER_KEY_BASE64_LENGTH ||
    !BASE64_PATTERN.test(senderKey)
  ) {
    throwMalformedEnvelope();
  }
  if (
    typeof sig !== "string" ||
    sig.length !== SIGNATURE_BASE64_LENGTH ||
    !BASE64_PATTERN.test(sig)
  ) {
    throwMalformedEnvelope();
  }
  return { sessionId, seq, role, kind, body: payload, senderKey, sig };
}

function createSessionState(sessionId, journalPath) {
  return {
    sessionId,
    journalPath,
    messages: [],
    lastSeq: 0,
    evidence: {},
    discovery: undefined,
    monitorSnapshot: null,
    waiters: new Set(),
    writeLock: Promise.resolve(),
  };
}

function applyJournalRecord(session, record) {
  if (!isPlainObject(record)) {
    return;
  }
  if (record.type === "session-created") {
    session.discovery = record.discovery ?? undefined;
    return;
  }
  if (record.type === "message" && isPlainObject(record.envelope)) {
    session.messages.push(record.envelope);
    const seqNum = Number(record.envelope.seq);
    if (Number.isSafeInteger(seqNum) && seqNum > session.lastSeq) {
      session.lastSeq = seqNum;
    }
    return;
  }
  if (
    record.type === "evidence" &&
    typeof record.role === "string" &&
    isPlainObject(record.triple)
  ) {
    try {
      session.evidence[record.role] = {
        json: Buffer.from(record.triple.json, "base64"),
        markdown: Buffer.from(record.triple.markdown, "base64"),
        marker: Buffer.from(record.triple.marker, "base64"),
      };
    } catch {
      // A malformed evidence journal record is tolerated the same way a
      // malformed line is: it is dropped rather than crashing the relay.
    }
    return;
  }
  if (record.type === "monitor-snapshot" && isPlainObject(record.snapshot)) {
    // Already validated at write time (handlePutSnapshot); replay trusts it
    // rather than re-validating, the same way "message" records above do.
    session.monitorSnapshot = record.snapshot;
  }
}

async function replayJournal(session) {
  let raw;
  try {
    raw = await readFile(session.journalPath, "utf8");
  } catch (error) {
    if (error?.code === "ENOENT") {
      return;
    }
    throw error;
  }
  for (const line of raw.split("\n")) {
    if (line.length === 0) {
      continue;
    }
    let record;
    try {
      record = JSON.parse(line);
    } catch {
      // A partial trailing line from a crash mid-write is tolerated; the
      // relay resumes from whatever complete lines exist.
      continue;
    }
    applyJournalRecord(session, record);
  }
}

async function loadExistingSessions(stateDir, sessions) {
  let entries;
  try {
    entries = await readdir(stateDir, { withFileTypes: true });
  } catch (error) {
    if (error?.code === "ENOENT") {
      return;
    }
    throw error;
  }
  for (const entry of entries) {
    if (!entry.isFile() || !entry.name.endsWith(JOURNAL_SUFFIX)) {
      continue;
    }
    const sessionId = entry.name.slice(0, -JOURNAL_SUFFIX.length);
    if (!SESSION_ID_PATTERN.test(sessionId)) {
      continue;
    }
    const session = createSessionState(
      sessionId,
      join(stateDir, entry.name),
    );
    await replayJournal(session);
    sessions.set(sessionId, session);
  }
}

function appendJournalLine(session, record) {
  session.writeLock = session.writeLock.then(() =>
    appendFile(session.journalPath, `${JSON.stringify(record)}\n`, "utf8"),
  );
  return session.writeLock;
}

function messagesAfter(session, afterSeq) {
  return session.messages.filter(
    (envelope) => Number(envelope.seq) > afterSeq,
  );
}

function notifyWaiters(session, newSeq) {
  for (const waiter of [...session.waiters]) {
    if (newSeq > waiter.afterSeq) {
      waiter.finish(messagesAfter(session, waiter.afterSeq));
    }
  }
}

function waitForMessages(session, afterSeq, waitMs, req) {
  const immediate = messagesAfter(session, afterSeq);
  if (immediate.length > 0 || waitMs <= 0) {
    return Promise.resolve(immediate);
  }
  return new Promise((resolve) => {
    const waiter = { afterSeq, done: false, timer: null };
    const finish = (value) => {
      if (waiter.done) {
        return;
      }
      waiter.done = true;
      clearTimeout(waiter.timer);
      session.waiters.delete(waiter);
      req.removeListener("close", onClose);
      resolve(value);
    };
    waiter.finish = finish;
    waiter.timer = setTimeout(
      () => finish(messagesAfter(session, afterSeq)),
      waitMs,
    );
    function onClose() {
      finish(messagesAfter(session, afterSeq));
    }
    req.on("close", onClose);
    session.waiters.add(waiter);
  });
}

function requireSession(sessions, sessionId) {
  const session = sessions.get(sessionId);
  if (!session) {
    throw new RelayError("Unknown session.", "UNKNOWN_SESSION", {
      status: 404,
    });
  }
  return session;
}

function requireRole(role) {
  if (!PARTY_ROLES.includes(role)) {
    throw new RelayError("Unknown evidence role.", "UNKNOWN_ROLE", {
      status: 400,
    });
  }
  return role;
}

async function handleCreateSession(req, sessions, stateDir) {
  const bodyBuf = await readBoundedBody(
    req,
    MAX_SESSION_CREATE_BYTES,
    "BODY_TOO_LARGE",
  );
  const body = parseJsonBody(bodyBuf);
  if (body !== undefined && !isPlainObject(body)) {
    throw new RelayError(
      "Session registration body must be a JSON object.",
      "MALFORMED_REQUEST",
      { status: 400 },
    );
  }

  let sessionId = body?.sessionId;
  if (sessionId === undefined) {
    sessionId = randomUUID();
  }
  if (typeof sessionId !== "string" || !SESSION_ID_PATTERN.test(sessionId)) {
    throw new RelayError("Invalid session id.", "MALFORMED_SESSION_ID", {
      status: 400,
    });
  }
  if (sessions.has(sessionId)) {
    throw new RelayError("Session already exists.", "SESSION_EXISTS", {
      status: 409,
    });
  }

  let discovery;
  if (body?.discovery !== undefined) {
    if (!isPlainObject(body.discovery) && !Array.isArray(body.discovery)) {
      throw new RelayError(
        "Discovery document must be a JSON object or array.",
        "MALFORMED_REQUEST",
        { status: 400 },
      );
    }
    discovery = body.discovery;
  }

  const session = createSessionState(
    sessionId,
    join(stateDir, `${sessionId}${JOURNAL_SUFFIX}`),
  );
  session.discovery = discovery;
  // Reserve the id before the first await so two concurrent registrations
  // for the same id cannot both observe an empty map.
  sessions.set(sessionId, session);
  await appendJournalLine(session, {
    type: "session-created",
    sessionId,
    discovery: discovery ?? null,
  });

  return { sessionId, paymentMoved: false };
}

async function handlePostMessage(req, sessions, sessionId) {
  const session = requireSession(sessions, sessionId);
  const bodyBuf = await readBoundedBody(
    req,
    MAX_MESSAGE_BODY_BYTES,
    "BODY_TOO_LARGE",
  );
  const body = parseJsonBody(bodyBuf);
  const envelope = validateEnvelopeShape(body, sessionId);

  const seqNum = Number(envelope.seq);
  const expectedSeq = session.lastSeq + 1;
  if (seqNum !== expectedSeq) {
    throw new RelayError(
      "Message sequence number is out of order.",
      "SEQ_CONFLICT",
      { status: 409, detail: { expectedSeq: String(expectedSeq) } },
    );
  }

  await appendJournalLine(session, { type: "message", envelope });
  session.messages.push(envelope);
  session.lastSeq = seqNum;
  notifyWaiters(session, seqNum);

  return { seq: envelope.seq };
}

async function handleGetMessages(req, sessions, sessionId, url) {
  const session = requireSession(sessions, sessionId);

  const afterParam = url.searchParams.get("after") ?? "0";
  if (!SEQ_PATTERN.test(afterParam)) {
    throw new RelayError("Invalid 'after' query parameter.", "MALFORMED_QUERY", {
      status: 400,
    });
  }
  const afterSeq = Number(afterParam);

  const waitParam = url.searchParams.get("waitMs");
  let waitMs = waitParam === null ? DEFAULT_WAIT_MS : Number(waitParam);
  if (!Number.isFinite(waitMs) || waitMs < 0) {
    throw new RelayError(
      "Invalid 'waitMs' query parameter.",
      "MALFORMED_QUERY",
      { status: 400 },
    );
  }
  waitMs = Math.min(waitMs, MAX_WAIT_MS);

  const messages = await waitForMessages(session, afterSeq, waitMs, req);
  return { messages };
}

async function handlePutEvidence(req, sessions, sessionId, role) {
  const session = requireSession(sessions, sessionId);
  requireRole(role);

  const bodyBuf = await readBoundedBody(
    req,
    MAX_EVIDENCE_REQUEST_BYTES,
    "BODY_TOO_LARGE",
  );
  const body = parseJsonBody(bodyBuf);
  if (!hasExactKeys(body, ["json", "markdown", "marker"])) {
    throw new RelayError(
      "Evidence body must contain exactly json, markdown, and marker.",
      "MALFORMED_EVIDENCE",
      { status: 400 },
    );
  }

  const parts = {};
  for (const part of ["json", "markdown", "marker"]) {
    const value = body[part];
    if (typeof value !== "string" || !BASE64_PATTERN.test(value)) {
      throw new RelayError(
        `Evidence part "${part}" must be base64-encoded.`,
        "MALFORMED_EVIDENCE",
        { status: 400 },
      );
    }
    parts[part] = Buffer.from(value, "base64");
  }

  for (const part of ["json", "markdown", "marker"]) {
    if (parts[part].byteLength > EVIDENCE_PART_LIMITS[part]) {
      throw new RelayError(
        `Evidence part "${part}" exceeds the allowed size.`,
        "EVIDENCE_TOO_LARGE",
        { status: 413 },
      );
    }
  }

  session.evidence[role] = parts;
  await appendJournalLine(session, {
    type: "evidence",
    role,
    triple: {
      json: parts.json.toString("base64"),
      markdown: parts.markdown.toString("base64"),
      marker: parts.marker.toString("base64"),
    },
  });

  return { role };
}

function handleGetEvidence(sessions, sessionId, role) {
  const session = requireSession(sessions, sessionId);
  requireRole(role);
  const parts = session.evidence[role];
  if (!parts) {
    throw new RelayError(
      "Evidence has not been uploaded for this role.",
      "EVIDENCE_NOT_FOUND",
      { status: 404 },
    );
  }
  return {
    role,
    json: parts.json.toString("base64"),
    markdown: parts.markdown.toString("base64"),
    marker: parts.marker.toString("base64"),
  };
}

function handleDiscovery(sessions, sessionId) {
  const session = requireSession(sessions, sessionId);
  if (session.discovery === undefined) {
    throw new RelayError(
      "No discovery document has been published for this session.",
      "DISCOVERY_NOT_SET",
      { status: 404 },
    );
  }
  return session.discovery;
}

// GET returns the published monitor snapshot verbatim once one exists (see
// src/monitor/snapshot.mjs for the shape the stakeholder page expects at
// this exact URL) -- otherwise it falls back to the relay's own bookkeeping
// summary, which predates the monitor and is kept for whatever already reads
// it. The two shapes are distinguishable by their keys; a caller doing
// validateSnapshot() on the fallback shape will simply reject it, which is
// correct: there is nothing to render yet.
function handleSnapshot(sessions, sessionId) {
  const session = requireSession(sessions, sessionId);
  if (session.monitorSnapshot !== null) {
    return session.monitorSnapshot;
  }
  return {
    ok: true,
    sessionId,
    paymentMoved: false,
    lastSeq: String(session.lastSeq),
    messageCount: session.messages.length,
    messages: session.messages.map((envelope) => ({
      seq: envelope.seq,
      role: envelope.role,
      kind: envelope.kind,
    })),
    evidence: {
      payer: Boolean(session.evidence.payer),
      payee: Boolean(session.evidence.payee),
    },
    discoverySet: session.discovery !== undefined,
  };
}

// PUT publishes a monitor snapshot for a session -- the operator process is
// the only expected caller. Like evidence PUT, the relay does not
// authenticate this: it is an untrusted mailbox by design (see file header),
// and a snapshot is a narration of a run, not an authority over it -- a bad
// actor publishing a false snapshot cannot move the literal verdict word
// (that only ever comes from the verifier's signed publication, rendered
// from the verdict field this endpoint merely carries) and cannot make
// paymentMoved anything but false (validateSnapshot rejects that outright).
async function handlePutSnapshot(req, sessions, sessionId) {
  const session = requireSession(sessions, sessionId);
  const bodyBuf = await readBoundedBody(
    req,
    MAX_SNAPSHOT_BODY_BYTES,
    "BODY_TOO_LARGE",
  );
  const body = parseJsonBody(bodyBuf);
  if (!isPlainObject(body) || body.sessionId !== sessionId) {
    throw new RelayError(
      "Snapshot body must be a monitor snapshot for this session.",
      "MALFORMED_SNAPSHOT",
      { status: 400 },
    );
  }
  try {
    validateSnapshot(body);
  } catch {
    throw new RelayError(
      "Snapshot does not match the required shape.",
      "MALFORMED_SNAPSHOT",
      { status: 400 },
    );
  }

  session.monitorSnapshot = body;
  await appendJournalLine(session, { type: "monitor-snapshot", snapshot: body });

  return { sessionId };
}

async function serveStaticFile(res, filePath, contentType) {
  let body;
  try {
    body = await readFile(filePath);
  } catch {
    throw new RelayError("Static asset not found.", "NOT_FOUND", {
      status: 404,
    });
  }
  res.writeHead(200, {
    "content-type": contentType,
    "content-length": String(body.length),
    "cache-control": "no-store",
  });
  res.end(body);
}

async function dispatch(req, res, sessions, stateDir) {
  const url = new URL(req.url, "http://relay.local");
  const segments = url.pathname.split("/").filter(Boolean);
  const method = req.method;

  if (method === "GET" && segments.length === 1 && segments[0] === "healthz") {
    writeJson(res, 200, {
      ok: true,
      paymentMoved: false,
      sessions: sessions.size,
    });
    return;
  }

  if (method === "GET" && segments.length === 1 && segments[0] === "snapshot.mjs") {
    await serveStaticFile(res, SNAPSHOT_MODULE_PATH, "text/javascript; charset=utf-8");
    return;
  }

  if (method === "GET" && segments.length === 2 && segments[0] === "monitor") {
    const asset = STAKEHOLDER_STATIC_FILES[segments[1]];
    if (asset) {
      await serveStaticFile(res, asset.file, asset.contentType);
    } else {
      // Any other second segment is treated as a session id, not a missing
      // asset -- the page itself is what decides whether that session
      // exists, by polling the snapshot endpoint after it loads.
      await serveStaticFile(res, STAKEHOLDER_INDEX_FILE, "text/html; charset=utf-8");
    }
    return;
  }

  if (segments[0] !== "v1") {
    throw new RelayError("Unknown route.", "NOT_FOUND", { status: 404 });
  }

  if (method === "POST" && segments.length === 2 && segments[1] === "sessions") {
    const result = await handleCreateSession(req, sessions, stateDir);
    writeJson(res, 201, { ok: true, ...result });
    return;
  }

  if (
    segments[1] === "discovery" &&
    segments.length === 3 &&
    method === "GET"
  ) {
    const discovery = handleDiscovery(sessions, segments[2]);
    writeJson(res, 200, discovery);
    return;
  }

  if (segments[1] === "sessions" && segments.length >= 3) {
    const sessionId = segments[2];

    if (method === "POST" && segments.length === 4 && segments[3] === "messages") {
      const result = await handlePostMessage(req, sessions, sessionId);
      writeJson(res, 201, { ok: true, ...result });
      return;
    }

    if (method === "GET" && segments.length === 4 && segments[3] === "messages") {
      const result = await handleGetMessages(req, sessions, sessionId, url);
      writeJson(res, 200, { ok: true, ...result });
      return;
    }

    if (segments.length === 5 && segments[3] === "evidence") {
      const role = segments[4];
      if (method === "PUT") {
        const result = await handlePutEvidence(req, sessions, sessionId, role);
        writeJson(res, 200, { ok: true, ...result });
        return;
      }
      if (method === "GET") {
        const result = handleGetEvidence(sessions, sessionId, role);
        writeJson(res, 200, { ok: true, ...result });
        return;
      }
    }

    if (method === "GET" && segments.length === 4 && segments[3] === "snapshot") {
      writeJson(res, 200, handleSnapshot(sessions, sessionId));
      return;
    }

    if (method === "PUT" && segments.length === 4 && segments[3] === "snapshot") {
      const result = await handlePutSnapshot(req, sessions, sessionId);
      writeJson(res, 200, { ok: true, ...result });
      return;
    }
  }

  throw new RelayError("Unknown route.", "NOT_FOUND", { status: 404 });
}

/**
 * Construct the relay's http.Server. Re-reads every session journal already
 * present under `stateDir` before returning, so a fresh instance pointed at
 * an existing state directory resumes exactly where a killed instance left
 * off. Does not call `.listen()` -- the caller decides host/port (bin/relay.mjs
 * for real use, ephemeral port 0 in tests).
 */
export async function createRelayServer({ stateDir }) {
  if (typeof stateDir !== "string" || stateDir.length === 0) {
    throw new RelayError(
      "A relay requires a state directory.",
      "CONFIG",
      { status: 500 },
    );
  }
  await mkdir(stateDir, { recursive: true });

  const sessions = new Map();
  await loadExistingSessions(stateDir, sessions);

  const server = createServer((req, res) => {
    dispatch(req, res, sessions, stateDir).catch((error) => {
      if (res.headersSent) {
        res.destroy();
        return;
      }
      if (error instanceof RelayError) {
        writeJson(res, error.status ?? 400, {
          ok: false,
          error: error.code,
          ...(error.detail !== undefined ? { detail: error.detail } : {}),
        });
        return;
      }
      // Never leak a stack trace to a client; an unclassified failure is
      // reported generically.
      writeJson(res, 500, { ok: false, error: "FAILED" });
    });
  });

  server.on("close", () => {
    for (const session of sessions.values()) {
      for (const waiter of session.waiters) {
        clearTimeout(waiter.timer);
      }
      session.waiters.clear();
    }
  });

  return server;
}
