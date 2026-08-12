import { createHash, createPublicKey, randomUUID, X509Certificate, verify } from "node:crypto";
import https from "node:https";
import { isIP } from "node:net";
import { types } from "node:util";

import { a2aCanonicalBytes } from "./auth.mjs";

const PATH = "/a2a/v1/bootstrap/invitations";
const CARD_PATHS = Object.freeze({
  initiator_card: "/a2a/v1/bootstrap/cards/initiator",
  responder_card: "/a2a/v1/bootstrap/cards/responder",
});
const SCHEMA = "clockchain.invitation-bootstrap-envelope/v1";
const EVIDENCE_SCHEMA = "clockchain.invitation-bootstrap-transport-evidence/v1";
const ROLES = Object.freeze(["initiator", "responder"]);
const DIGEST = /^[0-9a-f]{64}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const PRIVATE_DNS = /^(?:[a-z0-9-]+\.)*(?:task\.local|internal|local)$/i;
const MAX_SIGNATURE_LIFETIME_MS = 180_000;
const MAX_CLOCK_SKEW_MS = 30_000;
const REQUEST_TIMEOUT_MS = 5_000;
const ENVELOPE_KEYS = Object.freeze([
  "artifactKind",
  "bodyLength",
  "bodySha256",
  "expiresAtMs",
  "issuedAtMs",
  "jti",
  "method",
  "nonce",
  "path",
  "receiverBootstrapPublicKey",
  "receiverCertificateSha256",
  "receiverPublicEndpoint",
  "receiverRole",
  "receiverRuntimeId",
  "receiverWorkloadAttestationDigest",
  "runId",
  "schema",
  "senderBootstrapPublicKey",
  "senderRole",
  "senderRuntimeId",
  "senderWorkloadAttestationDigest",
  "sessionId",
  "version",
]);

export const INVITATION_BOOTSTRAP_CARD_CAPABILITY = Symbol("clockchain.invitation-bootstrap-card-capability");

function fail() {
  throw new Error("Invitation bootstrap transport failed safely.");
}

function digestBytes(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function digestString(value) {
  return digestBytes(Buffer.from(value, "utf8"));
}

function snapshot(value, keys) {
  try {
    if (
      value === null ||
      typeof value !== "object" ||
      Array.isArray(value) ||
      types.isProxy(value) ||
      ![Object.prototype, null].includes(Object.getPrototypeOf(value))
    ) fail();
    const descriptors = Object.getOwnPropertyDescriptors(value);
    const actual = Reflect.ownKeys(descriptors);
    if (actual.length !== keys.length || actual.some((key) => typeof key !== "string" || !keys.includes(key))) fail();
    const result = {};
    for (const key of keys) {
      const descriptor = descriptors[key];
      if (descriptor?.enumerable !== true || !Object.hasOwn(descriptor, "value")) fail();
      result[key] = descriptor.value;
    }
    return result;
  } catch (error) {
    if (error?.message === "Invitation bootstrap transport failed safely.") throw error;
    fail();
  }
}

function optionalSnapshot(value, required, optional = []) {
  try {
    if (
      value === null ||
      typeof value !== "object" ||
      Array.isArray(value) ||
      types.isProxy(value) ||
      ![Object.prototype, null].includes(Object.getPrototypeOf(value))
    ) fail();
    const descriptors = Object.getOwnPropertyDescriptors(value);
    const allowed = [...required, ...optional];
    const actual = Reflect.ownKeys(descriptors);
    if (actual.some((key) => typeof key !== "string" || !allowed.includes(key))) fail();
    for (const key of required) if (!Object.hasOwn(descriptors, key)) fail();
    const result = {};
    for (const key of actual) {
      const descriptor = descriptors[key];
      if (descriptor?.enumerable !== true || !Object.hasOwn(descriptor, "value")) fail();
      result[key] = descriptor.value;
    }
    return result;
  } catch (error) {
    if (error?.message === "Invitation bootstrap transport failed safely.") throw error;
    fail();
  }
}

function assertToken(value) {
  if (typeof value !== "string" || value.length < 1 || value.length > 128 || !/^[A-Za-z0-9._:-]+$/.test(value)) fail();
  return value;
}

function assertSessionId(value) {
  if (typeof value !== "string" || !UUID.test(value)) fail();
  return value;
}

function assertDigest(value) {
  if (typeof value !== "string" || !DIGEST.test(value)) fail();
  return value;
}

function assertEd25519Pem(value) {
  if (typeof value !== "string" || value.length < 32 || value.length > 4096 || !value.includes("-----BEGIN PUBLIC KEY-----")) fail();
  try {
    if (createPublicKey(value).asymmetricKeyType !== "ed25519") fail();
  } catch (error) {
    if (error?.message === "Invitation bootstrap transport failed safely.") throw error;
    fail();
  }
  return value;
}

function role(value) {
  if (!ROLES.includes(value)) fail();
  return value;
}

function opposite(value) {
  if (value === "initiator") return "responder";
  if (value === "responder") return "initiator";
  fail();
}

function runtime(value) {
  const item = snapshot(value, ["runtimeId", "workloadAttestationDigest"]);
  return Object.freeze({
    runtimeId: assertToken(item.runtimeId),
    workloadAttestationDigest: assertDigest(item.workloadAttestationDigest),
  });
}

function tlsConfig(value) {
  const item = snapshot(value, ["certificate", "ownCertificateSha256", "peerCertificateSha256", "privateKey"]);
  if (typeof item.certificate !== "string" || !item.certificate.includes("-----BEGIN CERTIFICATE-----")) fail();
  if (typeof item.privateKey !== "string" || !item.privateKey.includes("-----BEGIN")) fail();
  const own = assertDigest(item.ownCertificateSha256);
  const actual = digestBytes(new X509Certificate(item.certificate).raw);
  if (own !== actual) fail();
  return Object.freeze({
    certificate: item.certificate,
    privateKey: item.privateKey,
    ownCertificateSha256: own,
    peerCertificateSha256: assertDigest(item.peerCertificateSha256),
  });
}

function signer(value) {
  const item = snapshot(value, ["publicKey", "signCanonicalBytes"]);
  assertEd25519Pem(item.publicKey);
  if (typeof item.signCanonicalBytes !== "function") fail();
  return Object.freeze({ publicKey: item.publicKey, signCanonicalBytes: item.signCanonicalBytes });
}

function privateHost(hostname, { allowLoopbackForTests = false } = {}) {
  if (allowLoopbackForTests && (hostname === "127.0.0.1" || hostname === "localhost")) return true;
  if (isIP(hostname) === 4) {
    const octets = hostname.split(".").map(Number);
    if (octets[0] === 10) return true;
    if (octets[0] === 192 && octets[1] === 168) return true;
    if (octets[0] === 172 && octets[1] >= 16 && octets[1] <= 31) return true;
    return false;
  }
  return PRIVATE_DNS.test(hostname);
}

function endpoint(value, { allowLoopbackForTests = false } = {}) {
  if (typeof value !== "string") fail();
  let parsed;
  try {
    parsed = new URL(value);
  } catch {
    fail();
  }
  if (
    parsed.protocol !== "https:" ||
    parsed.username !== "" ||
    parsed.password !== "" ||
    parsed.search !== "" ||
    parsed.hash !== "" ||
    (parsed.pathname !== "" && parsed.pathname !== "/") ||
    (!allowLoopbackForTests && parsed.port !== "8443") ||
    (allowLoopbackForTests && parsed.port === "") ||
    !privateHost(parsed.hostname, { allowLoopbackForTests })
  ) fail();
  return `${parsed.protocol}//${parsed.host}`;
}

function jsonResponse(res, status, body) {
  res.writeHead(status, { "content-type": "application/json", "cache-control": "no-store" });
  res.end(`${JSON.stringify(body)}\n`);
}

async function readBoundedJson(req, maxBytes) {
  let body = "";
  for await (const chunk of req) {
    body += Buffer.from(chunk).toString("utf8");
    if (Buffer.byteLength(body) > maxBytes) fail();
  }
  try {
    const parsed = JSON.parse(body);
    if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) fail();
    return snapshot(parsed, ["body", "envelope"]);
  } catch (error) {
    if (error?.message === "Invitation bootstrap transport failed safely.") throw error;
    fail();
  }
}

function fingerprint(cert) {
  if (!cert?.raw) fail();
  return digestBytes(cert.raw);
}

async function postJson(url, payload, tls, maxBytes) {
  const parsed = new URL(url);
  const body = JSON.stringify(payload);
  if (Buffer.byteLength(body) > maxBytes) fail();
  return new Promise((resolve, reject) => {
    let peerFingerprint = null;
    const request = https.request({
      hostname: parsed.hostname,
      port: parsed.port,
      path: parsed.pathname,
      method: "POST",
      headers: { "content-type": "application/json", "content-length": Buffer.byteLength(body) },
      rejectUnauthorized: false,
      checkServerIdentity: () => undefined,
    }, (response) => {
      let responseBody = "";
      response.setTimeout(REQUEST_TIMEOUT_MS, () => {
        request.destroy();
        reject(new Error("timeout"));
      });
      response.on("data", (chunk) => {
        responseBody += Buffer.from(chunk).toString("utf8");
        if (Buffer.byteLength(responseBody) > maxBytes) {
          request.destroy();
          reject(new Error("too large"));
        }
      });
      response.on("end", () => {
        try {
          if (peerFingerprint !== tls.peerCertificateSha256) fail();
          resolve({ status: response.statusCode, body: JSON.parse(responseBody) });
        } catch (error) {
          reject(error);
        }
      });
    });
    request.setTimeout(REQUEST_TIMEOUT_MS, () => {
      request.destroy();
      reject(new Error("timeout"));
    });
    request.on("socket", (socket) => {
      socket.setTimeout(REQUEST_TIMEOUT_MS, () => {
        request.destroy();
        reject(new Error("timeout"));
      });
      socket.on("secureConnect", () => {
        try {
          peerFingerprint = fingerprint(socket.getPeerCertificate());
          if (peerFingerprint !== tls.peerCertificateSha256) {
            request.destroy();
            reject(new Error("bad pin"));
            return;
          }
          request.end(body);
        } catch (error) {
          request.destroy();
          reject(error);
        }
      });
    });
    request.on("error", reject);
  }).catch(() => fail());
}

function cleanEnvelope(value) {
  const item = optionalSnapshot(value, [...ENVELOPE_KEYS, "signature"]);
  const signature = snapshot(item.signature, ["algorithm", "value"]);
  if (signature.algorithm !== "ed25519" || typeof signature.value !== "string" || !/^[A-Za-z0-9+/]+={0,2}$/.test(signature.value)) fail();
  const unsigned = {};
  for (const key of ENVELOPE_KEYS) unsigned[key] = item[key];
  return Object.freeze({
    unsigned: Object.freeze(unsigned),
    signature: Object.freeze({ algorithm: "ed25519", value: signature.value }),
  });
}

function assertDecimalString(value) {
  if (typeof value !== "string" || !/^(?:0|[1-9][0-9]*)$/.test(value)) fail();
  return value;
}

function verifyEnvelope({ envelope, body, now, expected, artifactKind = "invitation", path = PATH }) {
  const clean = cleanEnvelope(envelope);
  const unsigned = clean.unsigned;
  if (
    unsigned.schema !== SCHEMA ||
    unsigned.version !== 1 ||
    unsigned.artifactKind !== artifactKind ||
    unsigned.method !== "POST" ||
    unsigned.path !== path ||
    unsigned.runId !== expected.runId ||
    unsigned.senderRole !== expected.peerRole ||
    unsigned.receiverRole !== expected.role ||
    unsigned.senderRuntimeId !== expected.peerRuntime.runtimeId ||
    unsigned.receiverRuntimeId !== expected.localRuntime.runtimeId ||
    unsigned.senderWorkloadAttestationDigest !== expected.peerRuntime.workloadAttestationDigest ||
    unsigned.receiverWorkloadAttestationDigest !== expected.localRuntime.workloadAttestationDigest ||
    unsigned.senderBootstrapPublicKey !== expected.peerBootstrapPublicKey ||
    unsigned.receiverBootstrapPublicKey !== expected.bootstrapSigner.publicKey ||
    unsigned.receiverPublicEndpoint !== expected.publicUrl ||
    unsigned.receiverCertificateSha256 !== expected.tls.ownCertificateSha256 ||
    unsigned.bodySha256 !== digestString(body) ||
    unsigned.bodyLength !== Buffer.byteLength(body)
  ) fail();
  assertSessionId(unsigned.sessionId);
  assertDecimalString(unsigned.issuedAtMs);
  assertDecimalString(unsigned.expiresAtMs);
  const issued = Number(unsigned.issuedAtMs);
  const expires = Number(unsigned.expiresAtMs);
  if (!Number.isSafeInteger(issued) || !Number.isSafeInteger(expires)) fail();
  if (issued >= expires || issued - MAX_CLOCK_SKEW_MS > now || now >= expires || expires - issued > MAX_SIGNATURE_LIFETIME_MS) fail();
  assertToken(unsigned.nonce);
  assertToken(unsigned.jti);
  let ok = false;
  try {
    ok = verify(null, a2aCanonicalBytes(unsigned), createPublicKey(expected.peerBootstrapPublicKey), Buffer.from(clean.signature.value, "base64"));
  } catch {
    fail();
  }
  if (ok !== true) fail();
  return unsigned;
}

function signedEnvelope({ artifactKind = "invitation", bootstrapSigner, body, expiresAtMs, localRuntime, path = PATH, peerBootstrapPublicKey, peerRuntime, peerRole, peerUrl, role, runId, sessionId, tls, now, nonce, jti }) {
  const unsigned = Object.freeze({
    schema: SCHEMA,
    version: 1,
    artifactKind,
    method: "POST",
    path,
    runId,
    sessionId,
    senderRole: role,
    receiverRole: peerRole,
    senderRuntimeId: localRuntime.runtimeId,
    receiverRuntimeId: peerRuntime.runtimeId,
    senderWorkloadAttestationDigest: localRuntime.workloadAttestationDigest,
    receiverWorkloadAttestationDigest: peerRuntime.workloadAttestationDigest,
    senderBootstrapPublicKey: bootstrapSigner.publicKey,
    receiverBootstrapPublicKey: peerBootstrapPublicKey,
    receiverPublicEndpoint: peerUrl,
    receiverCertificateSha256: tls.peerCertificateSha256,
    bodySha256: digestString(body),
    bodyLength: Buffer.byteLength(body),
    issuedAtMs: String(now),
    expiresAtMs: String(expiresAtMs),
    nonce,
    jti,
  });
  let value;
  try {
    value = bootstrapSigner.signCanonicalBytes(a2aCanonicalBytes(unsigned));
  } catch {
    fail();
  }
  if (typeof value !== "string") fail();
  return Object.freeze({ ...unsigned, signature: Object.freeze({ algorithm: "ed25519", value }) });
}

function publicInvitation({ direction, invitationDigest, sessionId, timestampMs }) {
  return Object.freeze({ direction, invitationDigest, sessionId, timestampMs });
}

export async function createInvitationBootstrapTransport(optionsInput = {}) {
  const options = optionalSnapshot(optionsInput, [
    "bootstrapSigner", "initialSessionId", "localRuntime", "peerBootstrapPublicKey",
    "peerRole", "peerRuntime", "role", "runId", "tls",
  ], [
    "allowLoopbackForTests", "listenHost", "maxBytes", "nowMs", "peerUrl", "port", "publicEndpoint",
  ]);
  const allowLoopbackForTests = options.allowLoopbackForTests ?? false;
  const listenHost = options.listenHost ?? "0.0.0.0";
  const maxBytes = options.maxBytes ?? 64 * 1024;
  const nowMs = options.nowMs ?? (() => Date.now());
  const port = options.port ?? 8443;
  if (allowLoopbackForTests !== true && allowLoopbackForTests !== false) fail();
  if (typeof listenHost !== "string" || listenHost.length === 0 || !Number.isInteger(port) || port < 0 || port > 65535) fail();
  if (!allowLoopbackForTests && (listenHost === "127.0.0.1" || listenHost === "localhost")) fail();
  if (!Number.isInteger(maxBytes) || maxBytes < 1024 || maxBytes > 262144 || typeof nowMs !== "function") fail();
  const localRole = role(options.role);
  const remoteRole = role(options.peerRole);
  if (opposite(localRole) !== remoteRole) fail();
  const cleanTls = tlsConfig(options.tls);
  const cleanSigner = signer(options.bootstrapSigner);
  const cleanLocalRuntime = runtime(options.localRuntime);
  const cleanPeerRuntime = runtime(options.peerRuntime);
  const peerBootstrapPublicKey = assertEd25519Pem(options.peerBootstrapPublicKey);
  if (peerBootstrapPublicKey === cleanSigner.publicKey) fail();
  const runId = assertToken(options.runId);
  let boundSessionId = options.initialSessionId;
  if (boundSessionId !== null) assertSessionId(boundSessionId);
  let currentPeerUrl = options.peerUrl === undefined || options.peerUrl === null ? null : endpoint(options.peerUrl, { allowLoopbackForTests });
  if (listenHost === "0.0.0.0" && !allowLoopbackForTests && options.publicEndpoint === undefined) fail();
  const configuredPublicUrl = options.publicEndpoint === undefined ? null : endpoint(options.publicEndpoint, { allowLoopbackForTests });
  const received = [];
  const sent = [];
  const used = new Set();
  let stored = null;
  let receiving = false;
  let receivedOnce = false;
  let sentOnce = false;
  let closed = false;
  let publicUrl = null;
  const sockets = new Set();
  const cardReceiving = new Set();
  const cardReceived = new Set();
  const cardSent = new Set();
  let cardReceiver = null;
  let cardRetired = false;

  async function receiveCard(req, res, artifactKind) {
    const path = CARD_PATHS[artifactKind];
    if (
      cardRetired || cardReceiver === null || boundSessionId === null ||
      cardReceiving.has(artifactKind) || cardReceived.has(artifactKind)
    ) fail();
    cardReceiving.add(artifactKind);
    try {
      const request = await readBoundedJson(req, maxBytes);
      if (typeof request.body !== "string" || Buffer.byteLength(request.body) < 1 || Buffer.byteLength(request.body) > maxBytes) fail();
      const now = nowMs();
      if (!Number.isSafeInteger(now)) fail();
      const unsigned = verifyEnvelope({
        artifactKind,
        path,
        envelope: request.envelope,
        body: request.body,
        now,
        expected: {
          bootstrapSigner: cleanSigner,
          localRuntime: cleanLocalRuntime,
          peerBootstrapPublicKey,
          peerRole: remoteRole,
          peerRuntime: cleanPeerRuntime,
          publicUrl,
          role: localRole,
          runId,
          tls: cleanTls,
        },
      });
      if (unsigned.sessionId !== boundSessionId) fail();
      const replayKey = `${unsigned.nonce}:${unsigned.jti}`;
      if (used.has(replayKey)) fail();
      used.add(replayKey);
      const artifactDigest = await cardReceiver({ artifactKind, body: request.body });
      assertDigest(artifactDigest);
      cardReceived.add(artifactKind);
      jsonResponse(res, 202, { ok: true, artifactDigest });
    } finally {
      cardReceiving.delete(artifactKind);
    }
  }

  const server = https.createServer({ key: cleanTls.privateKey, cert: cleanTls.certificate }, async (req, res) => {
    try {
      const cardEntry = Object.entries(CARD_PATHS).find(([, path]) => path === req.url) ?? null;
      const knownPath = req.url === PATH || cardEntry !== null;
      if (req.method !== "POST" || !knownPath || req.headers["content-type"] !== "application/json") {
        jsonResponse(res, req.method === "POST" ? 404 : 405, { ok: false });
        return;
      }
      req.setTimeout(REQUEST_TIMEOUT_MS, () => req.destroy());
      res.setTimeout(REQUEST_TIMEOUT_MS, () => res.destroy());
      if (cardEntry !== null) {
        await receiveCard(req, res, cardEntry[0]);
        return;
      }
      if (cardRetired) fail();
      if (receiving || receivedOnce || stored !== null) fail();
      receiving = true;
      try {
        const request = await readBoundedJson(req, maxBytes);
        if (typeof request.body !== "string" || Buffer.byteLength(request.body) < 1 || Buffer.byteLength(request.body) > maxBytes) fail();
        const now = nowMs();
        if (!Number.isSafeInteger(now)) fail();
        const unsigned = verifyEnvelope({
          envelope: request.envelope,
          body: request.body,
          now,
          expected: {
            bootstrapSigner: cleanSigner,
            localRuntime: cleanLocalRuntime,
            peerBootstrapPublicKey,
            peerRole: remoteRole,
            peerRuntime: cleanPeerRuntime,
            publicUrl,
            role: localRole,
            runId,
            tls: cleanTls,
          },
        });
        if (boundSessionId === null) {
          boundSessionId = unsigned.sessionId;
        } else if (boundSessionId !== unsigned.sessionId) {
          fail();
        }
        const replayKey = `${unsigned.nonce}:${unsigned.jti}`;
        if (used.has(replayKey)) fail();
        used.add(replayKey);
        const invitationDigest = digestString(request.body);
        stored = Object.freeze({ invitation: request.body, invitationDigest, sessionId: unsigned.sessionId });
        receivedOnce = true;
        received.push(publicInvitation({ direction: "inbound", invitationDigest, sessionId: unsigned.sessionId, timestampMs: now }));
        jsonResponse(res, 202, { ok: true, invitationDigest });
      } finally {
        receiving = false;
      }
    } catch {
      jsonResponse(res, 400, { ok: false });
    }
  });
  server.on("connection", (socket) => {
    sockets.add(socket);
    socket.setTimeout(REQUEST_TIMEOUT_MS, () => socket.destroy());
    socket.on("close", () => sockets.delete(socket));
  });
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(port, listenHost, () => {
      server.off("error", reject);
      resolve();
    });
  }).catch(() => fail());
  const address = server.address();
  const localUrl = `https://${address.address === "0.0.0.0" ? "127.0.0.1" : address.address}:${address.port}`;
  publicUrl = configuredPublicUrl ?? endpoint(localUrl, { allowLoopbackForTests });

  const cardCapability = Object.freeze({
    registerReceiver(receiver) {
      if (closed || cardRetired || cardReceiver !== null || typeof receiver !== "function") fail();
      cardReceiver = receiver;
    },
    async sendCard(input) {
      if (closed || cardRetired || boundSessionId === null || typeof currentPeerUrl !== "string") fail();
      const item = snapshot(input, ["artifactKind", "body", "expiresAtMs"]);
      const expectedKind = `${localRole}_card`;
      if (item.artifactKind !== expectedKind || cardSent.has(expectedKind)) fail();
      if (typeof item.body !== "string" || Buffer.byteLength(item.body) < 1 || Buffer.byteLength(item.body) > maxBytes) fail();
      const now = nowMs();
      if (
        !Number.isSafeInteger(now) || !Number.isSafeInteger(item.expiresAtMs) ||
        item.expiresAtMs <= now || item.expiresAtMs - now > MAX_SIGNATURE_LIFETIME_MS
      ) fail();
      cardSent.add(expectedKind);
      const path = CARD_PATHS[expectedKind];
      const envelope = signedEnvelope({
        artifactKind: expectedKind,
        path,
        bootstrapSigner: cleanSigner,
        body: item.body,
        expiresAtMs: item.expiresAtMs,
        localRuntime: cleanLocalRuntime,
        peerBootstrapPublicKey,
        peerRuntime: cleanPeerRuntime,
        peerRole: remoteRole,
        peerUrl: currentPeerUrl,
        role: localRole,
        runId,
        sessionId: boundSessionId,
        tls: cleanTls,
        now,
        nonce: `nonce-${randomUUID()}`,
        jti: `jti-${randomUUID()}`,
      });
      const response = await postJson(`${currentPeerUrl}${path}`, { envelope, body: item.body }, cleanTls, maxBytes);
      if (response.status !== 202 || response.body?.ok !== true) fail();
      assertDigest(response.body.artifactDigest);
      return Object.freeze({ artifactDigest: response.body.artifactDigest, acknowledged: true });
    },
    retire() {
      cardRetired = true;
      cardReceiver = null;
    },
  });

  const api = {
    publicUrl,
    setPeerUrl(value) {
      if (closed || cardRetired || sentOnce || cardSent.size > 0) fail();
      const next = endpoint(value, { allowLoopbackForTests });
      if (currentPeerUrl !== null && currentPeerUrl !== next) fail();
      currentPeerUrl = next;
    },
    async sendInvitation(input) {
      if (closed || cardRetired || typeof currentPeerUrl !== "string") fail();
      if (sentOnce) fail();
      const item = snapshot(input, ["expiresAtMs", "invitation", "sessionId"]);
      if (typeof item.invitation !== "string" || Buffer.byteLength(item.invitation) < 1 || Buffer.byteLength(item.invitation) > maxBytes) fail();
      assertSessionId(item.sessionId);
      if (boundSessionId === null) {
        boundSessionId = item.sessionId;
      } else if (boundSessionId !== item.sessionId) {
        fail();
      }
      const now = nowMs();
      if (!Number.isSafeInteger(now) || !Number.isSafeInteger(item.expiresAtMs) || item.expiresAtMs <= now || item.expiresAtMs - now > MAX_SIGNATURE_LIFETIME_MS) fail();
      const invitationDigest = digestString(item.invitation);
      sentOnce = true;
      const envelope = signedEnvelope({
        bootstrapSigner: cleanSigner,
        body: item.invitation,
        expiresAtMs: item.expiresAtMs,
        localRuntime: cleanLocalRuntime,
        peerBootstrapPublicKey,
        peerRuntime: cleanPeerRuntime,
        peerRole: remoteRole,
        peerUrl: currentPeerUrl,
        role: localRole,
        runId,
        sessionId: item.sessionId,
        tls: cleanTls,
        now,
        nonce: `nonce-${randomUUID()}`,
        jti: `jti-${randomUUID()}`,
      });
      let response;
      try {
        response = await postJson(`${currentPeerUrl}${PATH}`, { envelope, body: item.invitation }, cleanTls, maxBytes);
      } catch {
        fail();
      }
      if (response.status !== 202 || response.body?.ok !== true || response.body.invitationDigest !== invitationDigest) fail();
      sent.push(publicInvitation({ direction: "outbound", invitationDigest, sessionId: item.sessionId, timestampMs: now }));
      return Object.freeze({ invitationDigest, acknowledged: true });
    },
    takeInvitation() {
      if (closed || stored === null) fail();
      const value = stored;
      stored = null;
      return Object.freeze({ ...value });
    },
    publicEvidence() {
      return Object.freeze({
        schema: EVIDENCE_SCHEMA,
        runId,
        role: localRole,
        peerRole: remoteRole,
        sessionId: boundSessionId,
        localRuntimeId: cleanLocalRuntime.runtimeId,
        peerRuntimeId: cleanPeerRuntime.runtimeId,
        localWorkloadAttestationDigest: cleanLocalRuntime.workloadAttestationDigest,
        peerWorkloadAttestationDigest: cleanPeerRuntime.workloadAttestationDigest,
        localBootstrapPublicKeySha256: digestString(cleanSigner.publicKey),
        peerBootstrapPublicKeySha256: digestString(peerBootstrapPublicKey),
        localCertificateSha256: cleanTls.ownCertificateSha256,
        peerCertificateSha256: cleanTls.peerCertificateSha256,
        invitations: Object.freeze([...received, ...sent].map((entry) => Object.freeze({ ...entry }))),
      });
    },
    async close() {
      if (closed) return Object.freeze({ closed: true });
      closed = true;
      cardRetired = true;
      cardReceiver = null;
      for (const socket of sockets) socket.destroy();
      await new Promise((resolve, reject) => {
        server.close((error) => (error ? reject(error) : resolve()));
      }).catch(() => fail());
      stored = null;
      return Object.freeze({ closed: true });
    },
  };
  Object.defineProperty(api, INVITATION_BOOTSTRAP_CARD_CAPABILITY, {
    configurable: false,
    enumerable: false,
    value: cardCapability,
    writable: false,
  });
  return Object.freeze(api);
}
