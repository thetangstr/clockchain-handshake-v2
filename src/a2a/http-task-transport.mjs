import { createHash } from "node:crypto";
import https from "node:https";
import { isIP } from "node:net";
import { types } from "node:util";

import { a2aAgentCardDigest } from "./agent-card.mjs";
import { createDirectTaskChannel } from "./direct-task-channel.mjs";
const ROLES = Object.freeze(["initiator", "responder"]);
const PATH = "/a2a/v1/envelopes";
const PRIVATE_DNS = /^(?:[a-z0-9-]+\.)*(?:task\.local|internal|local)$/i;

function fail() {
  throw new Error("A2A HTTP task transport failed safely.");
}

function snapshot(value, keys) {
  try {
    if (value === null || typeof value !== "object" || Array.isArray(value) || types.isProxy(value)) fail();
    const descriptors = Object.getOwnPropertyDescriptors(value);
    const actual = Reflect.ownKeys(descriptors);
    if (actual.some((key) => typeof key !== "string") || actual.some((key) => !keys.includes(key))) fail();
    const result = {};
    for (const key of actual) {
      const descriptor = descriptors[key];
      if (!descriptor.enumerable || !Object.hasOwn(descriptor, "value")) fail();
      result[key] = descriptor.value;
    }
    return result;
  } catch (error) {
    if (error?.message === "A2A HTTP task transport failed safely.") throw error;
    fail();
  }
}

function opposite(role) {
  if (role === "initiator") return "responder";
  if (role === "responder") return "initiator";
  fail();
}

function jsonResponse(res, status, body) {
  res.writeHead(status, { "content-type": "application/json", "cache-control": "no-store" });
  res.end(`${JSON.stringify(body)}\n`);
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

function tlsOptions(value) {
  const item = snapshot(value, ["cert", "key", "peerCa", "peerCertificateSha256"]);
  if (typeof item.key !== "string" || typeof item.cert !== "string") fail();
  if (typeof item.peerCa !== "string" || !/^[0-9a-f]{64}$/.test(item.peerCertificateSha256)) fail();
  return Object.freeze({ ...item });
}

function fingerprint(cert) {
  if (!cert?.raw) fail();
  return createHash("sha256").update(cert.raw).digest("hex");
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
      ca: tls.peerCa,
      rejectUnauthorized: true,
      checkServerIdentity: () => undefined,
    }, (response) => {
      let responseBody = "";
      response.on("data", (chunk) => {
        responseBody += Buffer.from(chunk).toString("utf8");
        if (Buffer.byteLength(responseBody) > maxBytes) {
          request.destroy();
          reject(new Error("too large"));
        }
      });
      response.on("end", () => {
        try {
          if (tls.peerCertificateSha256 !== undefined && peerFingerprint !== tls.peerCertificateSha256) fail();
          resolve({ status: response.statusCode, body: JSON.parse(responseBody) });
        } catch (error) {
          reject(error);
        }
      });
    });
    request.on("socket", (socket) => {
      socket.on("secureConnect", () => {
        try {
          peerFingerprint = fingerprint(socket.getPeerCertificate());
          if (peerFingerprint !== tls.peerCertificateSha256) {
            request.destroy();
            reject(new Error("bad pin"));
            return;
          }
          request.end(body);
        } catch {
          peerFingerprint = null;
          request.destroy();
          reject(new Error("bad pin"));
        }
      });
    });
    request.on("error", reject);
  }).catch(() => fail());
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
    const keys = Object.keys(parsed);
    if (keys.length !== 1 || keys[0] !== "envelope") fail();
    return parsed.envelope;
  } catch {
    fail();
  }
}

function publicMessage(message, direction) {
  return Object.freeze({
    direction,
    fromRole: message.fromRole,
    toRole: message.toRole,
    sequence: message.sequence,
    artifactType: message.artifactType,
    artifactDigest: message.artifactDigest,
    messageDigest: message.messageDigest,
  });
}

export async function createHttpTaskTransport(optionsInput = {}) {
  const options = snapshot(optionsInput, [
    "allowLoopbackForTests", "listenHost", "maxBytes", "nowMs", "ownCard", "peerCard", "peerUrl",
    "port", "publicEndpoint", "role", "sessionId", "tls",
  ]);
  const {
    allowLoopbackForTests = false,
    sessionId,
    role,
    ownCard,
    peerCard,
    listenHost = "0.0.0.0",
    port = 8443,
    peerUrl = null,
    nowMs = () => Date.now(),
    maxBytes = 65536,
  } = options;
  const tls = tlsOptions(options.tls);
  if (typeof sessionId !== "string" || sessionId.length === 0 || !ROLES.includes(role)) fail();
  if (allowLoopbackForTests !== true && allowLoopbackForTests !== false) fail();
  if (typeof listenHost !== "string" || listenHost.length === 0 || !Number.isInteger(port) || port < 0 || port > 65535) fail();
  if (!allowLoopbackForTests && (listenHost === "127.0.0.1" || listenHost === "localhost")) fail();
  if (listenHost === "0.0.0.0" && !allowLoopbackForTests && options.publicEndpoint === undefined) fail();
  const configuredPublicUrl = options.publicEndpoint === undefined ? null : endpoint(options.publicEndpoint, { allowLoopbackForTests });
  if (typeof nowMs !== "function" || !Number.isInteger(maxBytes) || maxBytes < 1024 || maxBytes > 262144) fail();
  if (peerUrl !== null) endpoint(peerUrl, { allowLoopbackForTests });
  const peerRole = opposite(role);
  const channel = await createDirectTaskChannel({
    sessionId,
    initiatorCard: role === "initiator" ? ownCard : peerCard,
    responderCard: role === "responder" ? ownCard : peerCard,
    nowMs: nowMs(),
  });
  let currentPeerUrl = peerUrl;
  const received = [];
  const sent = [];
  const server = https.createServer({ key: tls.key, cert: tls.cert }, async (req, res) => {
    try {
      if (req.method !== "POST" || req.url !== PATH || req.headers["content-type"] !== "application/json") {
        jsonResponse(res, req.method === "POST" ? 404 : 405, { ok: false });
        return;
      }
      const envelope = await readBoundedJson(req, maxBytes);
      const result = await channel.send({ fromRole: peerRole, toRole: role, envelope, nowMs: nowMs() });
      const message = channel.publicEvidence().messages.at(-1);
      received.push(publicMessage(message, "inbound"));
      jsonResponse(res, 202, { ok: true, messageDigest: result.messageDigest });
    } catch {
      jsonResponse(res, 400, { ok: false });
    }
  });
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(port, listenHost, () => {
      server.off("error", reject);
      resolve();
    });
  });
  const address = server.address();
  const localUrl = `https://${address.address === "0.0.0.0" ? "127.0.0.1" : address.address}:${address.port}`;
  const publicUrl = configuredPublicUrl ?? endpoint(localUrl, { allowLoopbackForTests });
  return Object.freeze({
    url: localUrl,
    publicUrl,
    setPeerUrl(value) {
      currentPeerUrl = endpoint(value, { allowLoopbackForTests });
    },
    async sendEnvelope(input) {
      const { envelope } = snapshot(input, ["envelope"]);
      if (typeof currentPeerUrl !== "string") fail();
      const response = await postJson(`${currentPeerUrl}${PATH}`, { envelope }, tls, maxBytes);
      if (response.status !== 202) fail();
      const body = response.body;
      if (!body?.ok || typeof body.messageDigest !== "string") fail();
      await channel.send({ fromRole: role, toRole: peerRole, envelope, nowMs: nowMs() });
      const message = channel.publicEvidence().messages.at(-1);
      sent.push(publicMessage(message, "outbound"));
      return Object.freeze({ messageDigest: body.messageDigest });
    },
    receive() {
      return channel.receive({ role });
    },
    async postJsonForTests(path, body) {
      if (allowLoopbackForTests !== true || typeof path !== "string" || !path.startsWith("/")) fail();
      return postJson(`${localUrl}${path}`, body, tls, maxBytes);
    },
    publicEvidence() {
      return Object.freeze({
        schema: "clockchain.a2a-http-task-transport-evidence/v1",
        sessionId,
        role,
        endpointDigest: a2aAgentCardDigest(ownCard),
        cardDigests: Object.freeze({
          initiator: a2aAgentCardDigest(role === "initiator" ? ownCard : peerCard),
          responder: a2aAgentCardDigest(role === "responder" ? ownCard : peerCard),
        }),
        messages: Object.freeze([...received, ...sent].map((entry) => Object.freeze({ ...entry }))),
      });
    },
    async close() {
      await new Promise((resolve) => server.close(resolve));
    },
  });
}
