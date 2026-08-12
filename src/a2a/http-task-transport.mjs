import http from "node:http";

import { a2aAgentCardDigest } from "./agent-card.mjs";
import { createDirectTaskChannel } from "./direct-task-channel.mjs";
const ROLES = Object.freeze(["initiator", "responder"]);
const PATH = "/a2a/v1/envelopes";

function fail() {
  throw new Error("A2A HTTP task transport failed safely.");
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

export async function createHttpTaskTransport({
  sessionId,
  role,
  ownCard,
  peerCard,
  listenHost = "0.0.0.0",
  port = 8443,
  peerUrl = null,
  nowMs = () => Date.now(),
  maxBytes = 65536,
} = {}) {
  if (typeof sessionId !== "string" || sessionId.length === 0 || !ROLES.includes(role)) fail();
  if (typeof listenHost !== "string" || listenHost.length === 0 || !Number.isInteger(port) || port < 0 || port > 65535) fail();
  if (typeof nowMs !== "function" || !Number.isInteger(maxBytes) || maxBytes < 1024 || maxBytes > 262144) fail();
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
  const server = http.createServer(async (req, res) => {
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
  const url = `http://${address.address === "0.0.0.0" ? "127.0.0.1" : address.address}:${address.port}`;
  return Object.freeze({
    url,
    setPeerUrl(value) {
      if (typeof value !== "string" || !/^http:\/\/127\.0\.0\.1:[0-9]+$/.test(value)) fail();
      currentPeerUrl = value;
    },
    async sendEnvelope({ envelope }) {
      if (typeof currentPeerUrl !== "string") fail();
      const response = await fetch(`${currentPeerUrl}${PATH}`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ envelope }),
      });
      if (response.status !== 202) fail();
      const body = await response.json();
      if (!body?.ok || typeof body.messageDigest !== "string") fail();
      await channel.send({ fromRole: role, toRole: peerRole, envelope, nowMs: nowMs() });
      const message = channel.publicEvidence().messages.at(-1);
      sent.push(publicMessage(message, "outbound"));
      return Object.freeze({ messageDigest: body.messageDigest });
    },
    receive() {
      return channel.receive({ role });
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
