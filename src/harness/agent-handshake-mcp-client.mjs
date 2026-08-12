import { types } from "node:util";

import { parseSseJsonRpc, parseToolResult } from "../core/clockchain.mjs";

const ERROR = "Clockchain checkpoint submission failed safely.";
const ACCESS = /^ccra_[A-Za-z0-9_-]{22}$/;
const SIGNATURE = /^0x[0-9a-f]{130}$/;
const DIGEST = /^[0-9a-f]{64}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const ROLES = Object.freeze(["initiator", "responder"]);
const MAX_RESPONSE_BYTES = 64 * 1024;
const MAX_REQUEST_BYTES = 64 * 1024;

function fail() { throw new Error(ERROR); }

function clone(value, depth = 0) {
  if (depth > 16) fail();
  if (value === null || typeof value === "boolean") return value;
  if (typeof value === "string") { if (value.length > MAX_REQUEST_BYTES) fail(); return value; }
  if (typeof value === "number") { if (!Number.isFinite(value)) fail(); return value; }
  if (typeof value !== "object" || types.isProxy(value)) fail();
  if (Array.isArray(value)) {
    if (value.length > 64) fail();
    return value.map((item) => clone(item, depth + 1));
  }
  if (![Object.prototype, null].includes(Object.getPrototypeOf(value))) fail();
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const keys = Reflect.ownKeys(descriptors);
  if (keys.length > 32 || keys.some((key) => typeof key !== "string")) fail();
  const result = {};
  for (const key of keys) {
    const descriptor = descriptors[key];
    if (descriptor?.enumerable !== true || !Object.hasOwn(descriptor, "value")) fail();
    result[key] = clone(descriptor.value, depth + 1);
  }
  return result;
}

function exact(value, keys) {
  const item = clone(value);
  if (item === null || typeof item !== "object" || Array.isArray(item)) fail();
  if (JSON.stringify(Object.keys(item).sort()) !== JSON.stringify([...keys].sort())) fail();
  return item;
}

function exactOptions(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value) || types.isProxy(value)) fail();
  if (![Object.prototype, null].includes(Object.getPrototypeOf(value))) fail();
  const descriptors = Object.getOwnPropertyDescriptors(value);
  if (JSON.stringify(Reflect.ownKeys(descriptors).sort()) !== JSON.stringify(["endpoint", "fetchImpl", "timeoutMs"])) fail();
  const result = {};
  for (const key of ["endpoint", "fetchImpl", "timeoutMs"]) {
    const descriptor = descriptors[key];
    if (descriptor?.enumerable !== true || !Object.hasOwn(descriptor, "value")) fail();
    result[key] = descriptor.value;
  }
  return result;
}

async function readBounded(response) {
  if (!response?.body || typeof response.body.getReader !== "function") fail();
  const reader = response.body.getReader();
  const chunks = [];
  let total = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    if (!(value instanceof Uint8Array)) fail();
    total += value.byteLength;
    if (total > MAX_RESPONSE_BYTES) {
      try { await reader.cancel(); } catch {}
      fail();
    }
    chunks.push(Buffer.from(value));
  }
  return Buffer.concat(chunks, total).toString("utf8");
}

export function createAgentHandshakeCheckpointClient(options = {}) {
  try {
    const item = exactOptions(options);
    const endpoint = new URL(item.endpoint);
    if (
      endpoint.protocol !== "https:" || endpoint.username || endpoint.password ||
      endpoint.search || endpoint.hash || endpoint.pathname !== "/handshake/mcp" ||
      typeof item.fetchImpl !== "function" || !Number.isSafeInteger(item.timeoutMs) ||
      item.timeoutMs < 1 || item.timeoutMs > 30_000
    ) fail();
    let nextRequestId = 1;
    return Object.freeze({
      async submitCheckpoint(input) {
        try {
          const supplied = exact(input, ["access", "artifactSignatureHex", "checkpoint"]);
          if (!ACCESS.test(supplied.access) || !SIGNATURE.test(supplied.artifactSignatureHex)) fail();
          const checkpoint = clone(supplied.checkpoint);
          const id = nextRequestId++;
          const body = JSON.stringify({
            jsonrpc: "2.0",
            id,
            method: "tools/call",
            params: {
              name: "agent_handshake_submit_checkpoint",
              arguments: {
                access: supplied.access,
                artifactSignatureHex: supplied.artifactSignatureHex,
                checkpoint,
              },
            },
          });
          if (Buffer.byteLength(body) > MAX_REQUEST_BYTES) fail();
          const controller = new AbortController();
          const timeout = setTimeout(() => controller.abort(), item.timeoutMs);
          let response;
          let text;
          try {
            response = await item.fetchImpl(endpoint.href, {
              method: "POST",
              headers: { accept: "application/json, text/event-stream", "content-type": "application/json" },
              body,
              cache: "no-store",
              signal: controller.signal,
            });
            text = await readBounded(response);
          } finally {
            clearTimeout(timeout);
          }
          if (!Number.isInteger(response?.status) || response.status < 200 || response.status >= 300) fail();
          const result = exact(parseToolResult(parseSseJsonRpc(text, { expectedId: id })), [
            "role", "sessionId", "stage", "checkpointDigest", "roleAccess",
          ]);
          if (
            !ROLES.includes(result.role) || !UUID.test(result.sessionId) ||
            result.stage !== `${checkpoint.artifactType}_checkpoint_submitted` ||
            !DIGEST.test(result.checkpointDigest) || result.roleAccess !== supplied.access
          ) fail();
          return Object.freeze({
            role: result.role,
            sessionId: result.sessionId,
            stage: result.stage,
            checkpointDigest: result.checkpointDigest,
          });
        } catch { fail(); }
      },
    });
  } catch { fail(); }
}
