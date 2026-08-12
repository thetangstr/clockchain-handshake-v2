import { createPublicKey } from "node:crypto";
import { types } from "node:util";

export const BOOTSTRAP_DESCRIPTOR_SCHEMA = "clockchain.mechanics-proof-party-bootstrap/v1";

const ERROR = "Bootstrap exchange contract validation failed safely.";
const ROLES = Object.freeze(["initiator", "responder"]);
const HARNESSES = Object.freeze(["codex", "claude"]);
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const DIGEST = /^[0-9a-f]{64}$/;
const TOKEN = /^[A-Za-z0-9._:-]{1,128}$/;
const MAX_DESCRIPTOR_BYTES = 64 * 1024;
const MAX_WAIT_MS = 60_000;

function fail() { throw new Error(ERROR); }
function sanitize(error) { if (error?.message === ERROR) throw error; fail(); }

function exact(value, keys) {
  try {
    if (
      value === null || typeof value !== "object" || Array.isArray(value) || types.isProxy(value) ||
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
  } catch (error) { sanitize(error); }
}

function endpoint(value) {
  let url;
  try { url = new URL(value); } catch { fail(); }
  if (
    url.protocol !== "https:" || url.username !== "" || url.password !== "" || url.search !== "" ||
    url.hash !== "" || (url.pathname !== "" && url.pathname !== "/") || url.port !== "8443"
  ) fail();
  return `${url.protocol}//${url.host}`;
}

function runtimeBinding(value) {
  const item = exact(value, ["endpoint", "runtimeId", "taskId", "tlsCertificateSha256", "workloadAttestationDigest"]);
  if (
    !TOKEN.test(item.runtimeId) || !TOKEN.test(item.taskId) || !DIGEST.test(item.tlsCertificateSha256) ||
    !DIGEST.test(item.workloadAttestationDigest)
  ) fail();
  return Object.freeze({ ...item, endpoint: endpoint(item.endpoint) });
}

export function validateBootstrapDescriptor(value) {
  try {
    const item = exact(value, ["bootstrapPublicKey", "harness", "role", "runId", "runtime", "schema", "tlsCertificate"]);
    if (
      item.schema !== BOOTSTRAP_DESCRIPTOR_SCHEMA || !HARNESSES.includes(item.harness) || !ROLES.includes(item.role) ||
      !UUID.test(item.runId) || typeof item.bootstrapPublicKey !== "string" || item.bootstrapPublicKey.length > 4096 ||
      typeof item.tlsCertificate !== "string" || item.tlsCertificate.length > MAX_DESCRIPTOR_BYTES ||
      !item.tlsCertificate.startsWith("-----BEGIN CERTIFICATE-----\n") ||
      !item.tlsCertificate.endsWith("-----END CERTIFICATE-----\n")
    ) fail();
    try { if (createPublicKey(item.bootstrapPublicKey).asymmetricKeyType !== "ed25519") fail(); } catch { fail(); }
    const runtime = runtimeBinding(item.runtime);
    const clean = Object.freeze({
      schema: item.schema,
      bootstrapPublicKey: item.bootstrapPublicKey,
      harness: item.harness,
      role: item.role,
      runId: item.runId,
      runtime,
      tlsCertificate: item.tlsCertificate,
    });
    if (Buffer.byteLength(JSON.stringify(clean), "utf8") > MAX_DESCRIPTOR_BYTES) fail();
    return clean;
  } catch (error) { sanitize(error); }
}

function opposite(role) { return role === "initiator" ? "responder" : "initiator"; }

export function createBootstrapExchangeContract(optionsInput) {
  try {
    const options = exact(optionsInput, ["maxWaitMs", "role", "runId", "transport"]);
    if (
      !ROLES.includes(options.role) || !UUID.test(options.runId) || !Number.isSafeInteger(options.maxWaitMs) ||
      options.maxWaitMs < 1 || options.maxWaitMs > MAX_WAIT_MS
    ) fail();
    const transport = exact(options.transport, ["publishOwnDescriptor", "awaitPeerDescriptor", "destroy"]);
    if (Object.values(transport).some((value) => typeof value !== "function")) fail();
    let own = null;
    let publishAttempted = false;
    let peerAwaitAttempted = false;
    let destroyed = false;
    let destroyPromise = null;
    const destroyedResult = Object.freeze({ destroyed: true });

    return Object.freeze({
      async publishOwnDescriptor(value) {
        try {
          if (destroyed || publishAttempted) fail();
          publishAttempted = true;
          const clean = validateBootstrapDescriptor(value);
          if (clean.runId !== options.runId || clean.role !== options.role) fail();
          const publication = exact(await transport.publishOwnDescriptor(clean), ["published"]);
          if (publication.published !== true) fail();
          own = clean;
          return Object.freeze({ published: true });
        } catch (error) { sanitize(error); }
      },
      async awaitPeerDescriptor() {
        let timer = null;
        try {
          if (destroyed || own === null || peerAwaitAttempted) fail();
          peerAwaitAttempted = true;
          const controller = new AbortController();
          const timeout = new Promise((resolve, reject) => {
            timer = setTimeout(() => {
              controller.abort();
              reject(new Error(ERROR));
            }, options.maxWaitMs);
          });
          const candidate = await Promise.race([
            Promise.resolve().then(() => transport.awaitPeerDescriptor({ maxWaitMs: options.maxWaitMs, signal: controller.signal })),
            timeout,
          ]);
          const peer = validateBootstrapDescriptor(candidate);
          if (
            peer.runId !== options.runId || peer.role !== opposite(options.role) ||
            peer.bootstrapPublicKey === own.bootstrapPublicKey || peer.runtime.runtimeId === own.runtime.runtimeId ||
            peer.runtime.taskId === own.runtime.taskId ||
            peer.runtime.tlsCertificateSha256 === own.runtime.tlsCertificateSha256 ||
            peer.runtime.workloadAttestationDigest === own.runtime.workloadAttestationDigest
          ) fail();
          return peer;
        } catch (error) { sanitize(error); }
        finally { if (timer !== null) clearTimeout(timer); }
      },
      async destroy() {
        if (destroyPromise !== null) return destroyPromise;
        destroyed = true;
        destroyPromise = Promise.resolve()
          .then(() => transport.destroy())
          .then(() => destroyedResult)
          .catch(sanitize);
        return destroyPromise;
      },
    });
  } catch (error) { sanitize(error); }
}
