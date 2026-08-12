import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { PassThrough, Readable } from "node:stream";
import test from "node:test";

import { createBootstrapExchangeContract } from "../src/runtime/bootstrap-exchange-contract.mjs";
import { createStdinBootstrapExchange } from "../src/runtime/stdin-bootstrap-exchange.mjs";

const RUN_ID = "11111111-2222-4333-8444-555555555555";
const OTHER_RUN_ID = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";
const DIGEST = "a".repeat(64);
const OTHER_DIGEST = "b".repeat(64);
const CERTIFICATE = "-----BEGIN CERTIFICATE-----\npublic-test-certificate\n-----END CERTIFICATE-----\n";

function publicKey() {
  return generateKeyPairSync("ed25519").publicKey.export({ type: "spki", format: "pem" });
}

function descriptor(role, overrides = {}) {
  return {
    schema: "clockchain.mechanics-proof-party-bootstrap/v1",
    bootstrapPublicKey: publicKey(),
    harness: role === "initiator" ? "codex" : "claude",
    role,
    runId: RUN_ID,
    runtime: {
      endpoint: `https://${role}.task.local:8443`,
      runtimeId: `runtime-${role}`,
      taskId: `task-${role}`,
      tlsCertificateSha256: role === "initiator" ? DIGEST : OTHER_DIGEST,
      workloadAttestationDigest: role === "initiator" ? DIGEST : OTHER_DIGEST,
    },
    tlsCertificate: CERTIFICATE,
    ...overrides,
  };
}

function exchange(overrides = {}) {
  const { transport: transportOverrides = {}, ...contractOverrides } = overrides;
  const calls = [];
  const peer = descriptor("responder");
  const transport = {
    async publishOwnDescriptor(value) { calls.push(["publish", value]); return { published: true }; },
    async awaitPeerDescriptor({ maxWaitMs, signal }) { calls.push(["await", maxWaitMs, signal]); return peer; },
    async destroy() { calls.push(["destroy"]); return { destroyed: true, controllerSecret: "must-not-escape" }; },
    ...transportOverrides,
  };
  return {
    calls,
    peer,
    value: createBootstrapExchangeContract({
      maxWaitMs: 100,
      role: "initiator",
      runId: RUN_ID,
      transport,
      ...contractOverrides,
    }),
  };
}

test("bootstrap exchange publishes one frozen own descriptor and returns one frozen opposite-role descriptor", async () => {
  const own = descriptor("initiator");
  const { calls, peer, value } = exchange();
  assert.deepEqual(await value.publishOwnDescriptor(own), { published: true });
  const received = await value.awaitPeerDescriptor();
  assert.deepEqual(received, peer);
  assert.equal(Object.isFrozen(calls[0][1]), true);
  assert.equal(Object.isFrozen(calls[0][1].runtime), true);
  assert.equal(Object.isFrozen(received), true);
  assert.equal(Object.isFrozen(received.runtime), true);
  assert.equal(calls[1][1], 100);
  assert.equal(calls[1][2] instanceof AbortSignal, true);
});

test("bootstrap exchange rejects replay, same-role, different-run, and self descriptors", async () => {
  const own = descriptor("initiator");
  const cases = [
    descriptor("initiator"),
    descriptor("responder", { runId: OTHER_RUN_ID }),
    descriptor("responder", { bootstrapPublicKey: own.bootstrapPublicKey }),
    descriptor("responder", { runtime: { ...descriptor("responder").runtime, runtimeId: own.runtime.runtimeId } }),
    descriptor("responder", { runtime: { ...descriptor("responder").runtime, taskId: own.runtime.taskId } }),
    descriptor("responder", { runtime: { ...descriptor("responder").runtime, tlsCertificateSha256: own.runtime.tlsCertificateSha256 } }),
    descriptor("responder", { runtime: { ...descriptor("responder").runtime, workloadAttestationDigest: own.runtime.workloadAttestationDigest } }),
  ];
  for (const peer of cases) {
    const { value } = exchange({ transport: { async awaitPeerDescriptor() { return peer; } } });
    await value.publishOwnDescriptor(own);
    await assert.rejects(() => value.awaitPeerDescriptor(), /Bootstrap exchange contract validation failed safely/);
  }
  const { value } = exchange();
  await value.publishOwnDescriptor(own);
  await assert.rejects(() => value.publishOwnDescriptor(own), /Bootstrap exchange contract validation failed safely/);
  await value.awaitPeerDescriptor();
  await assert.rejects(() => value.awaitPeerDescriptor(), /Bootstrap exchange contract validation failed safely/);
});

test("bootstrap exchange rejects accessor, proxy, oversized, private-field, and ambiguous publication input", async () => {
  const own = descriptor("initiator");
  for (const candidate of [
    new Proxy(own, {}),
    Object.defineProperty({ ...own }, "runId", { enumerable: true, get() { return RUN_ID; } }),
    { ...own, controllerPrivateKey: "forbidden" },
    { ...own, tlsCertificate: `-----BEGIN CERTIFICATE-----\n${"x".repeat(70 * 1024)}\n-----END CERTIFICATE-----\n` },
    { ...own, runtime: new Proxy(own.runtime, {}) },
  ]) {
    const { value } = exchange();
    await assert.rejects(() => value.publishOwnDescriptor(candidate), /Bootstrap exchange contract validation failed safely/);
  }
  const { value } = exchange({ transport: { async publishOwnDescriptor() { return { published: false }; } } });
  await assert.rejects(() => value.publishOwnDescriptor(own), /Bootstrap exchange contract validation failed safely/);
  await assert.rejects(() => value.publishOwnDescriptor(own), /Bootstrap exchange contract validation failed safely/);
});

test("bootstrap exchange bounds peer wait and cleanup is idempotent and secret-free", async () => {
  let destroyCalls = 0;
  const { value } = exchange({
    maxWaitMs: 5,
    transport: {
      async awaitPeerDescriptor() {
        await new Promise((resolve) => setTimeout(resolve, 20));
        return descriptor("responder");
      },
      async destroy() { destroyCalls += 1; return { secret: "transport-secret" }; },
    },
  });
  await value.publishOwnDescriptor(descriptor("initiator"));
  await assert.rejects(() => value.awaitPeerDescriptor(), (error) => {
    assert.equal(error.message, "Bootstrap exchange contract validation failed safely.");
    assert.doesNotMatch(error.message, /transport|secret|timeout/i);
    return true;
  });
  const first = await value.destroy();
  const second = await value.destroy();
  assert.deepEqual(first, { destroyed: true });
  assert.equal(second, first);
  assert.equal(Object.isFrozen(first), true);
  assert.equal(destroyCalls, 1);
  assert.doesNotMatch(JSON.stringify(first), /transport-secret/);
});

test("bootstrap exchange requires exact safe construction and publish-before-await", async () => {
  for (const candidate of [
    {},
    { maxWaitMs: 0, role: "initiator", runId: RUN_ID, transport: {} },
    { maxWaitMs: 100, role: "payer", runId: RUN_ID, transport: {} },
    { maxWaitMs: 100, role: "initiator", runId: "bad", transport: {} },
    { maxWaitMs: 100, role: "initiator", runId: RUN_ID, transport: new Proxy({}, {}) },
    { maxWaitMs: 100, role: "initiator", runId: RUN_ID, transport: { publishOwnDescriptor() {}, awaitPeerDescriptor() {} } },
  ]) {
    assert.throws(() => createBootstrapExchangeContract(candidate), /Bootstrap exchange contract validation failed safely/);
  }
  const { value } = exchange();
  await assert.rejects(() => value.awaitPeerDescriptor(), /Bootstrap exchange contract validation failed safely/);
  await value.destroy();
  await assert.rejects(() => value.publishOwnDescriptor(descriptor("initiator")), /Bootstrap exchange contract validation failed safely/);
});

test("stdin bootstrap exchange preserves the exact one-line local controller protocol", async () => {
  const own = descriptor("initiator");
  const peer = descriptor("responder");
  const stdout = new PassThrough();
  let output = "";
  stdout.on("data", (chunk) => { output += chunk.toString("utf8"); });
  const value = createStdinBootstrapExchange({
    maxWaitMs: 100,
    role: "initiator",
    runId: RUN_ID,
    stdin: Readable.from([`${JSON.stringify(peer)}\n`]),
    stdout,
  });
  await value.publishOwnDescriptor(own);
  assert.deepEqual(await value.awaitPeerDescriptor(), peer);
  assert.equal(output, `${JSON.stringify(own)}\n`);
  assert.deepEqual(await value.destroy(), { destroyed: true });
});

test("stdin bootstrap exchange rejects more than one peer descriptor", async () => {
  const own = descriptor("initiator");
  const peerLine = `${JSON.stringify(descriptor("responder"))}\n`;
  const value = createStdinBootstrapExchange({
    maxWaitMs: 100,
    role: "initiator",
    runId: RUN_ID,
    stdin: Readable.from([peerLine, peerLine]),
    stdout: new PassThrough(),
  });
  await value.publishOwnDescriptor(own);
  await assert.rejects(() => value.awaitPeerDescriptor(), /Bootstrap exchange contract validation failed safely/);
});
