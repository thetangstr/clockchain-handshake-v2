import assert from "node:assert/strict";
import { createHash, generateKeyPairSync } from "node:crypto";
import test from "node:test";

import { createAwsSqsBootstrapExchange } from "../src/runtime/aws-sqs-bootstrap-exchange.mjs";

const RUN_ID = "11111111-2222-4333-8444-555555555555";
const REGION = "us-west-2";
const ACCOUNT = "123456789012";
const INITIATOR_QUEUE = `https://sqs.${REGION}.amazonaws.com/${ACCOUNT}/proof-${RUN_ID}-initiator`;
const RESPONDER_QUEUE = `https://sqs.${REGION}.amazonaws.com/${ACCOUNT}/proof-${RUN_ID}-responder`;
const SAFE_ERROR = "Managed bootstrap exchange failed safely.";
const CONTRACT_ERROR = "Bootstrap exchange contract validation failed safely.";

function publicKey() {
  return generateKeyPairSync("ed25519").publicKey.export({ type: "spki", format: "pem" });
}

function descriptor(role, suffix) {
  return {
    schema: "clockchain.mechanics-proof-party-bootstrap/v1",
    bootstrapPublicKey: publicKey(),
    harness: role === "initiator" ? "codex" : "claude",
    role,
    runId: RUN_ID,
    runtime: {
      endpoint: `https://10.0.0.${role === "initiator" ? "10" : "11"}:8443`,
      runtimeId: `runtime-${suffix}`,
      taskId: `task-${suffix}`,
      tlsCertificateSha256: role === "initiator" ? "a".repeat(64) : "b".repeat(64),
      workloadAttestationDigest: role === "initiator" ? "c".repeat(64) : "d".repeat(64),
    },
    tlsCertificate: "-----BEGIN CERTIFICATE-----\nZmFrZQ==\n-----END CERTIFICATE-----\n",
  };
}

function attributes(role, body, overrides = {}) {
  return {
    schema: { DataType: "String", StringValue: "clockchain.mechanics-proof-party-bootstrap/v1" },
    runId: { DataType: "String", StringValue: RUN_ID },
    role: { DataType: "String", StringValue: role },
    bodySha256: { DataType: "String", StringValue: createHash("sha256").update(body, "utf8").digest("hex") },
    ...overrides,
  };
}

class FakeSqsClient {
  constructor(responses = []) {
    this.responses = [...responses];
    this.calls = [];
    this.destroyed = false;
  }

  async send(command, options) {
    this.calls.push({ name: command.constructor.name, input: command.input, options });
    const response = this.responses.shift();
    if (response instanceof Error) throw response;
    return response ?? {};
  }

  destroy() { this.destroyed = true; }
}

function exchange(client, overrides = {}) {
  return createAwsSqsBootstrapExchange({
    maxWaitMs: 5_000,
    ownQueueUrl: INITIATOR_QUEUE,
    peerQueueUrl: RESPONDER_QUEUE,
    region: REGION,
    role: "initiator",
    runId: RUN_ID,
    sqsClient: client,
    ...overrides,
  });
}

test("SQS exchange publishes once to own queue and long-polls only the peer queue", async () => {
  const own = descriptor("initiator", "initiator");
  const peer = descriptor("responder", "responder");
  const peerBody = JSON.stringify(peer);
  const client = new FakeSqsClient([
    { MessageId: "own-message" },
    {
      Messages: [{
        Body: peerBody,
        MessageAttributes: attributes("responder", peerBody),
        ReceiptHandle: "peer-receipt",
      }],
    },
    {},
  ]);
  const rendezvous = exchange(client);

  assert.deepEqual(await rendezvous.publishOwnDescriptor(own), { published: true });
  assert.deepEqual(await rendezvous.awaitPeerDescriptor(), peer);
  assert.deepEqual(await rendezvous.destroy(), { destroyed: true });
  assert.deepEqual(client.calls.map(({ name }) => name), ["SendMessageCommand", "ReceiveMessageCommand", "DeleteMessageCommand"]);
  assert.equal(client.calls[0].input.QueueUrl, INITIATOR_QUEUE);
  assert.equal(client.calls[1].input.QueueUrl, RESPONDER_QUEUE);
  assert.equal(client.calls[2].input.QueueUrl, RESPONDER_QUEUE);
  assert.equal(client.calls[2].input.ReceiptHandle, "peer-receipt");
  assert.equal(client.calls[1].input.WaitTimeSeconds, 20);
  assert.equal(client.calls[1].input.MaxNumberOfMessages, 10);
  assert.deepEqual(client.calls[1].input.MessageAttributeNames, ["All"]);
  assert.deepEqual(client.calls[0].input.MessageAttributes, attributes("initiator", client.calls[0].input.MessageBody));
  assert.equal(client.destroyed, true);
});

test("SQS exchange continues exact long polls after an empty peer response", async () => {
  const own = descriptor("initiator", "initiator");
  const peer = descriptor("responder", "responder");
  const peerBody = JSON.stringify(peer);
  const client = new FakeSqsClient([
    { MessageId: "own-message" },
    { Messages: [] },
    { Messages: [{ Body: peerBody, MessageAttributes: attributes("responder", peerBody), ReceiptHandle: "peer-receipt" }] },
    {},
  ]);
  const rendezvous = exchange(client);
  await rendezvous.publishOwnDescriptor(own);
  assert.deepEqual(await rendezvous.awaitPeerDescriptor(), peer);
  const receives = client.calls.filter(({ name }) => name === "ReceiveMessageCommand");
  assert.equal(receives.length, 2);
  assert.ok(receives.every(({ input }) => input.QueueUrl === RESPONDER_QUEUE && input.WaitTimeSeconds === 20));
  assert.ok(receives.every(({ options }) => options.abortSignal instanceof AbortSignal));
  await rendezvous.destroy();
});

test("SQS exchange rejects queue pairs outside one exact account and region", () => {
  const client = new FakeSqsClient();
  for (const overrides of [
    { peerQueueUrl: `https://sqs.us-east-1.amazonaws.com/${ACCOUNT}/peer` },
    { peerQueueUrl: `https://sqs.${REGION}.amazonaws.com/999999999999/peer` },
    { ownQueueUrl: `http://sqs.${REGION}.amazonaws.com/${ACCOUNT}/own` },
    { ownQueueUrl: `https://example.com/${ACCOUNT}/own` },
    { ownQueueUrl: RESPONDER_QUEUE, peerQueueUrl: RESPONDER_QUEUE },
  ]) assert.throws(() => exchange(client, overrides), (error) => error.message === SAFE_ERROR);
});

test("SQS exchange deletes only an exact validated peer message", async () => {
  const own = descriptor("initiator", "initiator");
  const validPeer = descriptor("responder", "responder");
  const validBody = JSON.stringify(validPeer);
  const invalidCases = [
    { Body: validBody, MessageAttributes: attributes("responder", validBody, { runId: { DataType: "String", StringValue: "22222222-2222-4222-8222-222222222222" } }), ReceiptHandle: "r" },
    { Body: validBody, MessageAttributes: attributes("initiator", validBody), ReceiptHandle: "r" },
    { Body: validBody, MessageAttributes: attributes("responder", validBody, { bodySha256: { DataType: "String", StringValue: "0".repeat(64) } }), ReceiptHandle: "r" },
    { Body: "{", MessageAttributes: attributes("responder", "{"), ReceiptHandle: "r" },
    { Body: "x".repeat(65 * 1024), MessageAttributes: attributes("responder", "x".repeat(65 * 1024)), ReceiptHandle: "r" },
    { Body: JSON.stringify({ ...validPeer, runId: "22222222-2222-4222-8222-222222222222" }), MessageAttributes: attributes("responder", JSON.stringify({ ...validPeer, runId: "22222222-2222-4222-8222-222222222222" })), ReceiptHandle: "r" },
    { Body: JSON.stringify({ ...validPeer, role: "initiator" }), MessageAttributes: attributes("responder", JSON.stringify({ ...validPeer, role: "initiator" })), ReceiptHandle: "r" },
    { Body: validBody, MessageAttributes: { ...attributes("responder", validBody), extra: { DataType: "String", StringValue: "no" } }, ReceiptHandle: "r" },
    { Body: validBody, MessageAttributes: attributes("responder", validBody), ReceiptHandle: "" },
  ];

  for (const message of invalidCases) {
    const client = new FakeSqsClient([{ MessageId: "own" }, { Messages: [message] }]);
    const rendezvous = exchange(client);
    await rendezvous.publishOwnDescriptor(own);
    await assert.rejects(() => rendezvous.awaitPeerDescriptor(), (error) => error.message === CONTRACT_ERROR);
    assert.equal(client.calls.some(({ name }) => name === "DeleteMessageCommand"), false);
    await rendezvous.destroy();
  }

  const duplicateClient = new FakeSqsClient([{ MessageId: "own" }, { Messages: [
    { Body: validBody, MessageAttributes: attributes("responder", validBody), ReceiptHandle: "r1" },
    { Body: validBody, MessageAttributes: attributes("responder", validBody), ReceiptHandle: "r2" },
  ] }]);
  const duplicateExchange = exchange(duplicateClient);
  await duplicateExchange.publishOwnDescriptor(own);
  await assert.rejects(() => duplicateExchange.awaitPeerDescriptor(), (error) => error.message === CONTRACT_ERROR);
  assert.equal(duplicateClient.calls.some(({ name }) => name === "DeleteMessageCommand"), false);
  await duplicateExchange.destroy();
});

test("SQS exchange fails generically on timeout, abort, and transport errors", async () => {
  const own = descriptor("initiator", "initiator");
  for (const responses of [
    [{ MessageId: "own" }, new Error(`access denied for ${RESPONDER_QUEUE}`)],
    [{ MessageId: "own" }, { Messages: [] }],
  ]) {
    const client = new FakeSqsClient(responses);
    const rendezvous = exchange(client, { maxWaitMs: 5 });
    await rendezvous.publishOwnDescriptor(own);
    await assert.rejects(
      () => rendezvous.awaitPeerDescriptor(),
      (error) => error.message === CONTRACT_ERROR && !error.message.includes(RESPONDER_QUEUE),
    );
    await rendezvous.destroy();
  }

  let rejectReceive;
  const blockingClient = new FakeSqsClient([{ MessageId: "own" }]);
  blockingClient.send = async function send(command, options) {
    this.calls.push({ name: command.constructor.name, input: command.input, options });
    if (command.constructor.name === "SendMessageCommand") return { MessageId: "own" };
    if (command.constructor.name === "ReceiveMessageCommand") {
      return new Promise((resolve, reject) => {
        rejectReceive = reject;
        options.abortSignal.addEventListener("abort", () => reject(new Error(`aborted ${RESPONDER_QUEUE}`)), { once: true });
      });
    }
    return {};
  };
  const blocking = exchange(blockingClient);
  await blocking.publishOwnDescriptor(own);
  const pending = blocking.awaitPeerDescriptor();
  await new Promise((resolve) => setImmediate(resolve));
  await blocking.destroy();
  await assert.rejects(pending, (error) => !error.message.includes(RESPONDER_QUEUE));
  assert.equal(typeof rejectReceive, "function");
});

test("SQS exchange rejects duplicate publish and ambiguous send acknowledgement", async () => {
  const own = descriptor("initiator", "initiator");
  const ambiguous = exchange(new FakeSqsClient([{}]));
  await assert.rejects(() => ambiguous.publishOwnDescriptor(own), (error) => error.message === CONTRACT_ERROR);
  await ambiguous.destroy();

  const client = new FakeSqsClient([{ MessageId: "own" }]);
  const rendezvous = exchange(client);
  await rendezvous.publishOwnDescriptor(own);
  await assert.rejects(() => rendezvous.publishOwnDescriptor(own), /Bootstrap exchange contract validation failed safely/);
  assert.equal(client.calls.filter(({ name }) => name === "SendMessageCommand").length, 1);
  await rendezvous.destroy();
});
