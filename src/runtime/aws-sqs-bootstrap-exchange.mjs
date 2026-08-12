import { createHash } from "node:crypto";
import { types } from "node:util";

import {
  DeleteMessageCommand,
  ReceiveMessageCommand,
  SendMessageCommand,
  SQSClient,
} from "@aws-sdk/client-sqs";

import {
  BOOTSTRAP_DESCRIPTOR_SCHEMA,
  createBootstrapExchangeContract,
  validateBootstrapDescriptor,
} from "./bootstrap-exchange-contract.mjs";

const ERROR = "Managed bootstrap exchange failed safely.";
const REGION = /^[a-z]{2}(?:-gov)?-[a-z]+-\d$/;
const ACCOUNT = /^\d{12}$/;
const QUEUE_NAME = /^[A-Za-z0-9_-]{1,80}$/;
const DIGEST = /^[0-9a-f]{64}$/;
const MAX_BODY_BYTES = 64 * 1024;
const ATTRIBUTE_KEYS = Object.freeze(["bodySha256", "role", "runId", "schema"]);
const ROLES = Object.freeze(["initiator", "responder"]);
const INTERNAL_ERRORS = new WeakSet();

function safeError() {
  const error = new Error(ERROR);
  INTERNAL_ERRORS.add(error);
  return error;
}

function fail() { throw safeError(); }
function sanitize(error) { if (INTERNAL_ERRORS.has(error)) throw error; throw safeError(); }

function exact(value, keys) {
  try {
    if (
      value === null || typeof value !== "object" || Array.isArray(value) || types.isProxy(value) ||
      ![Object.prototype, null].includes(Object.getPrototypeOf(value))
    ) fail();
    const descriptors = Object.getOwnPropertyDescriptors(value);
    const actual = Reflect.ownKeys(descriptors);
    if (actual.length !== keys.length || actual.some((key) => typeof key !== "string" || !keys.includes(key))) fail();
    const output = {};
    for (const key of keys) {
      const descriptor = descriptors[key];
      if (descriptor?.enumerable !== true || !Object.hasOwn(descriptor, "value")) fail();
      output[key] = descriptor.value;
    }
    return output;
  } catch (error) { sanitize(error); }
}

function parseQueueUrl(raw, expectedRegion) {
  try {
    if (typeof raw !== "string" || raw.length > 2048) fail();
    const url = new URL(raw);
    const hostname = `sqs.${expectedRegion}.amazonaws.com`;
    if (
      url.protocol !== "https:" || url.hostname !== hostname || url.username !== "" || url.password !== "" ||
      url.port !== "" || url.search !== "" || url.hash !== ""
    ) fail();
    const parts = url.pathname.split("/").filter(Boolean);
    if (parts.length !== 2 || !ACCOUNT.test(parts[0]) || !QUEUE_NAME.test(parts[1])) fail();
    return Object.freeze({ account: parts[0], url: url.href.replace(/\/$/, "") });
  } catch (error) { sanitize(error); }
}

function sha256(body) { return createHash("sha256").update(body, "utf8").digest("hex"); }

function messageAttributes(role, runId, body) {
  return Object.freeze({
    schema: Object.freeze({ DataType: "String", StringValue: BOOTSTRAP_DESCRIPTOR_SCHEMA }),
    runId: Object.freeze({ DataType: "String", StringValue: runId }),
    role: Object.freeze({ DataType: "String", StringValue: role }),
    bodySha256: Object.freeze({ DataType: "String", StringValue: sha256(body) }),
  });
}

function stringAttribute(value) {
  const item = exact(value, ["DataType", "StringValue"]);
  if (item.DataType !== "String" || typeof item.StringValue !== "string") fail();
  return item.StringValue;
}

function validateMessage(message, { peerRole, runId }) {
  try {
    if (message === null || typeof message !== "object" || Array.isArray(message) || types.isProxy(message)) fail();
    if (typeof message.Body !== "string" || Buffer.byteLength(message.Body, "utf8") > MAX_BODY_BYTES) fail();
    if (typeof message.ReceiptHandle !== "string" || message.ReceiptHandle.length < 1 || message.ReceiptHandle.length > 4096) fail();
    const attributes = message.MessageAttributes;
    if (attributes === null || typeof attributes !== "object" || Array.isArray(attributes) || types.isProxy(attributes)) fail();
    const keys = Reflect.ownKeys(attributes);
    if (keys.length !== ATTRIBUTE_KEYS.length || keys.some((key) => typeof key !== "string" || !ATTRIBUTE_KEYS.includes(key))) fail();
    const schema = stringAttribute(attributes.schema);
    const attributeRunId = stringAttribute(attributes.runId);
    const role = stringAttribute(attributes.role);
    const bodyDigest = stringAttribute(attributes.bodySha256);
    if (
      schema !== BOOTSTRAP_DESCRIPTOR_SCHEMA || attributeRunId !== runId || role !== peerRole ||
      !DIGEST.test(bodyDigest) || bodyDigest !== sha256(message.Body)
    ) fail();
    let parsed;
    try { parsed = JSON.parse(message.Body); } catch { fail(); }
    const descriptor = validateBootstrapDescriptor(parsed);
    if (descriptor.runId !== runId || descriptor.role !== peerRole) fail();
    return Object.freeze({ descriptor, receiptHandle: message.ReceiptHandle });
  } catch (error) { sanitize(error); }
}

function opposite(role) { return role === "initiator" ? "responder" : "initiator"; }

export function createAwsSqsBootstrapExchange(optionsInput) {
  try {
    const options = exact(optionsInput, ["maxWaitMs", "ownQueueUrl", "peerQueueUrl", "region", "role", "runId", "sqsClient"]);
    if (!REGION.test(options.region) || !ROLES.includes(options.role)) fail();
    if (
      options.sqsClient === null || typeof options.sqsClient !== "object" ||
      typeof options.sqsClient.send !== "function" || typeof options.sqsClient.destroy !== "function"
    ) fail();
    const ownQueue = parseQueueUrl(options.ownQueueUrl, options.region);
    const peerQueue = parseQueueUrl(options.peerQueueUrl, options.region);
    if (ownQueue.account !== peerQueue.account || ownQueue.url === peerQueue.url) fail();
    const peerRole = opposite(options.role);
    let activeController = null;
    let destroyed = false;

    return createBootstrapExchangeContract({
      maxWaitMs: options.maxWaitMs,
      role: options.role,
      runId: options.runId,
      transport: {
        async publishOwnDescriptor(descriptor) {
          try {
            const body = JSON.stringify(descriptor);
            const response = await options.sqsClient.send(new SendMessageCommand({
              QueueUrl: ownQueue.url,
              MessageBody: body,
              MessageAttributes: messageAttributes(options.role, options.runId, body),
            }));
            if (typeof response?.MessageId !== "string" || response.MessageId.length < 1) fail();
            return Object.freeze({ published: true });
          } catch (error) { sanitize(error); }
        },
        async awaitPeerDescriptor({ maxWaitMs, signal }) {
          const startedAt = Date.now();
          const controller = new AbortController();
          activeController = controller;
          const abort = () => controller.abort();
          signal.addEventListener("abort", abort, { once: true });
          try {
            while (!controller.signal.aborted && Date.now() - startedAt < maxWaitMs) {
              const response = await options.sqsClient.send(new ReceiveMessageCommand({
                QueueUrl: peerQueue.url,
                MaxNumberOfMessages: 10,
                MessageAttributeNames: ["All"],
                WaitTimeSeconds: 20,
              }), { abortSignal: controller.signal });
              const messages = response?.Messages ?? [];
              if (!Array.isArray(messages)) fail();
              if (messages.length === 0) continue;
              if (messages.length !== 1) fail();
              const peer = validateMessage(messages[0], { peerRole, runId: options.runId });
              const deletion = await options.sqsClient.send(new DeleteMessageCommand({
                QueueUrl: peerQueue.url,
                ReceiptHandle: peer.receiptHandle,
              }), { abortSignal: controller.signal });
              if (deletion === null || typeof deletion !== "object") fail();
              return peer.descriptor;
            }
            fail();
          } catch (error) { sanitize(error); }
          finally {
            signal.removeEventListener("abort", abort);
            if (activeController === controller) activeController = null;
          }
        },
        async destroy() {
          try {
            if (!destroyed) {
              destroyed = true;
              activeController?.abort();
              options.sqsClient.destroy();
            }
            return Object.freeze({ destroyed: true });
          } catch (error) { sanitize(error); }
        },
      },
    });
  } catch (error) { sanitize(error); }
}

export function createTaskRoleAwsSqsBootstrapExchange(optionsInput) {
  try {
    const options = exact(optionsInput, ["ownQueueUrl", "peerQueueUrl", "region", "role", "runId"]);
    return createAwsSqsBootstrapExchange({
      ...options,
      maxWaitMs: 60_000,
      sqsClient: new SQSClient({ region: options.region }),
    });
  } catch (error) { sanitize(error); }
}
