import { types } from "node:util";

import { GetCallerIdentityCommand, STSClient } from "@aws-sdk/client-sts";

import { digestHex } from "../core/canonical.mjs";

const ERROR = "Managed ECS task bootstrap failed safely.";
const METADATA_PREFIX = "http://169.254.170.2/v4/";
const CREDENTIALS_PREFIX = "/v2/credentials/";
const MAX_METADATA_BYTES = 256 * 1024;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const DIGEST = /^[0-9a-f]{64}$/;
const ACCOUNT = /^[0-9]{12}$/;
const REGION = /^[a-z]{2}(?:-gov)?-[a-z]+-[0-9]$/;
const ROLE = /^(?:initiator|responder)$/;
const HARNESS = /^(?:codex|claude)$/;
const TASK_ID = /^[A-Za-z0-9:_-]{8,96}$/;
const IMAGE_ID = /^sha256:[0-9a-f]{64}$/;
const PRIVATE_IPV4 = /^(?:10\.(?:25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})\.(?:25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})\.(?:25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})|192\.168\.(?:25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})\.(?:25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})|172\.(?:1[6-9]|2[0-9]|3[0-1])\.(?:25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})\.(?:25[0-5]|2[0-4][0-9]|1?[0-9]{1,2}))$/;
const REJECT_ENV = Object.freeze([
  "AWS_ACCESS_KEY_ID",
  "AWS_SECRET_ACCESS_KEY",
  "AWS_SESSION_TOKEN",
  "AWS_WEB_IDENTITY_TOKEN_FILE",
  "AWS_ROLE_ARN",
  "AWS_PROFILE",
  "AWS_SHARED_CREDENTIALS_FILE",
  "AWS_CONFIG_FILE",
  "AWS_CONTAINER_CREDENTIALS_FULL_URI",
  "AWS_CONTAINER_AUTHORIZATION_TOKEN",
  "AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE",
  "AWS_ENDPOINT_URL",
  "AWS_ENDPOINT_URL_SQS",
  "CLOCKCHAIN_A2A_PUBLIC_ENDPOINT",
  "CLOCKCHAIN_RUNTIME_ID",
  "CLOCKCHAIN_TASK_ID",
  "CLOCKCHAIN_WORKLOAD_ATTESTATION_DIGEST",
]);
const OPTION_KEYS = Object.freeze(["env", "fetch", "stsClient", "timeoutMs"]);

function fail() { throw new Error(ERROR); }
function sanitize(error) { if (error?.message === ERROR) throw error; fail(); }

function ownData(value) {
  try {
    if (
      value === null || typeof value !== "object" || Array.isArray(value) || types.isProxy(value) ||
      ![Object.prototype, null].includes(Object.getPrototypeOf(value))
    ) fail();
    const descriptors = Object.getOwnPropertyDescriptors(value);
    const result = {};
    for (const key of Reflect.ownKeys(descriptors)) {
      if (typeof key !== "string") fail();
      const descriptor = descriptors[key];
      if (!descriptor.enumerable || !Object.hasOwn(descriptor, "value")) fail();
      result[key] = descriptor.value;
    }
    return result;
  } catch (error) { sanitize(error); }
}

function exactOptions(value) {
  const item = ownData(value);
  for (const key of Object.keys(item)) if (!OPTION_KEYS.includes(key)) fail();
  if (item.timeoutMs !== undefined && (!Number.isInteger(item.timeoutMs) || item.timeoutMs < 1 || item.timeoutMs > 10_000)) fail();
  if (item.fetch !== undefined && typeof item.fetch !== "function") fail();
  return item;
}

function string(value, pattern = null) {
  if (typeof value !== "string" || value.length === 0 || value.length > 4096 || (pattern && !pattern.test(value))) fail();
  return value;
}

function optional(env, key) {
  const value = env[key];
  return typeof value === "string" && value.length > 0 ? value : null;
}

function requireNoOverrides(env) {
  for (const key of REJECT_ENV) if (optional(env, key) !== null) fail();
}

function validateMetadataUri(value) {
  const raw = string(value);
  if (!raw.startsWith(METADATA_PREFIX) || raw.includes("?") || raw.includes("#")) fail();
  const suffix = raw.slice(METADATA_PREFIX.length);
  if (!/^[A-Za-z0-9._~/-]{8,256}$/.test(suffix) || suffix.split("/").some((part) => part === "." || part === ".." || part.length === 0)) fail();
  return `${raw}/task`;
}

function validateCredentialsRelativeUri(value) {
  const raw = string(value);
  if (!raw.startsWith(CREDENTIALS_PREFIX) || raw.includes("?") || raw.includes("#")) fail();
  const suffix = raw.slice(CREDENTIALS_PREFIX.length);
  if (!/^[A-Za-z0-9._~-]{8,256}$/.test(suffix)) fail();
  return raw;
}

async function readMetadataJson({ fetchImpl, metadataUrl, timeoutMs }) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const abortPromise = new Promise((resolve, reject) => {
      controller.signal.addEventListener("abort", () => reject(new Error(ERROR)), { once: true });
    });
    const responseRaw = await Promise.race([fetchImpl(metadataUrl, { signal: controller.signal }), abortPromise]);
    if (responseRaw === null || typeof responseRaw !== "object" || types.isProxy(responseRaw)) fail();
    const nativeResponse = typeof Response === "function" && responseRaw instanceof Response;
    const response = nativeResponse ? responseRaw : ownData(responseRaw);
    if (response.ok !== true) fail();
    const headersRaw = response.headers;
    let length = null;
    if (headersRaw !== undefined && headersRaw !== null) {
      if (types.isProxy(headersRaw)) fail();
      if (typeof Headers === "function" && headersRaw instanceof Headers) length = headersRaw.get("content-length");
      else {
        const headers = ownData(headersRaw);
        if (typeof headers.get !== "function") fail();
        length = headers.get("content-length");
      }
    }
    if (typeof length === "string" && Number(length) > MAX_METADATA_BYTES) fail();
    let body = "";
    if (response.body && typeof response.body.getReader === "function") {
      const reader = response.body.getReader();
      for (;;) {
        const chunk = await reader.read();
        if (chunk.done) break;
        body += Buffer.from(chunk.value).toString("utf8");
        if (Buffer.byteLength(body, "utf8") > MAX_METADATA_BYTES) fail();
      }
    } else if (typeof response.text === "function") {
      body = await response.text();
      if (Buffer.byteLength(body, "utf8") > MAX_METADATA_BYTES) fail();
    } else fail();
    return JSON.parse(body);
  } catch (error) { sanitize(error); }
  finally { clearTimeout(timer); }
}

function parseTaskArn(raw) {
  const arn = string(raw);
  const match = /^arn:aws:ecs:([a-z]{2}(?:-gov)?-[a-z]+-[0-9]):([0-9]{12}):task\/([A-Za-z0-9_-]+)\/([A-Za-z0-9:_-]+)$/.exec(arn);
  if (!match) fail();
  return Object.freeze({ arn, region: match[1], accountId: match[2], cluster: match[3], taskId: match[4] });
}

function parseContainerArn(raw, task) {
  const arn = string(raw);
  const match = /^arn:aws:ecs:([a-z]{2}(?:-gov)?-[a-z]+-[0-9]):([0-9]{12}):container\/([A-Za-z0-9_-]+)\/([A-Za-z0-9:_-]+)\/([A-Za-z0-9:_-]+)$/.exec(arn);
  if (!match || match[1] !== task.region || match[2] !== task.accountId || match[3] !== task.cluster || match[4] !== task.taskId) fail();
  return arn;
}

function selectedContainer(metadata, role, task) {
  if (!Array.isArray(metadata.Containers)) fail();
  const matches = metadata.Containers.map(ownData).filter((container) => container.Name === role);
  if (matches.length !== 1) fail();
  const container = matches[0];
  if (container.Type !== "NORMAL" || container.KnownStatus !== "RUNNING" || !IMAGE_ID.test(string(container.ImageID))) fail();
  const containerArn = parseContainerArn(container.ContainerARN, task);
  if (!Array.isArray(container.Networks) || container.Networks.length !== 1) fail();
  const network = ownData(container.Networks[0]);
  if (network.NetworkMode !== "awsvpc" || !Array.isArray(network.IPv4Addresses) || network.IPv4Addresses.length !== 1) fail();
  const privateIp = string(network.IPv4Addresses[0], PRIVATE_IPV4);
  return Object.freeze({ containerArn, imageId: container.ImageID, privateIp });
}

function canonicalMetadata(metadataInput, env) {
  const metadata = ownData(metadataInput);
  if (metadata.LaunchType !== "FARGATE" || metadata.KnownStatus !== "RUNNING") fail();
  const task = parseTaskArn(metadata.TaskARN);
  const region = string(env.AWS_REGION, REGION);
  if (task.region !== region) fail();
  const role = string(env.CLOCKCHAIN_ROLE, ROLE);
  const container = selectedContainer(metadata, role, task);
  return Object.freeze({
    accountId: task.accountId,
    availabilityZone: string(metadata.AvailabilityZone),
    containerArn: container.containerArn,
    family: string(metadata.Family),
    imageId: container.imageId,
    launchType: "FARGATE",
    privateIp: container.privateIp,
    region,
    revision: String(metadata.Revision),
    role,
    taskArn: task.arn,
    taskId: string(task.taskId, TASK_ID),
  });
}

async function callerIdentity({ accountId, region, stsClient }) {
  try {
    const client = stsClient ?? new STSClient({ region });
    const identity = await client.send(new GetCallerIdentityCommand({}));
    const item = ownData(identity);
    if (string(item.Account, ACCOUNT) !== accountId) fail();
    const arn = string(item.Arn);
    if (!new RegExp(`^arn:aws:sts::${accountId}:assumed-role\\/[^/]+\\/[A-Za-z0-9+=,.@:_/-]+$`).test(arn)) fail();
    return Object.freeze({ accountId: item.Account, arn, userId: string(item.UserId) });
  } catch (error) { sanitize(error); }
}

function runOptionsFrom(env, derived) {
  let mandate;
  try { mandate = JSON.parse(string(env.CLOCKCHAIN_MANDATE_JSON)); } catch { fail(); }
  const port = Number(string(env.CLOCKCHAIN_A2A_PORT));
  const runId = string(env.CLOCKCHAIN_RUN_ID, UUID);
  if (port !== 8443) fail();
  return Object.freeze({
    harness: string(env.CLOCKCHAIN_CLIENT, HARNESS),
    listenHost: string(env.CLOCKCHAIN_A2A_LISTEN_HOST),
    manifestDigest: string(env.CLOCKCHAIN_HELPER_MANIFEST_DIGEST, DIGEST),
    mandate,
    mcpEndpoint: string(env.CLOCKCHAIN_MCP_URL),
    opensslPath: string(env.CLOCKCHAIN_OPENSSL_PATH),
    port,
    publicEndpoint: `https://${derived.privateIp}:8443`,
    role: derived.role,
    root: string(env.CLOCKCHAIN_PARTY_ROOT),
    runId,
    runtimeId: `ecs-${derived.taskId}`,
    taskId: derived.taskId,
    workloadAttestationDigest: derived.workloadAttestationDigest,
  });
}

export async function resolveAwsEcsTaskBootstrap(optionsInput = {}) {
  try {
    const options = exactOptions(optionsInput);
    const env = options.env ?? process.env;
    if (env === null || typeof env !== "object" || Array.isArray(env) || types.isProxy(env)) fail();
    requireNoOverrides(env);
    const metadataUrl = validateMetadataUri(env.ECS_CONTAINER_METADATA_URI_V4);
    validateCredentialsRelativeUri(env.AWS_CONTAINER_CREDENTIALS_RELATIVE_URI);
    const fetchImpl = options.fetch ?? globalThis.fetch;
    if (typeof fetchImpl !== "function") fail();
    const metadata = canonicalMetadata(await readMetadataJson({
      fetchImpl,
      metadataUrl,
      timeoutMs: options.timeoutMs ?? 3_000,
    }), env);
    const identity = await callerIdentity({ accountId: metadata.accountId, region: metadata.region, stsClient: options.stsClient });
    const attestationCore = Object.freeze({
      schema: "clockchain.mechanics-proof-ecs-attestation-core/v1",
      accountId: metadata.accountId,
      availabilityZone: metadata.availabilityZone,
      containerArn: metadata.containerArn,
      family: metadata.family,
      imageId: metadata.imageId,
      launchType: metadata.launchType,
      privateIp: metadata.privateIp,
      region: metadata.region,
      revision: metadata.revision,
      role: metadata.role,
      stsArn: identity.arn,
      stsUserId: identity.userId,
      taskArn: metadata.taskArn,
      taskId: metadata.taskId,
    });
    const workloadAttestationDigest = digestHex(attestationCore);
    const derived = Object.freeze({ ...metadata, workloadAttestationDigest });
    const attestation = Object.freeze({
      workloadAttestationDigest,
      ...attestationCore,
      schema: "clockchain.mechanics-proof-ecs-attestation/v1",
    });
    return Object.freeze({ attestation, runOptions: runOptionsFrom(env, derived) });
  } catch (error) { sanitize(error); }
}
