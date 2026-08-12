import { createPublicKey, generateKeyPairSync, sign } from "node:crypto";
import { chmod, lstat, mkdir, rm, writeFile } from "node:fs/promises";
import { dirname, isAbsolute, join, resolve } from "node:path";
import { types } from "node:util";

import { createA2ACardBootstrap } from "../a2a/card-bootstrap.mjs";
import { createHttpTaskTransport } from "../a2a/http-task-transport.mjs";
import {
  createInvitationBootstrapTransport,
  invitationBootstrapFailureStage,
} from "../a2a/invitation-bootstrap-transport.mjs";
import { createPartyA2AAuthority } from "../harness/party-a2a-authority.mjs";
import { activatePartySignedChannel, defaultPartySignedChannelSleep } from "../harness/party-signed-channel-bootstrap.mjs";
import { createAgentHandshakeCheckpointClient } from "../harness/agent-handshake-mcp-client.mjs";
import { createAcpClaudeHarnessAdapter } from "../harness/acp-claude-adapter.mjs";
import { createAcpCodexHarnessAdapter } from "../harness/acp-codex-adapter.mjs";
import { acpProcessTransportFailureStage, createAcpProcessTransport } from "../harness/acp-process-transport.mjs";
import { createDirectA2APartyBridge } from "../harness/direct-a2a-party-bridge.mjs";
import {
  createVerifiedReleaseActionRecorder,
  verifiedReleaseActionRecorderFailureStage,
} from "../harness/verified-release-action-recorder.mjs";
import { ACP_VERSION_PINS } from "../harness/version-pins.mjs";
import { digestHex } from "../core/canonical.mjs";
import { installAppleClientAuthentication, loadAppleClientAuthentication } from "./apple-client-auth.mjs";
import { createEphemeralTlsIdentity } from "./ephemeral-tls-identity.mjs";

const ERROR = "Mechanics proof party runtime failed safely.";
const MCP_ENDPOINT = "https://mcp.clockchain.network/handshake/mcp";
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const DIGEST = /^[0-9a-f]{64}$/;
const TOKEN = /^[A-Za-z0-9._:-]{1,128}$/;
const ROLES = Object.freeze(["initiator", "responder"]);
const HARNESSES = Object.freeze(["codex", "claude"]);
const OPTION_KEYS = Object.freeze([
  "harness", "listenHost", "manifestDigest", "mandate", "mcpEndpoint", "opensslPath", "port",
  "publicEndpoint", "role", "root", "runId", "runtimeId", "taskId", "workloadAttestationDigest",
]);
const DEPENDENCY_KEYS = Object.freeze([
  "createActionRecorder", "createBootstrapSigner", "createBridge", "createCheckpointClient",
  "createHarnessAdapter", "createInvitationTransport", "createProcessTransport", "createTlsIdentity",
  "waitForInvitation",
]);
const CODEX_PROVIDER_ENV = Object.freeze(["CODEX_API_KEY", "OPENAI_API_KEY", "CLOCKCHAIN_CODEX_MODEL"]);
const CODEX_AUTH_JSON_BASE64 = "CLOCKCHAIN_CODEX_AUTH_JSON_BASE64";
const CLAUDE_BEDROCK_PROVIDER_ENV = Object.freeze([
  "CLAUDE_CODE_USE_BEDROCK", "ANTHROPIC_MODEL", "AWS_REGION", "AWS_DEFAULT_REGION",
  "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
]);
const AWS_CREDENTIAL_OVERRIDE_ENV = Object.freeze([
  "AWS_CONTAINER_CREDENTIALS_FULL_URI", "AWS_CONTAINER_AUTHORIZATION_TOKEN", "AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE",
  "AWS_WEB_IDENTITY_TOKEN_FILE", "AWS_ROLE_ARN", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN",
  "AWS_PROFILE", "AWS_SHARED_CREDENTIALS_FILE", "AWS_CONFIG_FILE", "AWS_ENDPOINT_URL", "AWS_ENDPOINT_URL_SQS",
]);
const RUNTIME_FAILURE_STAGES = Object.freeze([
  "peer-validate", "listener-create", "listener-ready", "invitation-await", "recorder-create",
  "recorder-construction-options", "recorder-construction-room", "recorder-construction-paths",
  "recorder-construction-platform",
  "recorder-release-manifest-fetch", "recorder-release-helper-fetch", "recorder-release-assets",
  "recorder-adapter-layout", "recorder-completion-socket",
  "checkpoint-client-create",
  "bridge-create", "provider-auth", "provider-auth-input", "provider-auth-decode", "provider-auth-parse",
  "provider-auth-install", "provider-auth-export", "transport-create", "adapter-create", "agent-starting",
  "agent-launch", "agent-launch-spawn", "agent-launch-stream", "agent-launch-initialize", "agent-launch-session",
  "agent-launch-model", "agent-launch-prompt", "agent-launch-completion", "agent-launch-completion-protocol",
  "agent-launch-completion-protocol-envelope", "agent-launch-completion-protocol-usage",
  "agent-launch-completion-protocol-tool-result", "agent-launch-completion-protocol-bridge",
  "agent-launch-completion-protocol-retained", "agent-launch-completion-protocol-event",
  "agent-launch-completion-protocol-envelope-runtime", "agent-launch-completion-protocol-envelope-session-id",
  "agent-launch-completion-protocol-envelope-update-type", "agent-launch-completion-protocol-envelope-before-session",
  "agent-launch-completion-protocol-envelope-early-tool", "agent-launch-completion-protocol-envelope-provisional-session",
  "agent-launch-completion-protocol-envelope-active-session",
  "agent-launch-completion-protocol-bridge-input", "agent-launch-completion-protocol-bridge-tool-name",
  "agent-launch-completion-protocol-bridge-clone", "agent-launch-completion-protocol-bridge-role-access",
  "agent-launch-completion-protocol-bridge-session", "agent-launch-completion-protocol-bridge-invite-shape",
  "agent-launch-completion-protocol-bridge-invite-send", "agent-launch-completion-protocol-bridge-accept",
  "agent-launch-completion-protocol-bridge-join", "agent-launch-completion-protocol-bridge-helper",
  "agent-launch-completion-protocol-bridge-digest",
  "agent-launch-completion-permission", "agent-launch-completion-stop", "evidence-validate", "certificate-event",
  "agent-terminate", "evidence-collect", "teardown",
  "listener-listen-eacces", "listener-listen-eaddrinuse", "listener-listen-eaddrnotavail",
  "listener-listen-eperm", "listener-listen-other",
]);
const RUNTIME_FAILURES = new WeakMap();

function fail() { throw new Error(ERROR); }
function sanitize(error) { if (error?.message === ERROR) throw error; fail(); }

function stagedFailure(stage) {
  if (!RUNTIME_FAILURE_STAGES.includes(stage)) fail();
  const error = new Error(ERROR);
  RUNTIME_FAILURES.set(error, stage);
  return error;
}

export function mechanicsProofPartyRuntimeFailureStage(error) {
  return RUNTIME_FAILURES.get(error) ?? null;
}

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

function optionalExact(value, required, optional = []) {
  try {
    if (
      value === null || typeof value !== "object" || Array.isArray(value) || types.isProxy(value) ||
      ![Object.prototype, null].includes(Object.getPrototypeOf(value))
    ) fail();
    const descriptors = Object.getOwnPropertyDescriptors(value);
    const keys = Reflect.ownKeys(descriptors);
    const allowed = [...required, ...optional];
    if (keys.some((key) => typeof key !== "string" || !allowed.includes(key))) fail();
    for (const key of required) if (!Object.hasOwn(descriptors, key)) fail();
    const result = {};
    for (const key of keys) {
      const descriptor = descriptors[key];
      if (!descriptor.enumerable || !Object.hasOwn(descriptor, "value")) fail();
      result[key] = descriptor.value;
    }
    return result;
  } catch (error) { sanitize(error); }
}

function cleanPath(value) {
  if (typeof value !== "string" || !isAbsolute(value)) fail();
  const path = resolve(value);
  if (path === "/" || path.length < 8) fail();
  return path;
}

function publicData(value, depth = 0) {
  if (depth > 10) fail();
  if (value === null || typeof value === "boolean") return value;
  if (typeof value === "string") { if (value.length > 64 * 1024) fail(); return value; }
  if (typeof value === "number") { if (!Number.isFinite(value)) fail(); return value; }
  if (typeof value !== "object" || types.isProxy(value)) fail();
  if (Array.isArray(value)) return Object.freeze(value.map((entry) => publicData(entry, depth + 1)));
  if (![Object.prototype, null].includes(Object.getPrototypeOf(value))) fail();
  const descriptors = Object.getOwnPropertyDescriptors(value);
  if (Reflect.ownKeys(descriptors).length > 96) fail();
  const result = {};
  for (const [key, descriptor] of Object.entries(descriptors)) {
    if (!descriptor.enumerable || !Object.hasOwn(descriptor, "value")) fail();
    if (/(?:private.?key|role.?access|transcript|reasoning|controller)/i.test(key)) fail();
    result[key] = publicData(descriptor.value, depth + 1);
  }
  return Object.freeze(result);
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

function descriptor(value) {
  const item = exact(value, ["bootstrapPublicKey", "harness", "role", "runId", "runtime", "schema", "tlsCertificate"]);
  if (
    item.schema !== "clockchain.mechanics-proof-party-bootstrap/v1" || !HARNESSES.includes(item.harness) ||
    !ROLES.includes(item.role) || !UUID.test(item.runId) || typeof item.tlsCertificate !== "string" ||
    !item.tlsCertificate.includes("-----BEGIN CERTIFICATE-----") || typeof item.bootstrapPublicKey !== "string"
  ) fail();
  try { if (createPublicKey(item.bootstrapPublicKey).asymmetricKeyType !== "ed25519") fail(); } catch { fail(); }
  return Object.freeze({ ...item, runtime: runtimeBinding(item.runtime) });
}

function cleanOptions(value) {
  const item = exact(value, OPTION_KEYS);
  if (
    !HARNESSES.includes(item.harness) || !ROLES.includes(item.role) || !UUID.test(item.runId) ||
    !DIGEST.test(item.manifestDigest) || !DIGEST.test(item.workloadAttestationDigest) ||
    !TOKEN.test(item.runtimeId) || !TOKEN.test(item.taskId) || item.mcpEndpoint !== MCP_ENDPOINT ||
    !Number.isInteger(item.port) || item.port !== 8443 || typeof item.listenHost !== "string" || item.listenHost.length === 0
  ) fail();
  return Object.freeze({
    ...item,
    root: cleanPath(item.root),
    opensslPath: cleanPath(item.opensslPath),
    publicEndpoint: endpoint(item.publicEndpoint),
    mandate: publicData(item.mandate),
  });
}

function opposite(role) { return role === "initiator" ? "responder" : "initiator"; }

function createBootstrapSigner() {
  let pair = generateKeyPairSync("ed25519");
  let active = true;
  const publicKey = pair.publicKey.export({ type: "spki", format: "pem" });
  return Object.freeze({
    publicKey,
    signCanonicalBytes(bytes) {
      if (!active || !Buffer.isBuffer(bytes)) fail();
      return sign(null, bytes, pair.privateKey).toString("base64");
    },
    destroy() { if (!active) fail(); active = false; pair = null; return Object.freeze({ destroyed: true }); },
  });
}

async function waitForInvitation(transport) {
  for (let count = 0; count < 6_000; count += 1) {
    const evidence = transport.publicEvidence();
    if (Array.isArray(evidence?.invitations) && evidence.invitations.some((entry) => entry?.direction === "inbound")) {
      return transport.takeInvitation();
    }
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
  fail();
}

const DEFAULTS = Object.freeze({
  createActionRecorder: createVerifiedReleaseActionRecorder,
  createBootstrapSigner,
  createBridge: createDirectA2APartyBridge,
  createCheckpointClient: createAgentHandshakeCheckpointClient,
  createHarnessAdapter({ harness, ...options }) {
    return harness === "codex" ? createAcpCodexHarnessAdapter(options) : createAcpClaudeHarnessAdapter(options);
  },
  createInvitationTransport: createInvitationBootstrapTransport,
  createProcessTransport: createAcpProcessTransport,
  createTlsIdentity: createEphemeralTlsIdentity,
  waitForInvitation,
});

function dependencies(input = {}) {
  if (input === null || typeof input !== "object" || Array.isArray(input) || types.isProxy(input)) fail();
  const descriptors = Object.getOwnPropertyDescriptors(input);
  const result = { ...DEFAULTS };
  for (const [key, descriptor] of Object.entries(descriptors)) {
    if (!DEPENDENCY_KEYS.includes(key) || !descriptor.enumerable || !Object.hasOwn(descriptor, "value") || typeof descriptor.value !== "function") fail();
    result[key] = descriptor.value;
  }
  return Object.freeze(result);
}

function bindingForCard(authorityBinding) {
  return Object.freeze({
    endpoint: authorityBinding.runtime.endpoint,
    partySignerAddress: authorityBinding.partySignerAddress,
    runtimeId: authorityBinding.runtime.runtimeId,
    taskId: authorityBinding.runtime.taskId,
    workloadAttestationDigest: authorityBinding.runtime.workloadAttestationDigest,
  });
}

function hasEnv(env, key) {
  return typeof env[key] === "string" && env[key].length > 0;
}

async function installCodexSerializedAuth(value, home, setStage) {
  setStage("decode");
  if (typeof value !== "string" || value.length < 4 || value.length > 96 * 1024 || !/^[A-Za-z0-9+/=]+$/.test(value)) fail();
  let serialized;
  try { serialized = Buffer.from(value, "base64").toString("utf8"); } catch { fail(); }
  if (Buffer.byteLength(serialized, "utf8") < 2 || Buffer.byteLength(serialized, "utf8") > 64 * 1024) fail();
  setStage("parse");
  const authentication = await loadAppleClientAuthentication({ client: "codex", serialized }).catch(fail);
  setStage("install");
  await installAppleClientAuthentication({ authentication, home }).catch(fail);
}

async function providerEnvFor(harness, home, env = process.env, setStage = () => {}) {
  const result = {};
  setStage("input");
  if (harness === "codex") {
    if (
      ["CLAUDE_CODE_USE_BEDROCK", "ANTHROPIC_MODEL", "ANTHROPIC_API_KEY"].some((key) => hasEnv(env, key)) ||
      AWS_CREDENTIAL_OVERRIDE_ENV.some((key) => hasEnv(env, key))
    ) fail();
    const authJson = env[CODEX_AUTH_JSON_BASE64];
    const hasSerializedAuth = typeof authJson === "string" && authJson.length > 0;
    const apiKeys = ["CODEX_API_KEY", "OPENAI_API_KEY"].filter((key) => hasEnv(env, key));
    if (apiKeys.length > 1 || (hasSerializedAuth && apiKeys.length > 0) || (!hasSerializedAuth && apiKeys.length !== 1)) fail();
    if (hasSerializedAuth) await installCodexSerializedAuth(authJson, home, setStage);
    setStage("export");
    for (const key of CODEX_PROVIDER_ENV) {
      const value = env[key];
      if (typeof value === "string" && value.length > 0) result[key] = value;
    }
  } else {
    if (
      hasEnv(env, CODEX_AUTH_JSON_BASE64) || hasEnv(env, "CODEX_API_KEY") ||
      hasEnv(env, "OPENAI_API_KEY") || hasEnv(env, "CLOCKCHAIN_CODEX_MODEL") ||
      hasEnv(env, "ANTHROPIC_API_KEY") || AWS_CREDENTIAL_OVERRIDE_ENV.some((key) => hasEnv(env, key))
    ) fail();
    setStage("export");
    for (const key of CLAUDE_BEDROCK_PROVIDER_ENV) {
      const value = env[key];
      if (typeof value === "string" && value.length > 0) result[key] = value;
    }
  }
  return Object.freeze(result);
}

function peerBindingForCard(peerRuntime) {
  return Object.freeze({
    endpoint: peerRuntime.endpoint,
    runtimeId: peerRuntime.runtimeId,
    taskId: peerRuntime.taskId,
    workloadAttestationDigest: peerRuntime.workloadAttestationDigest,
  });
}

export async function createMechanicsProofPartyRuntime(optionsInput = {}, dependenciesInput = {}) {
  let options;
  let deps;
  let rootIdentity = null;
  let initialTls = null;
  let initialBootstrapSigner = null;
  let constructed = false;
  try {
    options = cleanOptions(optionsInput);
    deps = dependencies(dependenciesInput);
    await mkdir(options.root, { mode: 0o700, recursive: false });
    await chmod(options.root, 0o700);
    const rootStat = await lstat(options.root);
    if (!rootStat.isDirectory() || rootStat.isSymbolicLink() || (rootStat.mode & 0o777) !== 0o700) fail();
    rootIdentity = Object.freeze({ dev: rootStat.dev, ino: rootStat.ino, path: options.root });
    const paths = Object.freeze({
      home: join(options.root, "home"),
      socket: join(options.root, "socket"),
      state: join(options.root, "state"),
      tmp: join(options.root, "workspace", "tmp"),
      workspace: join(options.root, "workspace"),
    });
    for (const path of [paths.home, paths.state, paths.workspace]) await mkdir(path, { mode: 0o700, recursive: false });
    await mkdir(paths.tmp, { mode: 0o700, recursive: false });
    const tls = await deps.createTlsIdentity({ hostname: new URL(options.publicEndpoint).hostname, opensslPath: options.opensslPath, root: join(options.root, "tls") });
    initialTls = tls;
    const bootstrapSigner = deps.createBootstrapSigner();
    initialBootstrapSigner = bootstrapSigner;
    if (
      typeof tls?.certificate !== "string" || typeof tls?.privateKey !== "string" || !DIGEST.test(tls?.certificateSha256) ||
      typeof tls?.destroy !== "function" || typeof bootstrapSigner?.publicKey !== "string" ||
      typeof bootstrapSigner?.signCanonicalBytes !== "function" || typeof bootstrapSigner?.destroy !== "function"
    ) fail();
    const localRuntime = Object.freeze({
      endpoint: options.publicEndpoint,
      runtimeId: options.runtimeId,
      taskId: options.taskId,
      tlsCertificateSha256: tls.certificateSha256,
      workloadAttestationDigest: options.workloadAttestationDigest,
    });
    const bootstrap = Object.freeze({
      schema: "clockchain.mechanics-proof-party-bootstrap/v1",
      bootstrapPublicKey: bootstrapSigner.publicKey,
      harness: options.harness,
      role: options.role,
      runId: options.runId,
      runtime: localRuntime,
      tlsCertificate: tls.certificate,
    });
    let invitationTransport = null;
    let actionRecorder = null;
    let bridge = null;
    let adapter = null;
    let launched = false;
    let destroyed = false;

    async function teardown() {
      if (destroyed) fail();
      destroyed = true;
      const tasks = [];
      if (launched && adapter !== null) tasks.push(() => adapter.terminateSession({ sessionId: options.runId, reason: "mechanics-proof-complete" }));
      if (bridge !== null) tasks.push(() => bridge.destroy());
      if (actionRecorder !== null) tasks.push(() => actionRecorder.close());
      if (invitationTransport !== null) tasks.push(() => invitationTransport.close());
      tasks.push(() => bootstrapSigner.destroy());
      tasks.push(() => tls.destroy());
      const results = await Promise.allSettled(tasks.map((task) => Promise.resolve().then(task)));
      try {
        const current = await lstat(options.root);
        if (!current.isDirectory() || current.isSymbolicLink() || current.dev !== rootStat.dev || current.ino !== rootStat.ino) fail();
        await rm(options.root, { recursive: true, force: false });
      } catch { results.push({ status: "rejected", reason: new Error("cleanup") }); }
      if (results.some((result) => result.status === "rejected")) fail();
      return Object.freeze({ completed: true });
    }

    constructed = true;
    return Object.freeze({
      bootstrapDescriptor() { if (destroyed) fail(); return bootstrap; },
      async run(input) {
        if (destroyed || invitationTransport !== null) fail();
        let terminalEvidence = null;
        let runFailed = false;
        let runFailureStage = null;
        let runStage = "peer-validate";
        try {
          const runInput = optionalExact(input, ["peerDescriptor"], ["onPublicEvent"]);
          const onPublicEvent = runInput.onPublicEvent ?? (() => undefined);
          if (typeof onPublicEvent !== "function") fail();
          let eventSequence = 0;
          async function emit(type, evidence) {
            eventSequence += 1;
            const event = Object.freeze({
              schema: "clockchain.mechanics-proof-party-event/v1",
              runId: options.runId,
              role: options.role,
              sequence: String(eventSequence),
              type,
              evidenceDigest: digestHex(publicData(evidence)),
            });
            await onPublicEvent(event);
          }
          const peer = descriptor(runInput.peerDescriptor);
          if (
            peer.runId !== options.runId || peer.role !== opposite(options.role) ||
            peer.runtime.runtimeId === localRuntime.runtimeId || peer.runtime.taskId === localRuntime.taskId ||
            peer.runtime.workloadAttestationDigest === localRuntime.workloadAttestationDigest ||
            peer.runtime.tlsCertificateSha256 === localRuntime.tlsCertificateSha256 ||
            peer.bootstrapPublicKey === bootstrapSigner.publicKey
          ) fail();
          runStage = "listener-create";
          invitationTransport = await deps.createInvitationTransport({
            bootstrapSigner: Object.freeze({
              publicKey: bootstrapSigner.publicKey,
              signCanonicalBytes: bootstrapSigner.signCanonicalBytes,
            }),
            initialSessionId: null,
            listenHost: options.listenHost,
            localRuntime: { runtimeId: localRuntime.runtimeId, workloadAttestationDigest: localRuntime.workloadAttestationDigest },
            peerBootstrapPublicKey: peer.bootstrapPublicKey,
            peerRole: peer.role,
            peerRuntime: { runtimeId: peer.runtime.runtimeId, workloadAttestationDigest: peer.runtime.workloadAttestationDigest },
            peerUrl: peer.runtime.endpoint,
            port: options.port,
            publicEndpoint: localRuntime.endpoint,
            role: options.role,
            runId: options.runId,
            tls: {
              certificate: tls.certificate,
              privateKey: tls.privateKey,
              ownCertificateSha256: localRuntime.tlsCertificateSha256,
              peerCertificateSha256: peer.runtime.tlsCertificateSha256,
            },
          });
          runStage = "listener-ready";
          await emit("a2a.listener.ready", invitationTransport.publicEvidence());
          let privateInvitation = null;
          if (options.role === "responder") {
            runStage = "invitation-await";
            privateInvitation = await deps.waitForInvitation(invitationTransport);
            await emit("a2a.invitation.received", invitationTransport.publicEvidence());
          }
          runStage = "recorder-create";
          actionRecorder = await deps.createActionRecorder({
            manifestDigest: options.manifestDigest,
            room: { cache: paths.home, home: paths.home, root: options.root, state: paths.state, tmp: paths.tmp, workspace: paths.workspace },
            socketRoot: paths.socket,
          });
          runStage = "checkpoint-client-create";
          const checkpointClient = deps.createCheckpointClient({
            endpoint: options.mcpEndpoint,
            fetchImpl: globalThis.fetch,
            timeoutMs: 15_000,
          });
          runStage = "bridge-create";
          bridge = deps.createBridge({
            activateSignedChannel: async (context) => activatePartySignedChannel({
              createAuthority: () => createPartyA2AAuthority({
                nowMs: () => Date.now(),
                peerRuntime: peer.runtime,
                platform: process.platform,
                policyDigest: context.policyDigest,
                repositorySha: context.repositorySha,
                role: options.role,
                runtime: localRuntime,
                sessionId: context.sessionId,
                statePath: join(paths.tmp, ".clockchain", "handshakes", context.sessionId, options.role, "wallet.json"),
                terms: context.terms,
              }),
              createCardBootstrap: ({ authorityBinding }) => createA2ACardBootstrap({
                nowMs: () => Date.now(),
                ownBinding: bindingForCard(authorityBinding),
                peerBinding: null,
                peerRuntime: peerBindingForCard(peer.runtime),
                role: options.role,
                sessionId: context.sessionId,
                transport: invitationTransport,
              }),
              createTaskTransport: async ({ cards, role }) => {
                await invitationTransport.close({ graceful: true });
                return createHttpTaskTransport({
                  allowLoopbackForTests: false,
                  listenHost: options.listenHost,
                  nowMs: () => Date.now(),
                  ownCard: cards[role],
                  peerCard: cards[opposite(role)],
                  peerUrl: peer.runtime.endpoint,
                  port: options.port,
                  publicEndpoint: localRuntime.endpoint,
                  role,
                  sessionId: context.sessionId,
                  tls: { cert: tls.certificate, key: tls.privateKey, peerCa: peer.tlsCertificate, peerCertificateSha256: peer.runtime.tlsCertificateSha256 },
                });
              },
              nowMs: () => Date.now(),
              role: options.role,
              sessionId: context.sessionId,
              sleep: defaultPartySignedChannelSleep,
            }),
            completionRecorder: actionRecorder,
            invitationTransport,
            nowMs: () => Date.now(),
            role: options.role,
            sessionId: null,
            submitCheckpoint: checkpointClient.submitCheckpoint,
          });
          runStage = "provider-auth";
          const providerEnv = await providerEnvFor(options.harness, paths.home, process.env, (stage) => {
            runStage = `provider-auth-${stage}`;
          });
          runStage = "transport-create";
          const processTransport = deps.createProcessTransport({
            actionRecorder: actionRecorder.actionRecorder,
            env: {
              PATH: `${join(process.cwd(), "node_modules", ".bin")}:${dirname(process.execPath)}:/usr/local/bin:/usr/bin:/bin`,
              ...providerEnv,
            },
            harness: options.harness,
            home: paths.home,
            pin: ACP_VERSION_PINS[options.harness],
            partyBridge: Object.freeze({
              observeToolResult(input) { return bridge.observeToolResult(input); },
            }),
            trustedAdapterPublicKeys: [actionRecorder.trustedAdapterPublicKey],
            workspace: paths.workspace,
          });
          runStage = "adapter-create";
          adapter = deps.createHarnessAdapter({
            decisionCallback: () => Object.freeze({ decision: "authorize" }),
            harness: options.harness,
            transport: processTransport,
            trustedAdapterPublicKeys: [actionRecorder.trustedAdapterPublicKey],
          });
          let invitationPath;
          if (privateInvitation !== null) {
            if (privateInvitation.sessionId === undefined || typeof privateInvitation.invitation !== "string") fail();
            invitationPath = join(paths.workspace, "responder-invitation.txt");
            await writeFile(invitationPath, `${privateInvitation.invitation}\n`, { encoding: "utf8", flag: "wx", mode: 0o600 });
            await chmod(invitationPath, 0o600);
            privateInvitation = null;
          }
          runStage = "agent-starting";
          await emit("agent.starting", { harness: options.harness, runtimeId: options.runtimeId });
          runStage = "agent-launch";
          await adapter.launchSession({
            runtime: { harness: options.harness, role: options.role, runtimeId: options.runtimeId, sessionId: options.runId },
            mandate: options.mandate,
            mcpEndpoint: options.mcpEndpoint,
            a2aConfig: {
              endpoint: localRuntime.endpoint,
              peerCard: { endpoint: peer.runtime.endpoint, id: peer.runtime.runtimeId },
              ...(invitationPath === undefined ? {} : { invitationPath }),
            },
          });
          launched = true;
          runStage = "evidence-validate";
          const bridgeEvidence = publicData(bridge.publicEvidence());
          const cardSignerAddresses = publicData(bridgeEvidence.cardSignerAddresses);
          const ownCardSigner = cardSignerAddresses?.[options.role];
          const peerCardSigner = cardSignerAddresses?.[opposite(options.role)];
          const certificateIdentity = publicData(bridgeEvidence.certificate?.identity);
          if (
            bridgeEvidence.sessionId === null || !UUID.test(bridgeEvidence.sessionId) ||
            bridgeEvidence.certificate?.verified !== true || !DIGEST.test(bridgeEvidence.certificate?.proofDigest) ||
            !DIGEST.test(bridgeEvidence.certificate?.certificateDigest) || !DIGEST.test(bridgeEvidence.certificate?.resultDigest) ||
            typeof ownCardSigner !== "string" || ownCardSigner !== certificateIdentity.sessionKeyAddress ||
            typeof peerCardSigner !== "string" || peerCardSigner === ownCardSigner ||
            !Array.isArray(bridgeEvidence.certificate?.anchors) || bridgeEvidence.certificate.anchors.length !== 3 ||
            !Array.isArray(bridgeEvidence.deliveries) || bridgeEvidence.deliveries.length !== 1
          ) fail();
          const directDelivery = publicData(bridgeEvidence.deliveries[0]);
          if (
            directDelivery.acknowledged !== true || !["proposal", "acceptance"].includes(directDelivery.artifactType) ||
            !DIGEST.test(directDelivery.artifactDigest) || !DIGEST.test(directDelivery.checkpointDigest) ||
            !Array.isArray(directDelivery.messageDigests) || directDelivery.messageDigests.length !== 2 ||
            directDelivery.messageDigests.some((digest) => !DIGEST.test(digest))
          ) fail();
          runStage = "certificate-event";
          await emit("certificate.verified", bridgeEvidence.certificate);
          runStage = "agent-terminate";
          await adapter.terminateSession({ sessionId: options.runId, reason: "mechanics-proof-complete" });
          launched = false;
          runStage = "evidence-collect";
          const harnessEvidence = publicData(await adapter.collectEvidence({ sessionId: options.runId }));
          terminalEvidence = Object.freeze({
            schema: "clockchain.mechanics-proof-party-evidence/v1",
            runId: options.runId,
            protocolSessionId: bridgeEvidence.sessionId,
            role: options.role,
            harness: options.harness,
            runtimeId: options.runtimeId,
            workloadAttestationDigest: options.workloadAttestationDigest,
            peerRuntimeId: peer.runtime.runtimeId,
            bridgeEvidenceDigest: digestHex(bridgeEvidence),
            harnessEvidenceDigest: digestHex(harnessEvidence),
            certificateProofDigest: bridgeEvidence.certificate.proofDigest,
            certificateDigest: bridgeEvidence.certificate.certificateDigest,
            resultDigest: bridgeEvidence.certificate.resultDigest,
            certificateVerified: true,
            identity: certificateIdentity,
            a2aCardSignerAddress: ownCardSigner,
            anchors: publicData(bridgeEvidence.certificate.anchors),
            directDelivery,
            externalBusinessActionPerformed: false,
            terminalStatus: "completed",
            teardown: Object.freeze({ completed: false }),
          });
        } catch (error) {
          runFailed = true;
          const listenerStage = runStage === "listener-create" ? invitationBootstrapFailureStage(error) : null;
          const recorderStage = runStage === "recorder-create" ? verifiedReleaseActionRecorderFailureStage(error) : null;
          const launchStage = runStage === "agent-launch" ? acpProcessTransportFailureStage(error) : null;
          runFailureStage = listenerStage !== null
            ? `listener-${listenerStage}`
            : recorderStage !== null ? `recorder-${recorderStage}`
              : launchStage !== null ? `agent-launch-${launchStage}` : runStage;
        }
        let teardownResult;
        try { teardownResult = await teardown(); } catch { runFailed = true; runFailureStage ??= "teardown"; }
        if (runFailed || terminalEvidence === null || teardownResult?.completed !== true) {
          throw stagedFailure(runFailureStage ?? "evidence-validate");
        }
        return Object.freeze({ ...terminalEvidence, teardown: Object.freeze({ completed: true }) });
      },
      destroy: teardown,
    });
  } catch (error) {
    if (!constructed) {
      const cleanup = [];
      if (initialBootstrapSigner !== null && typeof initialBootstrapSigner.destroy === "function") cleanup.push(() => initialBootstrapSigner.destroy());
      if (initialTls !== null && typeof initialTls.destroy === "function") cleanup.push(() => initialTls.destroy());
      await Promise.allSettled(cleanup.map((task) => Promise.resolve().then(task)));
      if (rootIdentity !== null) {
        try {
          const current = await lstat(rootIdentity.path);
          if (current.isDirectory() && !current.isSymbolicLink() && current.dev === rootIdentity.dev && current.ino === rootIdentity.ino) {
            await rm(rootIdentity.path, { recursive: true, force: false });
          }
        } catch {}
      }
    }
    sanitize(error);
  }
}
