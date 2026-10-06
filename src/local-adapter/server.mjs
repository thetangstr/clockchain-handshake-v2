// clockchain-local-adapter — the pre-installed local half of the Clockchain
// agent handshake. The hosted coordinator (a stateless streamable-HTTP MCP
// endpoint) issues localAction objects whose helper steps must run LOCALLY:
// private keys never leave this machine and the server never signs. The
// portable fallback asks the model to download pinned helper bytes and run a
// multi-KB `node --eval` command; safety-conscious runtimes correctly refuse
// runtime download-and-execute. This adapter removes that path: the user
// installs it once, it proxies the handshake tools upstream so it can observe
// localActions flowing through tool responses, stages each returned helper
// step privately after validating it against the release pin, and exposes a
// single fixed zero-input tool — authorize_local_action — that executes one
// staged digest-bound step per call through the pinned local helper. No
// runtime download, no eval of remote bytes, no model transcription.
//
// 2.2.0 (fill-from-local.mjs): the adapter fills every long handshake argument
// — role access, session key address, policy digest, signatures, checkpoint,
// invite terms — from its own staged results and withholds the signatures from
// authorize_local_action results, so the model never carries them. The number
// of model calls, and so of coordinator receipts, is unchanged.
//
// One other local tool exists: sign_agent_contract_bind (contract-bind.mjs),
// which signs exactly one agent-contract.bind/v1 statement with the session
// key of a handshake session this adapter already holds — never anything
// else. It has its own fixed refusal codes and is never proxied upstream.
//
// Every failure is fail-closed with the same generic refusal: the adapter
// never distinguishes WHICH check a candidate step failed — with a single
// exception. A step that passes every structural check but is pinned to a
// different release digest is refused with the upgrade-directed
// ADAPTER_RELEASE_MISMATCH_REFUSAL instead, because "your adapter is behind"
// is actionable where a bare refusal is not.

import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdirSync, readFileSync } from "node:fs";
import { tmpdir as osTmpdir } from "node:os";
import { isAbsolute, join, relative, resolve } from "node:path";
import { createInterface } from "node:readline";
import { promisify, types } from "node:util";

import {
  AGENT_HANDSHAKE_HELPER_NODE_MAJOR,
  AGENT_HANDSHAKE_HELPER_VERSION,
  AGENT_HANDSHAKE_RELEASE_ASSET_PREFIX,
} from "../agent-handshake/v2/constants.mjs";
import { localPolicyDigest, validateLocalPolicy } from "../agent-handshake/v2/policy.mjs";
import { canonicalBytes } from "../core/canonical.mjs";
import {
  CONTRACT_BIND_REFUSALS,
  CONTRACT_BIND_TOOL,
  CONTRACT_BIND_TOOL_DEFINITION,
  ContractBindRefusal,
  recordVerifiedSession,
  verifiedSessionFromStep,
  contractBindPinsFromEnv,
  contractBindPinsOption,
  contractBindRefusalText,
  signContractBindStatement,
} from "./contract-bind.mjs";
import { VERIFIED_HELPER_BOOTSTRAP } from "../harness/verified-release-action-recorder.mjs";
import {
  ACCESS_TOOLS,
  LOCAL_FILL_REFUSALS,
  createForwardJournal,
  createLocalValues,
  isTransientInviteRefusal,
  JOURNAL_KINDS,
  LOCAL_OUTCOMES,
  localFillRefusalText,
  planAccessFill,
  planInviteFill,
  TRANSIENT_OUTCOME,
  UPSTREAM_UNAVAILABLE_PREFIX,
  redactHelperResult,
  resolveInviteBudget,
  resolveInviteTerms,
  roleAccessFromResult,
  serverNonceFromResult,
  receiptHashFromResult,
  resultDigest,
  withLocalFills,
} from "./fill-from-local.mjs";
import {
  INVITATION_REF_REFUSALS,
  INVITATION_REF_RE,
  INVITATION_REF_TTL_MS,
  InvitationRefError,
  claimInvitationRef,
  discardIssuedInvitationRef,
  invitationShape,
  issuedInvitationRefState,
  putInvitationRef,
} from "./invitation-refs.mjs";
import { gateNeverShip } from "./never-ship-gate.mjs";

const execFileAsync = promisify(execFile);

export const ADAPTER_NAME = "clockchain-local-adapter";
export const ADAPTER_TOOL = "authorize_local_action";
export const ADAPTER_APPROVAL_TOOL = `mcp__${ADAPTER_NAME}__${ADAPTER_TOOL}`;
// While the ACM4 demo pin is live, the hosted edge routes /handshake/mcp to a
// frozen 2.1.6 instance and the current build's handshake surface is /next.
// CLOCKCHAIN_LOCAL_ADAPTER_ENDPOINT remains available as an override for
// custom endpoints (server.mjs:~470); it is not needed while this default
// matches the live route.
export const ADAPTER_DEFAULT_ENDPOINT = "https://mcp.clockchain.network/next/handshake/mcp";
export const ADAPTER_ASSET_ERROR = "ADAPTER_ASSET_VERIFICATION_FAILED";

const CLI_RESULT_SCHEMA = "clockchain.agent-handshake-cli-result/v1";
const SIGNING_REQUEST_SCHEMA = "clockchain.agent-handshake-signing-request/v1";
const CERTIFICATE_VERIFICATION_SCHEMA = "clockchain.agent-handshake-certificate-verification/v1";
const HELPER_FILENAME = "clockchain-agent-handshake.cjs";
const MANIFEST_FILENAME = "manifest.json";
const PIN_FILENAME = "pin.json";
const TMPDIR_TOKEN = "${TMPDIR%/}";

const SHA256 = /^[0-9a-f]{64}$/;
const COMMIT = /^[0-9a-f]{40}$/;
const KID = /^[a-z0-9][a-z0-9-]{0,63}$/;
const DECIMAL = /^(?:0|[1-9][0-9]*)$/;
const BASE64URL = /^[A-Za-z0-9_-]+$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const NODE_RUNTIME = new RegExp(`^${AGENT_HANDSHAKE_HELPER_NODE_MAJOR}\\.[0-9]+\\.[0-9]+$`);
const HELPER_ERROR_CODE = /^[A-Z][A-Z0-9_]{0,63}$/;

// A structurally valid step pinned to a different release digest means the
// coordinator has moved to a helper release this adapter does not vendor —
// or the step is corrupt/forged. Fail closed either way, but unlike every
// other refusal this one names the recovery path.
export const ADAPTER_RELEASE_MISMATCH_REFUSAL =
  "clockchain-local-adapter is behind the coordinator's required helper " +
  "release — upgrade with: npx -y @d4d.group/local-adapter@latest, then " +
  "restart your MCP client. If the adapter is already current, the step is " +
  "pinned to a different release — a mismatch that must not be bypassed.";
const GENERIC_REFUSAL = "Clockchain local adapter refused the action.";

const OPERATIONS = Object.freeze(["init", "policy", "inspect", "register", "sign", "verify-certificate"]);
const PAYLOAD_OPERATIONS = Object.freeze(["policy", "sign", "verify-certificate"]);
const SIGNING_OPERATIONS = Object.freeze(["identity_claim", "proposal", "acceptance", "evidence"]);
const ROLES = Object.freeze(["initiator", "responder"]);

const STEP_KEYS = Object.freeze([
  "operation", "role", "sessionId", "approvalTool", "commandLength",
  "commandSha256", "shellCommand", "shellCommandFetch", "policyDigest",
]);
const STEP_OPTIONAL_KEYS = Object.freeze(["shellCommandFetch", "policyDigest"]);
const PIN_KEYS = Object.freeze([
  "version", "sourceCommit", "manifestDigest", "allowedAssetPrefix", "hostRoots",
]);
const ROOT_KEYS = Object.freeze(["kid", "fingerprint"]);
const MANIFEST_KEYS = Object.freeze(["schema", "version", "sourceCommit", "nodeRuntime", "assets"]);
const ASSET_KEYS = Object.freeze([
  "platform", "arch", "upstreamSupport", "filename", "url", "byteLength",
  "sha256", "nativeSignature", "execution",
]);
const SIGNATURE_KEYS = Object.freeze(["type", "verified", "signer", "timestamp", "notarized"]);
const EXECUTION_KEYS = Object.freeze([
  "verified", "platform", "arch", "exitCode", "publicOutputSha256",
]);

// The coordinator's compactHelperStep emits exactly
//   <op> --state-dir "${TMPDIR%/}/.clockchain/handshakes/<uuid>/<role>"
// optionally followed by ` --payload-base64url <b64u>`; the quoted state-dir
// token is the only double-quoted word.
const SUFFIX_PATTERN = new RegExp(
  `^([a-z-]+) --state-dir "\\$\\{TMPDIR%/\\}/\\.clockchain/handshakes/` +
  `(${UUID.source.slice(1, -1)})/(initiator|responder)"` +
  `( --payload-base64url (${BASE64URL.source.slice(1, -1)}))?$`,
);

const MAX_STAGED_STEPS = 64;
const STAGED_STEP_TTL_MS = 20 * 60_000;
const UPSTREAM_RPC_BUDGET_MS = 30_000;
const HELPER_RUN_BUDGET_MS = 120_000;
const HELPER_MAX_OUTPUT_BYTES = 256 * 1024;
const MAX_LINE_BYTES = 1024 * 1024;
const MAX_PAYLOAD_BYTES = 512 * 1024;
const MAX_WALK_DEPTH = 32;
const FALLBACK_INSTRUCTIONS =
  "Clockchain local adapter: proxies the agent_handshake_* tools to the hosted " +
  "Clockchain coordinator and executes each staged, digest-bound local action " +
  "through the fixed zero-input tool authorize_local_action.";

const ADAPTER_TOOL_DEFINITION = Object.freeze({
  name: ADAPTER_TOOL,
  description:
    "Execute the next staged Clockchain local action for this role. The " +
    "adapter privately staged each digest-bound helper step issued inside a " +
    "localAction; one call executes exactly one staged step through the " +
    "pinned local helper. Takes no arguments; call once per staged step, in " +
    "order, waiting for each result before the next call.",
  inputSchema: Object.freeze({
    type: "object",
    properties: Object.freeze({}),
    additionalProperties: false,
  }),
});

// The adapter's local tools, in tools/list order. Anything else is proxied.
const LOCAL_TOOL_DEFINITIONS = Object.freeze([
  ADAPTER_TOOL_DEFINITION,
  CONTRACT_BIND_TOOL_DEFINITION,
]);

function invalid() {
  throw new Error(GENERIC_REFUSAL);
}

// C-ADP-1 journal helpers: what the model passed (never undefined, so the
// line hashes the same before and after JSON), and the plan of a call the
// adapter forwards as given.
function modelArgsOf(params) {
  return params.arguments === undefined ? null : params.arguments;
}
const NOTHING_FILLED = Object.freeze({ forwarded: null, filled: Object.freeze([]) });

// The coordinator was NOT reached: the hosted host's reverse proxy answered a
// bad gateway / unavailable while the host restarts between sessions (~1.3 s of
// every ~121 s), or the connection was refused. Nothing was sent to the host, so
// nothing was minted; the relayed refusal is coded (UPSTREAM_UNAVAILABLE) so a
// client can retry it, and an invite it refuses does not spend the budget.
// A timeout or any other status stays the generic failure (it may have applied).
const UPSTREAM_UNREACHED_STATUSES = new Set([502, 503]);
const UPSTREAM_UNREACHED_CAUSES = new Set(["ECONNREFUSED", "ENOTFOUND", "EAI_AGAIN"]);
class UpstreamUnreachedError extends Error {}

// 2.1.11 invitation guard. The responder invitation is a coordinator-minted
// role-access token: <base64url(JSON payload)>.<base64url(HMAC-SHA256)>. A
// model copying it from the opened rendezvous box can silently alter it (live
// p6-l-2026-10-01-7: "expMs" came back as "expms", identical length), and the
// coordinator then answers a non-retryable role_access_invalid. Check the
// structure locally — exact key set, responder role, accept-only tools, a
// 43-char signature — and refuse with an actionable code before forwarding.
// The token itself is never echoed.
const INVITATION_TOOL = "agent_handshake_accept_invitation";
const ROLE_ACCESS_KEYS = Object.freeze([
  "alg", "allowedTools", "aud", "expMs", "iss", "jti", "kid", "nbfMs", "role",
  "sessionId", "statementDigest", "typ", "v",
]);
const B64URL = /^[A-Za-z0-9_-]+$/;
// M1 (2.2.1): a refusal may name a payload field only when the name is short
// and identifier-shaped, and names at most FIELD_NAME_LIMIT of them; any other
// key is only counted, so no free text from the payload reaches the model.
const SAFE_FIELD_NAME = /^[A-Za-z][A-Za-z0-9]{0,15}$/;
const FIELD_NAME_LIMIT = 3;
function fieldNameList(keys) {
  const named = keys.filter((key) => SAFE_FIELD_NAME.test(key)).slice(0, FIELD_NAME_LIMIT);
  const others = keys.length - named.length;
  return [
    ...named.map((key) => JSON.stringify(key)),
    ...(others > 0 ? [`${others} other`] : []),
  ].join(", ");
}

// 2.1.12 pass-by-reference (see invitation-refs.mjs).
const INVITE_TOOL = "agent_handshake_invite";
export const INVITATION_REFS_ENV = "CLOCKCHAIN_LOCAL_ADAPTER_INVITATION_REFS";
const INVITATION_REF_TEXT = Object.freeze({
  INVITATION_REF_UNKNOWN:
    "this invitationRef is unknown, already used, or belongs to another tool. Open the sealed rendezvous box again (open_sealed returns a fresh invitationRef) and pass that ref.",
  INVITATION_REF_EXPIRED:
    "this invitationRef expired. Open the sealed rendezvous box again for a fresh invitationRef, or wait for a fresh invitation.",
  INVITATION_REF_STORE_UNAVAILABLE:
    "the company's private invitation store is unavailable on this host. Report this to your operator; do not retype the invitation.",
  INVITATION_REF_INVALID:
    "pass exactly { invitationRef } (optionally with acceptanceIdempotencyKey) — never the invitation text itself.",
});
function invitationRefRefusalText(code) {
  return `${code}: ${INVITATION_REF_TEXT[code] ?? INVITATION_REF_TEXT.INVITATION_REF_STORE_UNAVAILABLE}`;
}
const INVITATION_BY_REFERENCE_REQUIRED =
  "INVITATION_BY_REFERENCE_REQUIRED: this adapter accepts the responder invitation only by reference. " +
  "Pass { invitationRef } — the ref your signer's open_sealed returned — and never the invitation text; nothing was consumed.";
const INVITATION_REF_PROPERTY = Object.freeze({
  type: "string",
  pattern: INVITATION_REF_RE.source,
  description:
    "The single-use ref your company signer's open_sealed returned for the opened invitation. The adapter reads the exact invitation bytes locally; never pass the invitation text.",
});

// Rewrites the upstream agent_handshake_accept_invitation definition so the
// model sees the invitationRef argument (always), and — in refs mode — no
// longer sees the raw invitation argument at all.
function withInvitationRef(tool, refsOnly) {
  if (!isPlain(tool) || tool.name !== INVITATION_TOOL || !isPlain(tool.inputSchema)) return tool;
  const schema = tool.inputSchema;
  const properties = isPlain(schema.properties) ? { ...schema.properties } : {};
  if (refsOnly) delete properties.invitation;
  properties.invitationRef = INVITATION_REF_PROPERTY;
  const required = Array.isArray(schema.required) ? schema.required.filter((key) => key !== "invitation") : [];
  return {
    ...tool,
    description: `${typeof tool.description === "string" ? `${tool.description} ` : ""}` +
      (refsOnly
        ? "Pass invitationRef (from your signer's open_sealed); the adapter supplies the exact invitation bytes locally."
        : "Prefer invitationRef (from your signer's open_sealed) over the invitation text: the adapter supplies the exact bytes locally."),
    inputSchema: { ...schema, properties, required: refsOnly ? ["invitationRef"] : required },
  };
}

// 2.1.13 deliver-first guard (live p6-l-2026-10-02-2): the buyer created the
// invite in refs mode, then ran the staged local init/policy/inspect steps and
// never sealed or delivered the invitation; the provider waited ten minutes for
// nothing. In refs mode, while the ref this adapter issued for an Initiator
// session is unconsumed (<TMPDIR>/.clockchain/invitation-refs/<ref>.json still
// exists — the company signer consumes it when it seals or delivers), the adapter refuses that
// session's staged Initiator steps and its join/next/submit progression. An
// expired ref gets a distinct refusal and the session's staged steps are
// dropped, so the queue never deadlocks behind a session that cannot proceed.
export const DELIVER_INVITATION_FIRST = "DELIVER_INVITATION_FIRST";
export const DELIVER_INVITATION_EXPIRED = "DELIVER_INVITATION_EXPIRED";
const DELIVERY_GUARDED_TOOLS = Object.freeze(new Set([
  "agent_handshake_join",
  "agent_handshake_next",
  "agent_handshake_submit",
  "agent_handshake_submit_checkpoint",
]));
function deliverFirstText(entry, { staged }) {
  return `${DELIVER_INVITATION_FIRST}: the responder invitation for session ${entry.sessionId ?? "(this session)"} ` +
    `has not been delivered — invitation reference ${entry.ref} is still unconsumed. ` +
    "deliver this invitation reference to the provider through your company signer before continuing. " +
    (staged
      ? "Nothing was executed; the staged step stays queued."
      : "Nothing was sent to the coordinator.");
}
function deliverExpiredText(entry) {
  return `${DELIVER_INVITATION_EXPIRED}: invitation reference ${entry.ref} for session ${entry.sessionId ?? "(this session)"} ` +
    "expired before it was delivered, so this session can never be joined. " +
    "Create a fresh invitation with agent_handshake_invite, seal its new responderInvitationRef to the provider, " +
    "and deliver it; this session's staged steps were discarded.";
}

export function checkInvitationShape(invitation, { origin = "copy" } = {}) {
  const got = invitationShape(invitation);
  let expected = "<payload>";
  let ok = false;
  let detail = "";
  if (typeof invitation === "string" && invitation.length >= 80 && invitation.length <= 4096) {
    const parts = invitation.split(".");
    if (parts.length === 2 && B64URL.test(parts[0]) && B64URL.test(parts[1])) {
      try {
        const payload = JSON.parse(Buffer.from(parts[0], "base64url").toString("utf8"));
        if (isPlain(payload)) {
          const reencoded = Buffer.from(JSON.stringify(payload)).toString("base64url");
          expected = String(reencoded.length);
          const keys = Object.keys(payload).sort();
          const keysOk = keys.length === ROLE_ACCESS_KEYS.length &&
            keys.every((key, index) => key === ROLE_ACCESS_KEYS[index]);
          ok = keysOk &&
            reencoded === parts[0] &&
            payload.typ === "clockchain-agent-handshake-role-access" &&
            payload.role === "responder" &&
            Array.isArray(payload.allowedTools) && payload.allowedTools.length === 1 &&
            payload.allowedTools[0] === INVITATION_TOOL &&
            parts[1].length === 43;
          if (!ok && origin !== "ref") {
            // 2.1.12 (live p6-l-2026-10-02-1): at identical length the bare
            // "expected 628.43; got 628.43" read as a simulated fault to the
            // model. Name what changed — field NAMES only (public schema), no
            // values, never the token. 2.2.1: only short identifier-shaped
            // names, at most FIELD_NAME_LIMIT of them; the rest are counted.
            // Bytes behind a ref are the counterparty's: never named at all.
            const unexpected = keys.filter((key) => !ROLE_ACCESS_KEYS.includes(key));
            const missing = ROLE_ACCESS_KEYS.filter((key) => !keys.includes(key));
            const parts2 = [];
            if (unexpected.length > 0) parts2.push(`unexpected field ${fieldNameList(unexpected)}`);
            if (missing.length > 0) parts2.push(`missing field ${fieldNameList(missing)}`);
            if (parts2.length === 0) parts2.push("a field value or the signature differs from a coordinator-issued invitation");
            detail = ` — same length, but ${parts2.join("; ")}: a character was changed`;
          }
        }
      } catch { ok = false; }
    }
  }
  if (ok) return null;
  if (origin === "ref") {
    // M1 (2.2.1): nothing derived from the counterparty's bytes is echoed.
    return "INVITATION_CORRUPTED: the invitation the counterparty sealed is not a valid responder invitation. " +
      "It cannot be accepted; the ref is spent. Wait for the counterparty to seal and send a fresh invitation, then open that one.";
  }
  if (detail !== "") {
    return `INVITATION_CORRUPTED: the invitation was altered while copying (expected ${expected}.43 base64url; got ${got}${detail}). ` +
      "Do not retype the invitation: open the sealed rendezvous box again and pass the invitationRef it returns; the invitation was not consumed.";
  }
  return `INVITATION_CORRUPTED: the invitation was altered while copying (expected ${expected}.43 base64url; got ${got}). ` +
    "Re-open the sealed rendezvous box and pass its invitation value byte-for-byte (do not retype, decode, or reconstruct it); the invitation was not consumed.";
}

function releaseMismatch() {
  throw new Error(ADAPTER_RELEASE_MISMATCH_REFUSAL);
}

function isPlain(value) {
  return (
    value !== null && typeof value === "object" && !Array.isArray(value) &&
    !types.isProxy(value) &&
    [Object.prototype, null].includes(Object.getPrototypeOf(value))
  );
}

function exact(value, keys, required = keys) {
  if (!isPlain(value)) invalid();
  const actual = Reflect.ownKeys(value);
  if (actual.some((key) => typeof key !== "string" || !keys.includes(key))) invalid();
  for (const key of required) if (!Object.hasOwn(value, key)) invalid();
  const result = {};
  for (const key of actual) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (descriptor?.enumerable !== true || !Object.hasOwn(descriptor, "value")) invalid();
    result[key] = descriptor.value;
  }
  return result;
}

// --- install-time asset gate ------------------------------------------------

function validatePin(value) {
  const item = exact(value, PIN_KEYS);
  if (
    item.version !== AGENT_HANDSHAKE_HELPER_VERSION ||
    !COMMIT.test(item.sourceCommit) || !SHA256.test(item.manifestDigest) ||
    item.allowedAssetPrefix !== AGENT_HANDSHAKE_RELEASE_ASSET_PREFIX ||
    !Array.isArray(item.hostRoots) || item.hostRoots.length < 1 ||
    item.hostRoots.length > 2
  ) invalid();
  const roots = item.hostRoots.map((entry) => {
    const root = exact(entry, ROOT_KEYS);
    if (!KID.test(root.kid) || !SHA256.test(root.fingerprint)) invalid();
    return Object.freeze(root);
  });
  if (
    new Set(roots.map((root) => root.kid)).size !== roots.length ||
    new Set(roots.map((root) => root.fingerprint)).size !== roots.length
  ) invalid();
  return Object.freeze({ ...item, hostRoots: Object.freeze(roots) });
}

function validateManifestAsset(value, { allowedAssetPrefix, helperBytes }) {
  const item = exact(value, ASSET_KEYS);
  const signature = exact(item.nativeSignature, SIGNATURE_KEYS);
  const execution = exact(item.execution, EXECUTION_KEYS);
  if (
    item.platform !== "node" || item.arch !== "any" ||
    item.upstreamSupport !== "node24_portable" ||
    item.filename !== HELPER_FILENAME ||
    item.url !== `${allowedAssetPrefix}${HELPER_FILENAME}` ||
    !DECIMAL.test(item.byteLength) || BigInt(item.byteLength) < 1n ||
    !SHA256.test(item.sha256) ||
    signature.type !== "none" || signature.verified !== null ||
    signature.signer !== null || signature.timestamp !== null ||
    signature.notarized !== null ||
    execution.verified !== true || execution.platform !== "linux" ||
    execution.arch !== "x64" || execution.exitCode !== "0" ||
    !SHA256.test(execution.publicOutputSha256)
  ) invalid();
  if (
    String(helperBytes.length) !== item.byteLength ||
    createHash("sha256").update(helperBytes).digest("hex") !== item.sha256
  ) invalid();
  return Object.freeze(item);
}

export function verifyPinnedAssetBytes({ pin, manifestBytes, helperBytes } = {}) {
  const validatedPin = validatePin(pin);
  if (
    !Buffer.isBuffer(manifestBytes) || manifestBytes.length < 1 ||
    !Buffer.isBuffer(helperBytes) || helperBytes.length < 1 ||
    helperBytes.length > 1024 * 1024 ||
    createHash("sha256").update(manifestBytes).digest("hex") !== validatedPin.manifestDigest
  ) invalid();
  let manifest;
  try { manifest = JSON.parse(manifestBytes.toString("utf8")); } catch { invalid(); }
  const item = exact(manifest, MANIFEST_KEYS);
  if (
    item.schema !== "clockchain.agent-handshake-release-manifest/v1" ||
    item.version !== AGENT_HANDSHAKE_HELPER_VERSION ||
    item.sourceCommit !== validatedPin.sourceCommit ||
    !NODE_RUNTIME.test(item.nodeRuntime) ||
    !Array.isArray(item.assets) || item.assets.length !== 1
  ) invalid();
  try {
    if (!manifestBytes.equals(canonicalBytes(item))) invalid();
  } catch { invalid(); }
  validateManifestAsset(item.assets[0], {
    allowedAssetPrefix: validatedPin.allowedAssetPrefix,
    helperBytes,
  });
  return Object.freeze({
    helperBytes,
    helperSha256: item.assets[0].sha256,
    manifestBytes,
    pin: validatedPin,
  });
}

export function loadPinnedAssets({ assetDir, helperPath, manifestPath, pin, pinPath } = {}) {
  if (typeof assetDir !== "string" || !isAbsolute(resolve(assetDir))) invalid();
  const root = resolve(assetDir);
  const resolvedManifestPath = manifestPath !== undefined ? resolve(manifestPath) : join(root, MANIFEST_FILENAME);
  const resolvedHelperPath = helperPath !== undefined ? resolve(helperPath) : join(root, HELPER_FILENAME);
  const resolvedPinPath = pinPath !== undefined ? resolve(pinPath) : join(root, PIN_FILENAME);
  let pinValue = pin;
  if (pinValue === undefined) {
    try { pinValue = JSON.parse(readFileSync(resolvedPinPath, "utf8")); } catch { invalid(); }
  }
  let manifestBytes;
  let helperBytes;
  try {
    manifestBytes = readFileSync(resolvedManifestPath);
    helperBytes = readFileSync(resolvedHelperPath);
  } catch { invalid(); }
  const verified = verifyPinnedAssetBytes({ pin: pinValue, manifestBytes, helperBytes });
  return Object.freeze({
    ...verified,
    helperPath: resolvedHelperPath,
    manifestPath: resolvedManifestPath,
  });
}

// --- helper step validation --------------------------------------------------

function payloadBytes(encoded) {
  if (!BASE64URL.test(encoded)) invalid();
  const bytes = Buffer.from(encoded, "base64url");
  if (
    bytes.length < 1 || bytes.length > MAX_PAYLOAD_BYTES ||
    bytes.toString("base64url") !== encoded
  ) invalid();
  let record;
  try { record = JSON.parse(bytes.toString("utf8")); } catch { invalid(); }
  return record;
}

// Mirrors the requestBinding checks in the harness recorder, plus the
// coordinator-emitted schema/helperVersion binds the recorder leaves to the
// signed envelope.
function validatePayloadBinding(step, encoded) {
  const record = payloadBytes(encoded);
  if (!isPlain(record)) invalid();
  if (step.operation === "policy") {
    let policy;
    try { policy = validateLocalPolicy(record); } catch { invalid(); }
    if (policy.role !== step.role) invalid();
    if (step.policyDigest !== null && step.policyDigest !== localPolicyDigest(policy)) invalid();
    return;
  }
  if (
    (step.operation === "sign"
      ? record.schema !== SIGNING_REQUEST_SCHEMA || !SIGNING_OPERATIONS.includes(record.operation)
      : record.schema !== CERTIFICATE_VERIFICATION_SCHEMA) ||
    record.helperVersion !== AGENT_HANDSHAKE_HELPER_VERSION ||
    record.role !== step.role || record.sessionId !== step.sessionId ||
    record.externalBusinessActionPerformed !== false ||
    (step.policyDigest !== null && record.policyDigest !== step.policyDigest)
  ) invalid();
}

export function validateHelperStep(step, { manifestDigest } = {}) {
  if (!SHA256.test(manifestDigest)) invalid();
  const item = exact(
    step,
    STEP_KEYS,
    STEP_KEYS.filter((key) => !STEP_OPTIONAL_KEYS.includes(key)),
  );
  const shellCommand = item.shellCommand;
  if (typeof shellCommand !== "string" || shellCommand.length < 1) invalid();
  if (
    item.approvalTool !== ADAPTER_APPROVAL_TOOL ||
    !OPERATIONS.includes(item.operation) || !ROLES.includes(item.role) ||
    !UUID.test(item.sessionId) ||
    item.commandLength !== Buffer.byteLength(shellCommand) ||
    item.commandSha256 !== createHash("sha256").update(shellCommand).digest("hex") ||
    (item.shellCommandFetch !== undefined && typeof item.shellCommandFetch !== "string") ||
    (item.policyDigest !== undefined && !SHA256.test(item.policyDigest))
  ) invalid();
  const lead = `node --input-type=commonjs --eval '${VERIFIED_HELPER_BOOTSTRAP}' `;
  const assetArgs = ` ./${MANIFEST_FILENAME} ./${HELPER_FILENAME} `;
  if (!shellCommand.startsWith(lead)) invalid();
  const pinned = shellCommand.slice(lead.length);
  const stepDigest = pinned.slice(0, 64);
  if (!SHA256.test(stepDigest) || !pinned.slice(64).startsWith(assetArgs)) invalid();
  const suffix = pinned.slice(64 + assetArgs.length);
  const match = SUFFIX_PATTERN.exec(suffix);
  if (
    match === null || match[1] !== item.operation ||
    match[2] !== item.sessionId || match[3] !== item.role
  ) invalid();
  const encoded = match[5];
  if (PAYLOAD_OPERATIONS.includes(item.operation) !== (encoded !== undefined)) invalid();
  const staged = Object.freeze({
    commandLength: item.commandLength,
    commandSha256: item.commandSha256,
    operation: item.operation,
    payloadBase64url: encoded ?? null,
    policyDigest: item.policyDigest ?? null,
    role: item.role,
    sessionId: item.sessionId,
    stateDirShell: `${TMPDIR_TOKEN}/.clockchain/handshakes/${item.sessionId}/${item.role}`,
  });
  // policyDigest may bind only where the payload can carry it; an unverifiable
  // claim on a payload-less or digest-less step fails closed.
  if (staged.policyDigest !== null && !["policy", "sign"].includes(staged.operation)) invalid();
  // Every structural check has passed, so a differing embedded digest means
  // the step was minted against a different release pin — a different
  // manifestDigest, helper version, or allowedAssetPrefix all surface here.
  // Refuse as always, but with the distinct upgrade-directed text: it may be
  // an adapter that is behind, or a corrupt/forged step, and the message
  // covers both.
  if (stepDigest !== manifestDigest) releaseMismatch();
  if (encoded !== undefined) validatePayloadBinding(staged, encoded);
  return staged;
}

function collectHelperSteps(value, depth, out) {
  if (depth > MAX_WALK_DEPTH || value === null || typeof value !== "object") return;
  if (Array.isArray(value)) {
    for (const entry of value) collectHelperSteps(entry, depth + 1, out);
    return;
  }
  if (Object.hasOwn(value, "helperStep")) out.push(value.helperStep);
  if (Object.hasOwn(value, "helperSteps")) {
    if (!Array.isArray(value.helperSteps)) invalid();
    for (const entry of value.helperSteps) out.push(entry);
  }
  for (const key of Reflect.ownKeys(value)) {
    if (typeof key === "string") collectHelperSteps(value[key], depth + 1, out);
  }
}

// Coordinator responses embed runnable shell (shellCommand, the digest-bound
// shellCommandFetch download-and-exec chain, stateDirectoryCommand) for
// adapter-less clients. Under the adapter those bytes are staged privately and
// executed through authorize_local_action, so the agent-visible copy must not
// carry them: a ready-to-run shell chain inside a tool result is a
// social-engineering-shaped surface that could induce a less careful agent to
// bypass the adapter's verification boundary. commandSha256/commandLength stay
// — they attest to the staged step without being executable.
const WITHHELD_COMMAND =
  "[withheld by clockchain-local-adapter: this digest-bound step is staged " +
  "privately; execute it by calling authorize_local_action]";
const EXECUTABLE_KEYS = Object.freeze(new Set([
  "shellCommand", "shellCommandFetch", "stateDirectoryCommand",
]));

function scrubExecutableFields(value, depth = 0) {
  if (depth > MAX_WALK_DEPTH || value === null || typeof value !== "object") return false;
  if (Array.isArray(value)) {
    let changed = false;
    for (const entry of value) changed = scrubExecutableFields(entry, depth + 1) || changed;
    return changed;
  }
  let changed = false;
  for (const key of Object.keys(value)) {
    if (EXECUTABLE_KEYS.has(key) && typeof value[key] === "string") {
      value[key] = WITHHELD_COMMAND;
      changed = true;
    } else {
      changed = scrubExecutableFields(value[key], depth + 1) || changed;
    }
  }
  return changed;
}

// --- upstream proxy -----------------------------------------------------------

function parseUpstreamBody(text, contentType) {
  if (typeof text !== "string" || text.length === 0) invalid();
  if (!contentType?.includes("text/event-stream")) {
    try { return [JSON.parse(text)]; } catch { invalid(); }
  }
  // SSE: each blank-line-terminated event joins its data: lines with "\n".
  const messages = [];
  let data = null;
  for (const line of text.split(/\r?\n/)) {
    if (line.startsWith("data:")) {
      data = (data ?? "") + (data === null ? "" : "\n") + line.slice(5).replace(/^ /, "");
      continue;
    }
    if (line.trim() === "") {
      if (data !== null) { messages.push(data); data = null; }
    }
  }
  if (data !== null) messages.push(data);
  const parsed = [];
  for (const payload of messages) {
    try { parsed.push(JSON.parse(payload)); } catch { invalid(); }
  }
  return parsed;
}

// --- server --------------------------------------------------------------------

function helperErrorCode(stderr) {
  if (typeof stderr === "string" && stderr.trim().length > 0 && Buffer.byteLength(stderr) < 4096) {
    try {
      const parsed = JSON.parse(stderr.trim());
      const code = isPlain(parsed?.error) ? parsed.error.code : parsed?.code;
      if (typeof code === "string" && HELPER_ERROR_CODE.test(code)) return code;
    } catch { /* fall through to the generic refusal */ }
  }
  return "Clockchain local adapter refused the action.";
}

async function defaultRunHelper({ args, file, maxBufferBytes, timeoutMs }) {
  try {
    const { stdout, stderr } = await execFileAsync(file, args, {
      encoding: "utf8",
      env: process.env,
      maxBuffer: maxBufferBytes,
      timeout: timeoutMs,
    });
    return Object.freeze({
      code: 0,
      stderr: typeof stderr === "string" ? stderr : "",
      stdout: typeof stdout === "string" ? stdout : "",
    });
  } catch (error) {
    return Object.freeze({
      code: Number.isSafeInteger(error?.code) && error.code !== 0 ? error.code : 1,
      stderr: typeof error?.stderr === "string" ? error.stderr : "",
      stdout: typeof error?.stdout === "string" ? error.stdout : "",
    });
  }
}

export function createLocalAdapterServer(options = {}) {
  const input = exact(options, [
    "assetDir", "assets", "contractBind", "endpoint", "fetchImpl", "helperPath", "input",
    "invitationRefs", "inviteBudget", "inviteTerms", "manifestPath", "now", "output", "pin", "pinPath", "runHelper",
    "testOnlyBuild", "tmpdir",
  ], []);
  const assets = input.assets !== undefined
    ? (() => {
        const value = exact(input.assets, [
          "helperBytes", "helperPath", "helperSha256", "manifestBytes", "manifestPath", "pin",
        ]);
        if (
          !Buffer.isBuffer(value.helperBytes) || !Buffer.isBuffer(value.manifestBytes) ||
          typeof value.helperPath !== "string" || typeof value.manifestPath !== "string" ||
          !SHA256.test(value.helperSha256)
        ) invalid();
        return Object.freeze({ ...value, pin: validatePin(value.pin) });
      })()
    : loadPinnedAssets({
        assetDir: input.assetDir,
        helperPath: input.helperPath,
        manifestPath: input.manifestPath,
        pin: input.pin,
        pinPath: input.pinPath,
      });
  const pin = assets.pin;
  const endpoint = input.endpoint ??
    process.env.CLOCKCHAIN_LOCAL_ADAPTER_ENDPOINT ??
    ADAPTER_DEFAULT_ENDPOINT;
  if (typeof endpoint !== "string" || !/^https:\/\//.test(endpoint)) invalid();
  // Never-ship gate (B3-2): a test-only helper runs only under its own build
  // record, a pinned non-production root and a loopback test endpoint; a
  // release configuration never runs a test-only helper. Throws on any mix.
  gateNeverShip({ helperBytes: assets.helperBytes, pin, endpoint, testOnlyBuild: input.testOnlyBuild });
  const fetchImpl = input.fetchImpl ?? globalThis.fetch;
  if (typeof fetchImpl !== "function") invalid();
  const runHelper = input.runHelper ?? defaultRunHelper;
  if (typeof runHelper !== "function") invalid();
  if (input.now !== undefined && typeof input.now !== "function") invalid();
  if (input.tmpdir !== undefined && typeof input.tmpdir !== "string") invalid();
  const now = input.now ?? Date.now;
  // L1: the company's pinned tokenKeyId/serverKeyId lists, from the option
  // (tests, embedders) or the adapter's environment (launchd plist).
  const contractBindPins = input.contractBind !== undefined
    ? contractBindPinsOption(input.contractBind)
    : contractBindPinsFromEnv(process.env);
  const tmpRoot = resolve(input.tmpdir ?? process.env.TMPDIR ?? osTmpdir());
  // 2.1.12 refs mode: the invitation never reaches the model. Off by default
  // for the published adapter (a human-relayed invite still needs the raw
  // value); the fleet's launchd plist sets INVITATION_REFS_ENV=1.
  if (input.invitationRefs !== undefined && typeof input.invitationRefs !== "boolean") invalid();
  const invitationRefs = input.invitationRefs ?? process.env[INVITATION_REFS_ENV] === "1";
  const queue = [];
  // 2.1.13: issued refs not yet consumed by the signer's seal_to, and the
  // sessions abandoned because their ref expired undelivered. Entries are
  // { ref, sessionId, roleAccess, expMs }.
  const undelivered = new Map();
  const abandoned = new Map();
  // 2.2.0: role accesses and helper results this adapter holds, the invite
  // terms pin, and the forwarding journal (fill-from-local.mjs).
  const localValues = createLocalValues({ now });
  const inviteTermsPin = resolveInviteTerms({
    option: input.inviteTerms,
    env: process.env,
    endpoint,
    defaultEndpoint: ADAPTER_DEFAULT_ENDPOINT,
  });
  const forwardJournal = createForwardJournal({ tmpRoot, now });
  // Per-run invite budget (fill-from-local.mjs resolveInviteBudget): checked and
  // reserved synchronously right before an invite is forwarded, so concurrent
  // calls can never overshoot; the base is this epoch's journal, read once.
  const inviteBudget = resolveInviteBudget({ option: input.inviteBudget, env: process.env });
  let invitesBase = null;
  let invitesReserved = 0;
  async function reserveInvite() {
    if (inviteBudget.invalid === true) return { code: LOCAL_FILL_REFUSALS.budgetPin };
    if (inviteBudget.budget === null) return null;
    invitesBase ??= forwardJournal.count(INVITE_TOOL).catch(() => 0);
    const base = await invitesBase;
    const sent = base + invitesReserved;
    if (sent >= inviteBudget.budget) return { code: LOCAL_FILL_REFUSALS.inviteBudget, detail: { sent, budget: inviteBudget.budget } };
    invitesReserved += 1;
    return null;
  }
  let upstreamId = 0;
  let upstreamInit = null;
  // The coordinator's MCP session (initialize response header), sent on every
  // later upstream request so the call is not served on the stateless path
  // (which carries no session id into the receipt). null = none issued.
  let upstreamSessionId = null;
  let pendingExecution = Promise.resolve();
  // C-ADP-1 (TB/LLD.md §8.4): fill and submit are serialized per session, and
  // a staged step whose digest was already handed to the helper is never
  // staged again by this process. Steps that executed successfully are seeded
  // once from this epoch's journal, so a restart keeps refusing those too.
  const sessionLocks = new Map();
  const executedDigests = new Set();
  let executedSeed = null;

  function withSessionLock(key, fn) {
    const previous = sessionLocks.get(key) ?? Promise.resolve();
    const run = previous.then(() => fn());
    const tail = run.then(() => {}, () => {});
    sessionLocks.set(key, tail);
    void tail.then(() => { if (sessionLocks.get(key) === tail) sessionLocks.delete(key); });
    return run;
  }

  // Resolves true once the journal's executed digests are loaded; false when
  // the journal exists but cannot be read (staging then fails closed).
  function seedExecutedDigests() {
    executedSeed ??= forwardJournal.executedStepDigests().then((digests) => {
      for (const digest of digests) executedDigests.add(digest);
      return true;
    }, () => false);
    return executedSeed;
  }

  const UNKNOWN_SESSION = /unknown[\s_-]*session|session[\s_-]*(not[\s_-]*found|expired|unknown)|invalid[\s_-]*session/i;

  async function upstreamRequest(method, params, { notification = false, retried = false } = {}) {
    const id = ++upstreamId;
    const body = notification
      ? { jsonrpc: "2.0", method, ...(params !== undefined ? { params } : {}) }
      : { jsonrpc: "2.0", id, method, ...(params !== undefined ? { params } : {}) };
    const sentSession = method === "initialize" ? null : upstreamSessionId;
    let response;
    try {
      response = await fetchImpl(endpoint, {
        method: "POST",
        headers: {
          accept: "application/json, text/event-stream",
          "content-type": "application/json",
          // Opt-in receipt nonce echo: the coordinator (when its receipts are on)
          // returns this call's serverNonce in result._meta["clockchain/receipt"].
          "x-clockchain-receipt": "1",
          // Only when the server issued one: old servers stay compatible.
          ...(sentSession !== null ? { "mcp-session-id": sentSession } : {}),
        },
        body: JSON.stringify(body),
        signal: AbortSignal.timeout(UPSTREAM_RPC_BUDGET_MS),
      });
    } catch (error) {
      if (UPSTREAM_UNREACHED_CAUSES.has(error?.cause?.code) || UPSTREAM_UNREACHED_CAUSES.has(error?.code)) {
        throw new UpstreamUnreachedError("connection refused");
      }
      throw error;
    }
    // A stored session the server no longer knows: re-initialize once and replay.
    const reinitialize = async () => {
      upstreamSessionId = null;
      upstreamInit = null;
      await upstreamInitialize();
      return upstreamRequest(method, params, { notification, retried: true });
    };
    if (!response?.ok) {
      if (UPSTREAM_UNREACHED_STATUSES.has(response?.status)) throw new UpstreamUnreachedError(`HTTP ${response.status}`);
      if (sentSession !== null && !retried && response?.status === 404) return reinitialize();
      invalid();
    }
    const text = await response.text();
    if (method === "initialize") {
      const issued = response.headers?.get?.("mcp-session-id");
      if (typeof issued === "string" && issued.length > 0) upstreamSessionId = issued;
    }
    if (notification) return null;
    const messages = parseUpstreamBody(text, response.headers?.get?.("content-type") ?? "");
    const envelope = messages.find((message) => isPlain(message) && message.id === id);
    if (
      envelope === undefined || envelope.jsonrpc !== "2.0" ||
      (envelope.result === undefined) === (envelope.error === undefined)
    ) invalid();
    if (
      sentSession !== null && !retried && envelope.error !== undefined &&
      UNKNOWN_SESSION.test(String(envelope.error?.message ?? ""))
    ) return reinitialize();
    return envelope;
  }

  function upstreamInitialize(params) {
    if (upstreamInit === null) {
      upstreamInit = upstreamRequest("initialize", params ?? {
        protocolVersion: "2024-11-05",
        capabilities: {},
        clientInfo: { name: ADAPTER_NAME, version: pin.version },
      }).then((envelope) => {
        if (envelope.error !== undefined) return null;
        // Best-effort session notification; the endpoint is stateless, so a
        // failure here must not poison the cached initialize result.
        void upstreamRequest("notifications/initialized", {}, { notification: true }).catch(() => {});
        return isPlain(envelope.result) ? envelope.result : null;
      }).catch(() => null);
    }
    return upstreamInit;
  }

  // `meta` collects the digests this result staged and the ones it carried
  // that were already executed (C-ADP-1), for the forward line.
  function stageToolResult(result, { meta = {}, seeded = true } = {}) {
    if (!isPlain(result) || !Array.isArray(result.content)) return;
    const parsedItems = [];
    const candidates = [];
    for (const item of result.content) {
      if (!isPlain(item) || item.type !== "text" || typeof item.text !== "string") continue;
      let parsed;
      try { parsed = JSON.parse(item.text); } catch { continue; }
      parsedItems.push({ item, parsed });
      collectHelperSteps(parsed, 0, candidates);
    }
    // Validate every candidate before any scrub or enqueue: an invalid step
    // refuses the whole response, so the withheld copy is never reached.
    const staged = candidates.map((candidate) =>
      validateHelperStep(candidate, { manifestDigest: pin.manifestDigest }));
    if (staged.length > 0 && !seeded) invalid();
    // Where the steps came from: the receipt of the call that carried them.
    const receiptHash = receiptHashFromResult(result);
    const nonce = serverNonceFromResult(result);
    for (const step of staged) {
      // C-ADP-1: an executed step is never staged again, whatever re-issues it.
      if (executedDigests.has(step.commandSha256)) {
        (meta.skippedExecuted ??= []).push(step.commandSha256);
        continue;
      }
      // The coordinator re-issues an unchanged localAction on each poll while a
      // step stays pending — the same byte-identical command is the same
      // digest-bound action, so an already-staged duplicate must not shift the
      // queue head away from the step the caller just read.
      if (queue.some((pending) => pending.commandSha256 === step.commandSha256)) continue;
      if (queue.length >= MAX_STAGED_STEPS) invalid();
      const localActionSource = Object.freeze(receiptHash !== null
        ? { sessionId: step.sessionId, receiptHash }
        : { sessionId: step.sessionId, nonce });
      queue.push(Object.freeze({ ...step, stagedAtMs: now(), localActionSource }));
      (meta.staged ??= []).push(step.commandSha256);
    }
    for (const { item, parsed } of parsedItems) {
      if (scrubExecutableFields(parsed)) item.text = JSON.stringify(parsed);
    }
  }

  function textResult(text, isError = false) {
    return Object.freeze({
      content: Object.freeze([Object.freeze({ type: "text", text })]),
      ...(isError ? { isError: true } : {}),
    });
  }

  function resolveStateDir(step) {
    if (!step.stateDirShell.startsWith(`${TMPDIR_TOKEN}/`)) invalid();
    const stateDir = resolve(tmpRoot + step.stateDirShell.slice(TMPDIR_TOKEN.length));
    const offset = relative(tmpRoot, stateDir);
    if (
      offset === "" || offset.startsWith("..") || isAbsolute(offset) ||
      !stateDir.endsWith(`/.clockchain/handshakes/${step.sessionId}/${step.role}`)
    ) invalid();
    mkdirSync(stateDir, { recursive: true, mode: 0o700 });
    return stateDir;
  }

  // Tool-call-time re-verification: the spawned bootstrap re-checks both
  // digests inside the child, so this gate exists to refuse before spawn.
  function verifyAssetsNow() {
    let manifestBytes;
    let helperBytes;
    try {
      manifestBytes = readFileSync(assets.manifestPath);
      helperBytes = readFileSync(assets.helperPath);
    } catch { invalid(); }
    if (
      createHash("sha256").update(manifestBytes).digest("hex") !== pin.manifestDigest ||
      createHash("sha256").update(helperBytes).digest("hex") !== assets.helperSha256
    ) invalid();
  }

  function dropStagedSteps(sessionId) {
    if (sessionId === null) return;
    for (let index = queue.length - 1; index >= 0; index -= 1) {
      if (queue[index].sessionId === sessionId && queue[index].role === "initiator") queue.splice(index, 1);
    }
  }

  async function abandonSession(entry) {
    undelivered.delete(entry.ref);
    abandoned.set(entry.ref, entry);
    // Bounded: only the most recent abandoned sessions keep their refusal.
    while (abandoned.size > MAX_STAGED_STEPS) abandoned.delete(abandoned.keys().next().value);
    dropStagedSteps(entry.sessionId);
    await discardIssuedInvitationRef({ tmpRoot, ref: entry.ref });
  }

  // Resolve the delivery state of the issued ref for a session (by sessionId
  // or by its Initiator roleAccess). null = nothing to guard.
  async function deliveryGuard({ sessionId = null, access = null }) {
    if (!invitationRefs) return null;
    const matches = (entry) =>
      (sessionId !== null && entry.sessionId === sessionId) ||
      (access !== null && entry.roleAccess === access);
    for (const entry of abandoned.values()) if (matches(entry)) return { kind: "expired", entry };
    for (const entry of [...undelivered.values()]) {
      if (!matches(entry)) continue;
      const state = await issuedInvitationRefState({ tmpRoot, ref: entry.ref, expMs: entry.expMs, nowMs: now() });
      if (state === "consumed") { undelivered.delete(entry.ref); continue; }
      if (state === "pending") return { kind: "pending", entry };
      await abandonSession(entry);
      return { kind: "expired", entry };
    }
    return null;
  }

  // Before issuing a new ref: settle every tracked one, so the store sweep in
  // putInvitationRef (which deletes expired records) is never mistaken for a
  // delivery of a session that expired unnoticed.
  async function settleIssuedRefs() {
    for (const entry of [...undelivered.values()]) {
      const state = await issuedInvitationRefState({ tmpRoot, ref: entry.ref, expMs: entry.expMs, nowMs: now() });
      if (state === "consumed") undelivered.delete(entry.ref);
      else if (state === "expired") await abandonSession(entry);
    }
  }

  // `ctx` tells the caller which step this call took and whether the helper
  // was spawned for it, also when this function throws (C-ADP-1 local line).
  async function executeStagedAction(ctx = {}) {
    while (queue.length > 0 && now() - queue[0].stagedAtMs > STAGED_STEP_TTL_MS) queue.shift();
    const head = queue[0];
    if (head !== undefined && head.role === "initiator") {
      const guard = await deliveryGuard({ sessionId: head.sessionId });
      if (guard?.kind === "pending") return textResult(deliverFirstText(guard.entry, { staged: true }), true);
      if (guard?.kind === "expired") {
        dropStagedSteps(head.sessionId);
        return textResult(deliverExpiredText(guard.entry), true);
      }
    }
    const step = queue.shift();
    if (step === undefined) {
      return textResult("Clockchain local adapter has no staged action to execute.", true);
    }
    ctx.step = step;
    // C-ADP-1: from the moment it is taken off the queue the step counts as
    // executed, so a poll that re-issues it while this run waits for the
    // session lock cannot stage it again; it is never staged again even when
    // the helper fails (a retry needs a fresh step from the coordinator).
    executedDigests.add(step.commandSha256);
    // The helper run and the values it leaves behind are serialized with that
    // session's fill-and-submit calls.
    return withSessionLock(step.sessionId, () => runStagedStep(step, ctx));
  }

  async function runStagedStep(step, ctx) {
    verifyAssetsNow();
    const stateDir = resolveStateDir(step);
    const args = [
      "--input-type=commonjs", "--eval", VERIFIED_HELPER_BOOTSTRAP,
      pin.manifestDigest, assets.manifestPath, assets.helperPath,
      step.operation, "--state-dir", stateDir,
    ];
    if (step.payloadBase64url !== null) args.push("--payload-base64url", step.payloadBase64url);
    ctx.spawned = true;
    const outcome = await runHelper({
      args: Object.freeze(args),
      // The helper must run under real Node >=24. process.execPath is that
      // Node under the stdio entry; under a compiled binary (e.g. bun) it is
      // the adapter itself, so an explicit override exists.
      file: process.env.CLOCKCHAIN_LOCAL_ADAPTER_NODE ?? process.execPath,
      maxBufferBytes: HELPER_MAX_OUTPUT_BYTES,
      timeoutMs: HELPER_RUN_BUDGET_MS,
    });
    if (!isPlain(outcome) || outcome.code !== 0) {
      ctx.failed = true;
      return textResult(helperErrorCode(outcome?.stderr), true);
    }
    const text = typeof outcome.stdout === "string" ? outcome.stdout.trim() : "";
    if (text.length < 2 || text.length > HELPER_MAX_OUTPUT_BYTES) invalid();
    let record;
    try { record = JSON.parse(text); } catch { invalid(); }
    if (
      !isPlain(record) || record.schema !== CLI_RESULT_SCHEMA ||
      record.helperVersion !== pin.version || record.operation !== step.operation
    ) invalid();
    // L3: remember a verified session (write-once) for sign_agent_contract_bind.
    // Best-effort: it never changes this step's result.
    const verifiedSession = verifiedSessionFromStep({ step, helperResult: record });
    if (verifiedSession !== null) {
      await recordVerifiedSession({
        stateDir,
        sessionId: verifiedSession.sessionId,
        role: verifiedSession.role,
        sessionKeyAddress: verifiedSession.sessionKeyAddress,
        expiresAtMs: Number(verifiedSession.expiresAtMs),
      });
    }
    // 2.2.0: keep the values the handshake tools need, and show the model a
    // copy without the signatures, the checkpoint or any long hex.
    let signRequest = null;
    if (step.operation === "sign" && step.payloadBase64url !== null) {
      try { signRequest = JSON.parse(Buffer.from(step.payloadBase64url, "base64url").toString("utf8")); } catch { signRequest = null; }
    }
    localValues.recordHelperResult({ step, record, signRequest });
    return textResult(JSON.stringify(redactHelperResult(record, {
      signingOperation: typeof signRequest?.operation === "string" ? signRequest.operation : null,
    })));
  }

  // C-ADP-1: one local line per local tool call, on the forward journal's chain.
  function journalLocal({ tool, sessionId = null, role = null, operation = null, step = null, outcome, response }) {
    return forwardJournal.append({
      kind: JOURNAL_KINDS.local,
      tool,
      sessionId: step?.sessionId ?? sessionId,
      role: step?.role ?? role,
      operation: step?.operation ?? operation,
      stagedStepDigest: step?.commandSha256 ?? null,
      localActionSource: step?.localActionSource ?? null,
      outcome,
      resultDigest: resultDigest(response.error !== undefined ? response.error : response.result),
    });
  }

  async function callAdapterTool(params) {
    if (!isPlain(params)) return { error: { code: -32602, message: "invalid params" } };
    const args = params.arguments;
    if (
      args !== undefined &&
      (!isPlain(args) || Reflect.ownKeys(args).length !== 0)
    ) {
      const response = { error: { code: -32602, message: "tool takes no arguments" } };
      await journalLocal({ tool: ADAPTER_TOOL, outcome: LOCAL_OUTCOMES.refused, response });
      return response;
    }
    // Serialize executions: a second call while one is in flight must see the
    // queue state the first execution left behind, never a shared head. The
    // local line is written inside the same chain, so the journal keeps the
    // execution order.
    const run = pendingExecution.then(async () => {
      const ctx = {};
      let response;
      try {
        response = { result: await executeStagedAction(ctx) };
      } catch {
        response = { result: textResult(GENERIC_REFUSAL, true) };
        ctx.failed = true;
      }
      const outcome = ctx.spawned !== true ? LOCAL_OUTCOMES.refused
        : ctx.failed === true ? LOCAL_OUTCOMES.error : LOCAL_OUTCOMES.ok;
      await journalLocal({ tool: ADAPTER_TOOL, step: ctx.step ?? null, outcome, response });
      return response;
    });
    pendingExecution = run.catch(() => {});
    try {
      return await run;
    } catch {
      return { result: textResult(GENERIC_REFUSAL, true) };
    }
  }

  // sign_agent_contract_bind: a purely local tool (never proxied upstream).
  // Every refusal is one of the fixed contract-bind codes; arbitrary error
  // text never crosses this boundary.
  async function callContractBindTool(params) {
    const args = isPlain(params.arguments) ? params.arguments : {};
    const line = {
      tool: CONTRACT_BIND_TOOL,
      sessionId: typeof args.runId === "string" && UUID.test(args.runId) ? args.runId : null,
      role: ROLES.includes(args.side) ? args.side : null,
      operation: "contract-bind",
    };
    let response;
    let outcome;
    try {
      const output = await signContractBindStatement(params.arguments, {
        nowMs: now(),
        serverKeyIds: contractBindPins.serverKeyIds,
        tmpRoot,
        tokenKeyIds: contractBindPins.tokenKeyIds,
      });
      response = { result: textResult(JSON.stringify(output)) };
      outcome = LOCAL_OUTCOMES.ok;
    } catch (error) {
      const code = error instanceof ContractBindRefusal
        ? error.code
        : CONTRACT_BIND_REFUSALS.signing;
      response = { result: textResult(contractBindRefusalText(code), true) };
      outcome = LOCAL_OUTCOMES.refused;
    }
    await journalLocal({ ...line, outcome, response });
    return response;
  }

  async function handleToolsList(id, params) {
    try {
      const envelope = await upstreamRequest("tools/list", params);
      if (envelope.error !== undefined) return { jsonrpc: "2.0", id, error: envelope.error };
      const result = isPlain(envelope.result) ? envelope.result : {};
      const tools = Array.isArray(result.tools) ? result.tools : [];
      return {
        jsonrpc: "2.0",
        id,
        result: {
          ...result,
          tools: [
            ...tools.map((tool) => withLocalFills(withInvitationRef(tool, invitationRefs), {
              inviteTerms: inviteTermsPin.terms ?? null,
            })),
            ...LOCAL_TOOL_DEFINITIONS,
          ],
        },
      };
    } catch {
      // An unreachable coordinator must not hide the one tool that is local.
      return {
        jsonrpc: "2.0",
        id,
        result: { tools: [...LOCAL_TOOL_DEFINITIONS] },
      };
    }
  }

  async function handleToolsCall(id, params) {
    if (!isPlain(params) || typeof params.name !== "string") {
      return { jsonrpc: "2.0", id, error: { code: -32602, message: "invalid params" } };
    }
    if (params.name === ADAPTER_TOOL) {
      const outcome = await callAdapterTool(params);
      return { jsonrpc: "2.0", id, ...outcome };
    }
    if (params.name === CONTRACT_BIND_TOOL) {
      const outcome = await callContractBindTool(params);
      return { jsonrpc: "2.0", id, ...outcome };
    }
    const modelArgs = modelArgsOf(params);
    if (params.name === INVITATION_TOOL) {
      const args = isPlain(params.arguments) ? params.arguments : {};
      if (Object.hasOwn(args, "invitationRef")) return acceptByRef(id, params, args);
      if (invitationRefs) return refuseLocal(id, params.name, modelArgs, INVITATION_BY_REFERENCE_REQUIRED);
      const refusal = checkInvitationShape(args.invitation);
      if (refusal !== null) return refuseLocal(id, params.name, modelArgs, refusal);
    }
    if (params.name === INVITE_TOOL) {
      if (inviteTermsPin.invalid === true) {
        return refuseLocal(id, params.name, modelArgs, localFillRefusalText(LOCAL_FILL_REFUSALS.termsPin));
      }
      let plan = null;
      const args = isPlain(params.arguments) ? params.arguments : {};
      if (inviteTermsPin.terms !== null) {
        plan = planInviteFill({ args, terms: inviteTermsPin.terms });
        if (plan.refusal !== undefined) {
          return refuseLocal(id, params.name, modelArgs, localFillRefusalText(plan.refusal.code, plan.refusal.detail));
        }
      }
      // Only a call that would really be forwarded spends the budget — and an
      // invite the coordinator refused as transient gives it back (it minted
      // nothing; its journal line says "transient", so a restart recounts the same).
      const over = await reserveInvite();
      if (over !== null) return refuseLocal(id, params.name, modelArgs, localFillRefusalText(over.code, over.detail));
      const response = await forwardFilled(id, params, modelArgs, plan ?? NOTHING_FILLED);
      if (inviteBudget.budget !== null && isTransientInviteRefusal(response)) invitesReserved -= 1;
      return response;
    }
    if (!ACCESS_TOOLS.has(params.name)) return forwardFilled(id, params, modelArgs, NOTHING_FILLED);
    // 2.2.0: resolve the session — the access the model passed, or the one
    // live access this adapter holds — before the deliver-first guard, so an
    // omitted access is guarded exactly like an explicit one.
    const args = isPlain(params.arguments) ? params.arguments : {};
    let entry;
    let accessFilled = false;
    if (typeof args.access === "string") {
      entry = localValues.sessionFor(args.access);
    } else if (!Object.hasOwn(args, "access")) {
      const live = localValues.liveSessions(isAbandonedSession);
      if (live.length > 1) {
        return refuseLocal(id, params.name, modelArgs,
          localFillRefusalText(LOCAL_FILL_REFUSALS.ambiguous, { tool: params.name, count: live.length }));
      }
      // No live session held: nothing to fill, forwarded as given (below).
      if (live.length === 1) {
        entry = live[0];
        accessFilled = true;
      }
    }
    const guarded = await deliveryGuardRefusal(params.name, accessFilled ? { ...args, access: entry.access } : args);
    if (guarded !== null) return refuseLocal(id, params.name, modelArgs, guarded);
    // An access this adapter never saw is forwarded untouched: the coordinator
    // is its authority, and the adapter holds no values for it.
    if (entry === undefined) return forwardFilled(id, params, modelArgs, NOTHING_FILLED);
    // C-ADP-1: plan, forward and spend under the session's lock, so two calls
    // of one session never fill the same held value, and a fill never reads
    // the values while that session's helper step is still running.
    return withSessionLock(entry.sessionId ?? `access:${entry.access}`, async () => {
      const plan = planAccessFill({
        tool: params.name,
        args,
        entry,
        accessFilled,
        localValues,
        helperVersion: pin.version,
      });
      if (plan.refusal !== undefined) {
        return refuseLocal(id, params.name, modelArgs, localFillRefusalText(plan.refusal.code, plan.refusal.detail));
      }
      return forwardFilled(id, params, modelArgs, plan);
    });
  }

  function isAbandonedSession(entry) {
    for (const gone of abandoned.values()) {
      if (gone.roleAccess === entry.access || (entry.sessionId !== null && gone.sessionId === entry.sessionId)) return true;
    }
    return false;
  }

  // 2.1.13 deliver-first guard for join/next/submit/submit_checkpoint: the
  // refusal text, or null.
  async function deliveryGuardRefusal(name, args) {
    if (!invitationRefs || !DELIVERY_GUARDED_TOOLS.has(name)) return null;
    const access = typeof args.access === "string" ? args.access
      : typeof args.roleAccess === "string" ? args.roleAccess : null;
    const sessionId = typeof args.sessionId === "string" ? args.sessionId : null;
    if (access === null && sessionId === null) return null;
    const guard = await deliveryGuard({ sessionId, access });
    if (guard?.kind === "pending") return deliverFirstText(guard.entry, { staged: false });
    if (guard?.kind === "expired") return deliverExpiredText(guard.entry);
    return null;
  }

  // C-ADP-1: an adapter-side refusal of a forwardable tool. Nothing was sent
  // upstream; the line records the model's args and the refusal code.
  async function refuseLocal(id, tool, modelArgs, text) {
    const code = /^([A-Z][A-Z0-9_]{0,63}):/.exec(text)?.[1] ?? "ADAPTER_REFUSED";
    await forwardJournal.append({ kind: JOURNAL_KINDS.refusedLocal, tool, modelArgs, code });
    return { jsonrpc: "2.0", id, result: textResult(text, true) };
  }

  // 2.2.0 + C-ADP-1: forward the (filled) args; on an accepted call spend the
  // local value it used; journal every forwarded call, filled or not.
  async function forwardFilled(id, params, modelArgs, { forwarded, filled, onSuccess = () => {} }) {
    const meta = {};
    const sent = filled.length === 0 ? params : { ...params, arguments: forwarded };
    const response = await proxyToolCall(id, sent, meta);
    if (filled.length > 0 && response.error === undefined && response.result?.isError !== true) onSuccess();
    await journalForward({ tool: params.name, modelArgs, forwardedArgs: modelArgsOf(sent), filled, response, meta });
    return response;
  }

  function journalForward({ tool, modelArgs, forwardedArgs, filled, dropped = [], response, meta = {} }) {
    return forwardJournal.append({
      kind: JOURNAL_KINDS.forward,
      tool,
      modelArgs,
      forwardedArgs,
      filled,
      ...(dropped.length > 0 ? { dropped } : {}),
      serverNonce: response.error === undefined ? serverNonceFromResult(response.result) : null,
      receiptHash: response.error === undefined ? receiptHashFromResult(response.result) : null,
      ...(meta.staged?.length > 0 ? { stagedStepDigests: meta.staged } : {}),
      ...(meta.skippedExecuted?.length > 0 ? { skippedExecuted: meta.skippedExecuted } : {}),
      outcome: tool === INVITE_TOOL && isTransientInviteRefusal(response) ? TRANSIENT_OUTCOME
        : response.error !== undefined ? "error" : response.result?.isError === true ? "refused" : "ok",
    });
  }

  // 2.1.12: agent_handshake_accept_invitation with { invitationRef } — the
  // signer's open_sealed stored the counterparty's invitation in this
  // company's private ref store; read the exact bytes locally, run the 2.1.11
  // guard on them, forward them as `invitation`, and spend the ref only when
  // the coordinator accepted. A failure that leaves the invitation unspent
  // (transport, coordinator refusal) releases the ref for a retry.
  async function acceptByRef(id, params, args) {
    const keys = Object.keys(args);
    if (keys.some((key) => key !== "invitationRef" && key !== "acceptanceIdempotencyKey")) {
      return refuseLocal(id, INVITATION_TOOL, args, invitationRefRefusalText(INVITATION_REF_REFUSALS.invalid));
    }
    let claim;
    try {
      claim = await claimInvitationRef({ tmpRoot, ref: args.invitationRef, kind: "received", nowMs: now() });
    } catch (error) {
      const code = error instanceof InvitationRefError ? error.code : INVITATION_REF_REFUSALS.store;
      return refuseLocal(id, INVITATION_TOOL, args, invitationRefRefusalText(code));
    }
    const refusal = checkInvitationShape(claim.invitation, { origin: "ref" });
    if (refusal !== null) {
      // The bytes are exactly what the counterparty sealed — a retry cannot
      // fix them, so the ref is spent.
      await claim.consume();
      return refuseLocal(id, INVITATION_TOOL, args, refusal);
    }
    const forwarded = {
      ...params,
      arguments: {
        invitation: claim.invitation,
        ...(Object.hasOwn(args, "acceptanceIdempotencyKey") ? { acceptanceIdempotencyKey: args.acceptanceIdempotencyKey } : {}),
      },
    };
    const meta = {};
    const response = await proxyToolCall(id, forwarded, meta);
    if (response.error === undefined && response.result?.isError !== true) await claim.consume();
    else await claim.release();
    // 2.2.0: the forwarded args carry the invitation, the model's the ref.
    await journalForward({
      tool: INVITATION_TOOL,
      modelArgs: args,
      forwardedArgs: forwarded.arguments,
      filled: ["invitation"],
      dropped: ["invitationRef"],
      response,
      meta,
    });
    return response;
  }

  // 2.1.12 refs mode: agent_handshake_invite's responderInvitation is moved
  // into the ref store (kind "issued") and replaced by responderInvitationRef
  // in every place the model could read it. The signer's seal_to takes that
  // ref, so the Initiator model never carries the invitation either.
  async function withIssuedInvitationRef(result) {
    if (!isPlain(result) || !Array.isArray(result.content)) return result;
    let ref = null;
    let invitation = null;
    let sessionId = null;
    let roleAccess = null;
    let issuedAtMs = null;
    const content = [];
    for (const item of result.content) {
      if (!isPlain(item) || item.type !== "text" || typeof item.text !== "string") { content.push(item); continue; }
      let parsed;
      try { parsed = JSON.parse(item.text); } catch { content.push(item); continue; }
      if (!isPlain(parsed) || typeof parsed.responderInvitation !== "string") { content.push(item); continue; }
      if (invitation !== null && parsed.responderInvitation !== invitation) invalid();
      invitation = parsed.responderInvitation;
      if (typeof parsed.sessionId === "string" && UUID.test(parsed.sessionId)) sessionId ??= parsed.sessionId;
      if (typeof parsed.roleAccess === "string" && parsed.roleAccess.length > 0) roleAccess ??= parsed.roleAccess;
      if (ref === null) {
        await settleIssuedRefs();
        issuedAtMs = now();
        ref = await putInvitationRef({ tmpRoot, kind: "issued", invitation, nowMs: issuedAtMs });
      }
      const { responderInvitation: _withheld, ...rest } = parsed;
      content.push({ ...item, text: JSON.stringify({ ...rest, responderInvitationRef: ref }) });
    }
    if (ref === null) return result;
    // 2.1.13: track the ref until the signer's seal_to consumes it.
    undelivered.set(ref, Object.freeze({ ref, sessionId, roleAccess, expMs: issuedAtMs + INVITATION_REF_TTL_MS }));
    const next = { ...result, content };
    if (isPlain(result.structuredContent)) {
      const { responderInvitation: _withheld, ...rest } = result.structuredContent;
      next.structuredContent = { ...rest, responderInvitationRef: ref };
    }
    return next;
  }

  async function proxyToolCall(id, params, meta = {}) {
    let envelope;
    try {
      envelope = await upstreamRequest("tools/call", params);
    } catch (error) {
      if (error instanceof UpstreamUnreachedError) {
        return {
          jsonrpc: "2.0",
          id,
          error: { code: -32603, message: `${UPSTREAM_UNAVAILABLE_PREFIX} the coordinator was not reached (${error.message}); nothing was sent. Retry shortly.` },
        };
      }
      return {
        jsonrpc: "2.0",
        id,
        error: { code: -32603, message: "Clockchain local adapter upstream request failed." },
      };
    }
    if (envelope.error !== undefined) return { jsonrpc: "2.0", id, error: envelope.error };
    const seeded = await seedExecutedDigests();
    try {
      stageToolResult(envelope.result, { meta, seeded });
    } catch (error) {
      // The only refusal text allowed past this boundary besides the generic
      // one is the release-mismatch upgrade hint — arbitrary error messages
      // never leak upstream internals.
      const text =
        typeof error?.message === "string" && error.message === ADAPTER_RELEASE_MISMATCH_REFUSAL
          ? ADAPTER_RELEASE_MISMATCH_REFUSAL
          : GENERIC_REFUSAL;
      return {
        jsonrpc: "2.0",
        id,
        result: textResult(text, true),
      };
    }
    // 2.2.0: remember the role access each invite/accept result hands out.
    if ((params.name === INVITE_TOOL || params.name === INVITATION_TOOL) && envelope.result?.isError !== true) {
      const seen = roleAccessFromResult(envelope.result, {
        role: params.name === INVITE_TOOL ? "initiator" : "responder",
      });
      if (seen !== null) localValues.recordRoleAccess(seen);
    }
    if (invitationRefs && params.name === INVITE_TOOL) {
      try {
        return { jsonrpc: "2.0", id, result: await withIssuedInvitationRef(envelope.result) };
      } catch (error) {
        const code = error instanceof InvitationRefError ? error.code : INVITATION_REF_REFUSALS.store;
        return { jsonrpc: "2.0", id, result: textResult(invitationRefRefusalText(code), true) };
      }
    }
    return { jsonrpc: "2.0", id, result: envelope.result };
  }

  async function handleInitialize(id, params) {
    const requested = isPlain(params) && typeof params.protocolVersion === "string"
      ? params.protocolVersion
      : null;
    const upstream = await upstreamInitialize(isPlain(params) ? params : undefined);
    const upstreamProtocol = typeof upstream?.protocolVersion === "string"
      ? upstream.protocolVersion
      : null;
    return {
      jsonrpc: "2.0",
      id,
      result: {
        protocolVersion: requested ?? upstreamProtocol ?? "2024-11-05",
        capabilities: { tools: {} },
        serverInfo: { name: ADAPTER_NAME, version: pin.version },
        instructions: typeof upstream?.instructions === "string"
          ? upstream.instructions
          : FALLBACK_INSTRUCTIONS,
      },
    };
  }

  async function handleMessage(message) {
    if (!isPlain(message) || message.jsonrpc !== "2.0") return null;
    const method = message.method;
    if (typeof method !== "string") return null;
    if (method.startsWith("notifications/")) return null;
    const id = message.id;
    if (id === undefined || id === null) return null;
    if (method === "initialize") return handleInitialize(id, message.params);
    if (method === "ping") return { jsonrpc: "2.0", id, result: {} };
    if (method === "tools/list") return handleToolsList(id, message.params);
    if (method === "tools/call") return handleToolsCall(id, message.params);
    return { jsonrpc: "2.0", id, error: { code: -32601, message: "method not found" } };
  }

  return Object.freeze({
    handleMessage,
    pendingCount: () => queue.length,
    pin,
    serverInfo: Object.freeze({ name: ADAPTER_NAME, version: pin.version }),
    toolDefinition: ADAPTER_TOOL_DEFINITION,
  });
}

export function startLocalAdapterStdio(options = {}) {
  const server = createLocalAdapterServer(options);
  const input = options?.input ?? process.stdin;
  const output = options?.output ?? process.stdout;
  // A closed stdout (client exited mid-session) must not crash the loop.
  output.on?.("error", () => {});
  const lines = createInterface({ input, terminal: false });
  lines.on("line", (line) => {
    if (line.trim().length === 0 || Buffer.byteLength(line) > MAX_LINE_BYTES) return;
    let message;
    try { message = JSON.parse(line); } catch { return; }
    void Promise.resolve(server.handleMessage(message))
      .then((response) => {
        if (response !== null && response !== undefined) {
          output.write(`${JSON.stringify(response)}\n`);
        }
      })
      .catch(() => {});
  });
  return Object.freeze({
    server,
    close() { lines.close(); },
  });
}
