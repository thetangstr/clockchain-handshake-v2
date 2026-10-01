// sign_agent_contract_bind — the adapter's second (and only other) local tool.
//
// The agent-contract server (clockchain-developer-tools packages/mcp-server,
// src/agent-contract) late-binds a `*` bearer token to a handshake party only
// when the caller proves possession of that party's handshake session key:
// an EIP-191 signature over sha256(canonicalJson(statement)) for the strict
// seven-key `agent-contract.bind/v1` statement, recovering to
// certificate.result.parties[side].sessionKeyAddress. That key is the
// per-session secp256k1 wallet the pinned helper created under
// ${TMPDIR}/.clockchain/handshakes/<sessionId>/<role>/wallet.json — so only
// this adapter's uid can produce the proof, and it must never become a
// generic signing oracle. See the SECURITY section of docs/local-adapter.md.

import { createHash } from "node:crypto";
import { lstat } from "node:fs/promises";
import { isAbsolute, join, relative, resolve } from "node:path";
import { types } from "node:util";

import { recoverMessageAddress } from "viem";

import { readAgentPolicy } from "../agent-cli/policy.mjs";
import { readPrivateText, writePrivateFile } from "../core/private-path.mjs";
import { signExactBytes } from "../core/wallet-bridge.mjs";

// --- canonical JSON: byte-for-byte port of the contract server -------------
//
// Port of clockchain-developer-tools packages/mcp-server
// src/agent-contract/canonical.ts canonicalJson/canonicalDigest (object keys
// sorted recursively by UTF-16 code unit, no insignificant whitespace,
// JSON.stringify string/number encoding, undefined/function/symbol object
// members dropped, the same members refused in arrays and at top level).
// Parity is proven by test/fixtures/agent-contract-canonical-digest-vectors.json
// (a verbatim copy of the server's own vectors) — keep this byte-compatible.
// The adapter's own canonicalBytes (src/core/canonical.mjs) is a different,
// stricter profile and is deliberately NOT used for the bind preimage.

export function contractCanonicalJson(value) {
  const canon = (v) => {
    if (v === null) return "null";
    switch (typeof v) {
      case "number":
        if (!Number.isFinite(v)) throw new Error("canonicalJson: non-finite number");
        return JSON.stringify(v);
      case "boolean":
      case "string":
        return JSON.stringify(v);
      case "object": {
        if (Array.isArray(v)) {
          return `[${v.map((item) => {
            if (item === undefined || typeof item === "function" || typeof item === "symbol") {
              throw new Error("canonicalJson: unrepresentable array member");
            }
            return canon(item);
          }).join(",")}]`;
        }
        return `{${Object.keys(v)
          .filter((k) => v[k] !== undefined && typeof v[k] !== "function" && typeof v[k] !== "symbol")
          .sort()
          .map((k) => `${JSON.stringify(k)}:${canon(v[k])}`)
          .join(",")}}`;
      }
      default:
        throw new Error(`canonicalJson: unrepresentable type ${typeof v}`);
    }
  };
  return canon(value);
}

/** sha256 of the contract canonical JSON, `0x`-prefixed lowercase hex. */
export function contractCanonicalDigest(value) {
  return `0x${createHash("sha256").update(contractCanonicalJson(value), "utf8").digest("hex")}`;
}

// --- the bind statement ------------------------------------------------------

export const CONTRACT_BIND_TOOL = "sign_agent_contract_bind";
export const CONTRACT_BIND_DOMAIN = "agent-contract.bind/v1";
// The contract server accepts issuedAt in [challenge.issuedAt,
// challenge.issuedAt + TTL] (TTL default 60 s). The adapter's own window is
// against its local clock: a statement may be at most this old or this far
// in the future. It only narrows what the adapter signs; the server's
// single-use, principal-bound challenge remains the replay control.
export const CONTRACT_BIND_ISSUED_AT_MAX_AGE_MS = 120_000;
export const CONTRACT_BIND_ISSUED_AT_MAX_SKEW_MS = 30_000;

// Fixed refusal codes. Never echoes input bytes; the code only says which
// class of check failed so a caller can fix its request inside the
// challenge TTL.
export const CONTRACT_BIND_REFUSALS = Object.freeze({
  arguments: "BIND_ARGUMENTS_INVALID",
  notConfigured: "BIND_NOT_CONFIGURED",
  keyIdNotAllowed: "BIND_KEY_ID_NOT_ALLOWED",
  issuedAt: "BIND_ISSUED_AT_OUT_OF_WINDOW",
  session: "BIND_SESSION_NOT_HELD",
  notVerified: "BIND_SESSION_NOT_VERIFIED",
  expired: "BIND_SESSION_EXPIRED",
  signing: "BIND_SIGNING_FAILED",
});

export function contractBindRefusalText(code) {
  return `Clockchain local adapter refused the bind statement (${code}).`;
}

export class ContractBindRefusal extends Error {
  constructor(code) {
    super(contractBindRefusalText(code));
    this.name = "ContractBindRefusal";
    this.code = code;
  }
}

function refuse(code) {
  throw new ContractBindRefusal(code);
}

// Field order is the server's schema order (schemas.ts bindStatementSchema);
// the signed bytes use canonical (sorted) order regardless.
const STATEMENT_KEYS = Object.freeze([
  "domain", "runId", "side", "tokenKeyId", "serverKeyId", "challenge", "issuedAt",
]);
const SIDES = Object.freeze(["initiator", "responder"]);
// A handshake sessionId — the contract runId IS the certificate's sessionId.
// Same pattern the adapter stages helper steps under.
const UUID_SOURCE = "^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$";
const UUID = new RegExp(UUID_SOURCE);
// Server: keyId = z.string().min(1).max(64). The adapter additionally keeps
// key ids to visible ASCII so nothing ambiguous enters a signed preimage.
const KEY_ID_SOURCE = "^[!-~]{1,64}$";
const KEY_ID = new RegExp(KEY_ID_SOURCE);
const CHALLENGE_SOURCE = "^[0-9a-f]{64}$";
const CHALLENGE = new RegExp(CHALLENGE_SOURCE);
// Server: z.string().datetime({ offset: false }) — UTC "Z" form only.
const ISO_UTC = /^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,9})?Z$/;

export const CONTRACT_BIND_TOOL_DEFINITION = Object.freeze({
  name: CONTRACT_BIND_TOOL,
  description:
    "Sign an agent-contract bind statement (agent-contract.bind/v1) with this " +
    "role's handshake session key, proving possession of the key the " +
    "handshake certificate names as parties[side].sessionKeyAddress. Signs " +
    "ONLY this seven-key statement and ONLY for a handshake session this " +
    "adapter holds locally for that side; refuses everything else. Get the " +
    "challenge from contract_bind_challenge, set issuedAt to the current UTC " +
    "time, call this tool, then pass statement and signature to contract_bind " +
    "as bindStatement and bindStatementSignature before the challenge expires. " +
    "Only the tokenKeyId/serverKeyId values pinned for this company are " +
    "accepted. Returns {statement, signature, sessionKeyAddress}; the key " +
    "never leaves this machine.",
  inputSchema: Object.freeze({
    type: "object",
    properties: Object.freeze({
      domain: Object.freeze({ type: "string", const: CONTRACT_BIND_DOMAIN }),
      runId: Object.freeze({
        type: "string",
        pattern: UUID_SOURCE,
        description: "The handshake sessionId (the contract runId).",
      }),
      side: Object.freeze({ type: "string", enum: SIDES }),
      tokenKeyId: Object.freeze({
        type: "string", pattern: KEY_ID_SOURCE,
        description: "keyId of the contract bearer token that will call contract_bind.",
      }),
      serverKeyId: Object.freeze({
        type: "string", pattern: KEY_ID_SOURCE,
        description: "The contract server's signer keyId.",
      }),
      challenge: Object.freeze({
        type: "string", pattern: CHALLENGE_SOURCE,
        description: "The challenge returned by contract_bind_challenge.",
      }),
      issuedAt: Object.freeze({
        type: "string", format: "date-time",
        description: "Current time, ISO-8601 UTC with Z (e.g. new Date().toISOString()).",
      }),
    }),
    required: STATEMENT_KEYS,
    additionalProperties: false,
  }),
});

function isPlainRecord(value) {
  return (
    value !== null && typeof value === "object" && !Array.isArray(value) &&
    !types.isProxy(value) &&
    [Object.prototype, null].includes(Object.getPrototypeOf(value))
  );
}

/**
 * Validate tool arguments as exactly one bind statement and return it with
 * keys in canonical order (a fresh frozen object built from the caller's
 * own string data properties — nothing is signed by reference).
 */
export function validateContractBindStatement(args, { nowMs } = {}) {
  if (!Number.isSafeInteger(nowMs)) refuse(CONTRACT_BIND_REFUSALS.arguments);
  if (!isPlainRecord(args)) refuse(CONTRACT_BIND_REFUSALS.arguments);
  const keys = Reflect.ownKeys(args);
  if (
    keys.length !== STATEMENT_KEYS.length ||
    keys.some((key) => typeof key !== "string" || !STATEMENT_KEYS.includes(key))
  ) refuse(CONTRACT_BIND_REFUSALS.arguments);
  const fields = {};
  for (const key of STATEMENT_KEYS) {
    const descriptor = Object.getOwnPropertyDescriptor(args, key);
    if (
      descriptor?.enumerable !== true || !Object.hasOwn(descriptor, "value") ||
      typeof descriptor.value !== "string"
    ) refuse(CONTRACT_BIND_REFUSALS.arguments);
    fields[key] = descriptor.value;
  }
  if (
    fields.domain !== CONTRACT_BIND_DOMAIN ||
    !UUID.test(fields.runId) ||
    !SIDES.includes(fields.side) ||
    !KEY_ID.test(fields.tokenKeyId) ||
    !KEY_ID.test(fields.serverKeyId) ||
    !CHALLENGE.test(fields.challenge) ||
    !ISO_UTC.test(fields.issuedAt)
  ) refuse(CONTRACT_BIND_REFUSALS.arguments);
  const issuedAtMs = Date.parse(fields.issuedAt);
  // Date.parse rolls impossible calendar values over (Feb 30 -> Mar 2,
  // 24:00 -> next day); the round trip refuses them.
  if (
    !Number.isFinite(issuedAtMs) ||
    new Date(issuedAtMs).toISOString().slice(0, 19) !== fields.issuedAt.slice(0, 19)
  ) refuse(CONTRACT_BIND_REFUSALS.arguments);
  if (
    issuedAtMs < nowMs - CONTRACT_BIND_ISSUED_AT_MAX_AGE_MS ||
    issuedAtMs > nowMs + CONTRACT_BIND_ISSUED_AT_MAX_SKEW_MS
  ) refuse(CONTRACT_BIND_REFUSALS.issuedAt);
  const statement = {};
  for (const key of [...STATEMENT_KEYS].sort()) statement[key] = fields[key];
  return Object.freeze(statement);
}

// --- per-company key-id pins (L1) --------------------------------------------
//
// The adapter signs only for the contract token(s) and contract server(s)
// this company was provisioned with. Pins come from the environment of the
// adapter process — in the travel lane, the root-owned launchd plist of the
// <U>-svc adapter — as comma-separated key-id lists. Unset, empty or
// malformed pins disable the tool entirely (fail closed, never partially):
// a stock install of the public package never signs a bind statement.

export const CONTRACT_BIND_TOKEN_KEY_IDS_ENV = "CLOCKCHAIN_LOCAL_ADAPTER_BIND_TOKEN_KEY_IDS";
export const CONTRACT_BIND_SERVER_KEY_IDS_ENV = "CLOCKCHAIN_LOCAL_ADAPTER_BIND_SERVER_KEY_IDS";
const MAX_PINNED_KEY_IDS = 16;

function parsePinList(text) {
  if (typeof text !== "string" || text.trim().length === 0) return undefined;
  return text.split(",").map((entry) => entry.trim());
}

/** The raw pin config from an environment object (validated at call time). */
export function contractBindPinsFromEnv(env = process.env) {
  return {
    tokenKeyIds: parsePinList(env?.[CONTRACT_BIND_TOKEN_KEY_IDS_ENV]),
    serverKeyIds: parsePinList(env?.[CONTRACT_BIND_SERVER_KEY_IDS_ENV]),
  };
}

function pinSet(value) {
  if (
    !Array.isArray(value) || value.length < 1 || value.length > MAX_PINNED_KEY_IDS ||
    value.some((entry) => typeof entry !== "string" || !KEY_ID.test(entry))
  ) return null;
  return new Set(value);
}

function resolvePins({ tokenKeyIds, serverKeyIds }) {
  const tokens = pinSet(tokenKeyIds);
  const servers = pinSet(serverKeyIds);
  if (tokens === null || servers === null) refuse(CONTRACT_BIND_REFUSALS.notConfigured);
  return { tokens, servers };
}

/** Validates a createLocalAdapterServer `contractBind` option's shape. */
export function contractBindPinsOption(value) {
  if (!isPlainRecord(value)) return { tokenKeyIds: null, serverKeyIds: null };
  const keys = Reflect.ownKeys(value);
  if (keys.length !== 2 || !keys.includes("tokenKeyIds") || !keys.includes("serverKeyIds")) {
    return { tokenKeyIds: null, serverKeyIds: null };
  }
  return { tokenKeyIds: value.tokenKeyIds, serverKeyIds: value.serverKeyIds };
}

// --- the verified-session record (L3) -------------------------------------------
//
// The pinned helper persists no session deadline. The adapter, which executes
// each role's terminal verify-certificate step, records — write-once, as a
// private file beside wallet.json — the facts that step established once the
// helper reported certificateVerified/VERIFIED: the session, the role, the
// party sessionKeyAddress the certificate names, and the session's own expiry
// = min(payload sessionDeadlineMs, host session-key certificate validUntilMs)
// (the helper refuses a certificate whose validUntilMs exceeds the deadline;
// the coordinator sets deadline = session open + 10 min). The bind tool signs
// only for a session with this record, before its expiry, with the wallet
// that the verified certificate names.

export const VERIFIED_SESSION_FILE = "contract-bind-session.json";
const VERIFIED_SESSION_SCHEMA = "clockchain.local-adapter.verified-session/v1";
const VERIFIED_SESSION_KEYS = Object.freeze([
  "schema", "sessionId", "role", "sessionKeyAddress", "expiresAtMs",
]);
const ADDRESS = /^0x[0-9a-f]{40}$/;
const DECIMAL = /^(?:0|[1-9][0-9]*)$/;

function verifiedSessionRecord({ sessionId, role, sessionKeyAddress, expiresAtMs }) {
  if (
    typeof sessionId !== "string" || !UUID.test(sessionId) ||
    !SIDES.includes(role) ||
    typeof sessionKeyAddress !== "string" || !ADDRESS.test(sessionKeyAddress) ||
    !Number.isSafeInteger(expiresAtMs) || expiresAtMs < 0
  ) return null;
  return {
    schema: VERIFIED_SESSION_SCHEMA,
    sessionId,
    role,
    sessionKeyAddress,
    expiresAtMs: String(expiresAtMs),
  };
}

/**
 * Write the verified-session record (create-only, private file). Returns
 * false — never throws — on invalid input or when a record already exists:
 * the first verification of a session wins.
 */
export async function recordVerifiedSession({
  stateDir, sessionId, role, sessionKeyAddress, expiresAtMs, platform = process.platform,
} = {}) {
  const record = verifiedSessionRecord({ sessionId, role, sessionKeyAddress, expiresAtMs });
  if (record === null || typeof stateDir !== "string" || !isAbsolute(stateDir)) return false;
  try {
    await writePrivateFile({
      bytes: Buffer.from(`${JSON.stringify(record)}\n`, "utf8"),
      path: join(resolve(stateDir), VERIFIED_SESSION_FILE),
      platform,
    });
    return true;
  } catch {
    return false;
  }
}

/**
 * The verified-session facts from one executed verify-certificate step: the
 * validated staged step (its payload was already bound to role/sessionId at
 * staging) and the helper's validated CLI result. null unless the helper
 * reported a verified VERIFIED certificate for exactly this role/session.
 */
export function verifiedSessionFromStep({ step, helperResult } = {}) {
  try {
    if (step?.operation !== "verify-certificate" || typeof step.payloadBase64url !== "string") return null;
    const payload = JSON.parse(Buffer.from(step.payloadBase64url, "base64url").toString("utf8"));
    const validUntil = payload?.certificate?.hostSessionKeyCertificate?.certificate?.validUntilMs;
    if (
      helperResult?.certificateVerified !== true || helperResult.outcome !== "VERIFIED" ||
      helperResult.role !== step.role || helperResult.sessionId !== step.sessionId ||
      payload?.role !== step.role || payload?.sessionId !== step.sessionId ||
      typeof payload.sessionDeadlineMs !== "string" || !DECIMAL.test(payload.sessionDeadlineMs) ||
      typeof validUntil !== "string" || !DECIMAL.test(validUntil)
    ) return null;
    const expiresAtMs = Math.min(Number(payload.sessionDeadlineMs), Number(validUntil));
    const sessionKeyAddress = helperResult.identity?.sessionKeyAddress;
    if (typeof sessionKeyAddress !== "string") return null;
    return verifiedSessionRecord({
      sessionId: step.sessionId,
      role: step.role,
      sessionKeyAddress: sessionKeyAddress.toLowerCase(),
      expiresAtMs,
    });
  } catch {
    return null;
  }
}

async function readVerifiedSession({ stateDir, platform }) {
  let record;
  try {
    record = JSON.parse(await readPrivateText({ path: join(stateDir, VERIFIED_SESSION_FILE), platform }));
  } catch {
    refuse(CONTRACT_BIND_REFUSALS.notVerified);
  }
  if (
    !isPlainRecord(record) ||
    Object.keys(record).length !== VERIFIED_SESSION_KEYS.length ||
    VERIFIED_SESSION_KEYS.some((key) => !Object.hasOwn(record, key)) ||
    record.schema !== VERIFIED_SESSION_SCHEMA ||
    typeof record.expiresAtMs !== "string" || !DECIMAL.test(record.expiresAtMs) ||
    verifiedSessionRecord({ ...record, expiresAtMs: Number(record.expiresAtMs) }) === null
  ) refuse(CONTRACT_BIND_REFUSALS.notVerified);
  return Object.freeze({ ...record, expiresAtMs: Number(record.expiresAtMs) });
}

// --- the held session ----------------------------------------------------------

function privateDirectory(stats, platform) {
  if (!stats.isDirectory() || stats.isSymbolicLink()) return false;
  if (platform === "win32") return true;
  if (typeof process.getuid === "function" && stats.uid !== process.getuid()) return false;
  return (stats.mode & 0o077) === 0;
}

/**
 * Resolve the state dir of a session this adapter holds for `side`, WITHOUT
 * creating anything: the session dir and role dir must already exist as
 * private real directories (never symlinks) under
 * <tmpRoot>/.clockchain/handshakes, and wallet.json must exist in it. The
 * wallet-bridge re-checks the wallet's own privacy when it reads the key.
 */
async function heldStateDir({ tmpRoot, runId, side, platform }) {
  const handshakes = join(tmpRoot, ".clockchain", "handshakes");
  const sessionDir = join(handshakes, runId);
  const stateDir = join(sessionDir, side);
  const offset = relative(tmpRoot, stateDir);
  if (
    offset === "" || offset.startsWith("..") || isAbsolute(offset) ||
    stateDir !== resolve(stateDir) ||
    !stateDir.endsWith(`/.clockchain/handshakes/${runId}/${side}`)
  ) refuse(CONTRACT_BIND_REFUSALS.session);
  try {
    for (const dir of [sessionDir, stateDir]) {
      if (!privateDirectory(await lstat(dir), platform)) refuse(CONTRACT_BIND_REFUSALS.session);
    }
    const wallet = await lstat(join(stateDir, "wallet.json"));
    if (!wallet.isFile() || wallet.isSymbolicLink()) refuse(CONTRACT_BIND_REFUSALS.session);
  } catch (error) {
    if (error instanceof ContractBindRefusal) throw error;
    refuse(CONTRACT_BIND_REFUSALS.session);
  }
  return stateDir;
}

const SECP256K1_HALF_N = 0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0n;

/**
 * Sign one validated bind statement with the session key of a session this
 * adapter holds. Order matters: every argument check runs before any
 * filesystem access, and every session check runs before the key is read.
 */
export async function signContractBindStatement(args, {
  nowMs,
  platform = process.platform,
  readPolicy = readAgentPolicy,
  serverKeyIds,
  signBytes = signExactBytes,
  tmpRoot,
  tokenKeyIds,
} = {}) {
  const statement = validateContractBindStatement(args, { nowMs });
  const pins = resolvePins({ tokenKeyIds, serverKeyIds });
  if (!pins.tokens.has(statement.tokenKeyId) || !pins.servers.has(statement.serverKeyId)) {
    refuse(CONTRACT_BIND_REFUSALS.keyIdNotAllowed);
  }
  if (typeof tmpRoot !== "string" || !isAbsolute(tmpRoot)) refuse(CONTRACT_BIND_REFUSALS.session);
  const stateDir = await heldStateDir({
    tmpRoot: resolve(tmpRoot), runId: statement.runId, side: statement.side, platform,
  });
  // Local policy gate: the pinned helper's committed policy for this session
  // must exist, verify against its own digest, and name this side's role.
  let committed;
  try {
    committed = await readPolicy({ stateDir, platform });
  } catch {
    refuse(CONTRACT_BIND_REFUSALS.session);
  }
  if (committed?.policy?.role !== statement.side) refuse(CONTRACT_BIND_REFUSALS.session);
  // L3: only a session this adapter saw verified, and only before its expiry.
  const verified = await readVerifiedSession({ stateDir, platform });
  if (verified.sessionId !== statement.runId || verified.role !== statement.side) {
    refuse(CONTRACT_BIND_REFUSALS.notVerified);
  }
  if (nowMs >= verified.expiresAtMs) refuse(CONTRACT_BIND_REFUSALS.expired);

  const digest = contractCanonicalDigest(statement);
  let signed;
  try {
    signed = await signBytes({ bytesHex: digest, platform, statePath: join(stateDir, "wallet.json") });
  } catch {
    refuse(CONTRACT_BIND_REFUSALS.signing);
  }
  const signature = typeof signed?.signatureHex === "string" ? signed.signatureHex.toLowerCase() : "";
  const address = typeof signed?.address === "string" ? signed.address.toLowerCase() : "";
  // Self-check before release: canonical form (65 bytes, v in {27,28},
  // low-s — the server's isCanonicalEip191Signature) and recovery to the
  // session address over exactly the digest the server will recompute.
  if (!/^0x[0-9a-f]{130}$/.test(signature) || !/^0x[0-9a-f]{40}$/.test(address)) {
    refuse(CONTRACT_BIND_REFUSALS.signing);
  }
  const v = Number.parseInt(signature.slice(130), 16);
  const s = BigInt(`0x${signature.slice(66, 130)}`);
  if ((v !== 27 && v !== 28) || s === 0n || s > SECP256K1_HALF_N) refuse(CONTRACT_BIND_REFUSALS.signing);
  let recovered;
  try {
    recovered = await recoverMessageAddress({ message: { raw: digest }, signature });
  } catch {
    refuse(CONTRACT_BIND_REFUSALS.signing);
  }
  if (recovered.toLowerCase() !== address) refuse(CONTRACT_BIND_REFUSALS.signing);
  // The wallet must be the party key the verified certificate names; a
  // mismatch withholds the signature (it would only fail at the server).
  if (address !== verified.sessionKeyAddress) refuse(CONTRACT_BIND_REFUSALS.notVerified);
  return Object.freeze({ statement, signature, sessionKeyAddress: address });
}
