// 2.2.0 handshake by reference (travel_mvp docs/travel-mvp/design/
// AGENT-TOOLS-BY-REFERENCE.md §6).
//
// Live runs lost about a third of their time to the model re-typing long
// opaque values between handshake tools — the 132-char signatures, the
// 173-char checkpoint object, the 64-char policy digest, the 153-char invite
// statement — and every re-type is a chance to corrupt one character. The
// adapter already stages every helper step and sees every helper result, so it
// holds each of those values itself. This module lets it fill them:
//
//   agent_handshake_invite             reference, statement, validForSeconds,
//                                      identityPolicy  <- the pinned published terms
//   every tool taking access           access          <- the role access seen in
//                                                         this role's invite/accept result
//   agent_handshake_join               helperVersion   <- the pin
//                                      sessionKeyAddress, policyDigest
//                                                      <- the latest init/inspect/policy
//                                                         result for the session and role
//   agent_handshake_submit             policyDigest, signatureHex
//                                                      <- the oldest unspent sign result
//   agent_handshake_submit_checkpoint  artifactSignatureHex, checkpoint
//                                                      <- the oldest sign result whose
//                                                         checkpoint is unsubmitted
//
// Rules:
//   - A model-supplied value must equal the local one (byte for byte; an
//     address case-insensitively, an object by sorted-key JSON). Otherwise the
//     call is refused LOCAL_VALUE_MISMATCH and never forwarded. The value the
//     model wrote is forwarded as written, so every model field equals the same
//     forwarded field.
//   - Where the adapter holds no local value (no live session, an access it
//     never saw, a helper step not yet executed) it forwards what the model
//     gave and the coordinator answers as before.
//   - The call count does not change: each model call is one forwarded call
//     with one coordinator receipt. The handshake's no-cheating rule (each
//     role's own model makes its join / propose / accept calls) is untouched.
//   - Signatures, the checkpoint, the full address and the policy digest are
//     withheld from authorize_local_action results, so nothing tempts a copy.
//   - Every call whose forwarded args differ from the model's args is appended
//     to a hash-chained private journal ({tool, modelArgs, forwardedArgs,
//     filled, serverNonce}) — the verifiable preimage R8 needs to reproduce the
//     coordinator receipt's argsDigest for an adapter-filled call.

import { createHash } from "node:crypto";
import { constants as fsConstants } from "node:fs";
import { lstat, mkdir, open, readFile } from "node:fs/promises";
import { join } from "node:path";
import { types } from "node:util";

export const LOCAL_FILL_REFUSALS = Object.freeze({
  mismatch: "LOCAL_VALUE_MISMATCH",
  ambiguous: "SESSION_AMBIGUOUS",
  termsPin: "INVITE_TERMS_PIN_INVALID",
  inviteBudget: "INVITE_BUDGET_EXHAUSTED",
  budgetPin: "INVITE_BUDGET_PIN_INVALID",
});

// Per-run invite budget (travel_mvp plan: at most 3 handshake invites per run;
// run p6-l-2026-10-03-1 sent 7). A run is one adapter epoch: the fleet's
// launchd PathState starts this process for the run and ac-run-config rotates
// the forwarding journal when a new epoch opens, so the count is this process's
// forwarded invites, seeded once from the epoch's journal (a KeepAlive restart
// mid-run keeps counting). Every forwarded invite counts, whatever the
// coordinator answered — except one it refused as transient (the hosted generic
// host between sessions: HANDSHAKE_TEMPORARILY_UNAVAILABLE, retryable, with a
// retryAfterMs hint; live p6-ta-2026-10-03-5). That refusal minted no session
// and holds no seat, so it is journaled with outcome "transient" and the budget
// (and the restart recount) leaves it out.
export const DEFAULT_INVITE_BUDGET = 3;
export const TRANSIENT_OUTCOME = "transient";
export const TRANSIENT_INVITE_CODE = "HANDSHAKE_TEMPORARILY_UNAVAILABLE";
/** The generic host's "invitation window ended" code (it stops; a fresh session follows): nothing minted. */
export const WINDOW_ENDED_CODE = "RENDEZVOUS_UNAVAILABLE";
/** The adapter's own refusal when the coordinator was not reached at all (server.mjs). */
export const UPSTREAM_UNAVAILABLE_PREFIX = "UPSTREAM_UNAVAILABLE:";

/**
 * Is this tools/call response an invite refusal that minted nothing?
 *  - the host between sessions: the generic host answers a NON-error result
 *    ({error: "HANDSHAKE_TEMPORARILY_UNAVAILABLE", retryable: true, retryAfterMs}),
 *    the v2 public tools an isError one of the same body — the code, retryable
 *    true, and no session, role access or invitation in it;
 *  - the window ended (RENDEZVOUS_UNAVAILABLE as error or reason, no session in it);
 *  - the coordinator not reached at all (this adapter's UPSTREAM_UNAVAILABLE error).
 */
export function isTransientInviteRefusal(response) {
  if (!isPlainObject(response)) return false;
  if (response.error !== undefined) {
    return isPlainObject(response.error) && typeof response.error.message === "string" &&
      response.error.message.startsWith(UPSTREAM_UNAVAILABLE_PREFIX);
  }
  const result = response.result;
  if (!isPlainObject(result)) return false;
  const bodies = [];
  if (isPlainObject(result.structuredContent)) bodies.push(result.structuredContent);
  for (const item of Array.isArray(result.content) ? result.content : []) {
    if (!isPlainObject(item) || item.type !== "text" || typeof item.text !== "string") continue;
    try {
      const parsed = JSON.parse(item.text);
      if (isPlainObject(parsed)) bodies.push(parsed);
    } catch { /* not a JSON body */ }
  }
  if (bodies.length === 0) return false;
  return bodies.every((body) =>
    (((body.error === TRANSIENT_INVITE_CODE || body.reason === TRANSIENT_INVITE_CODE) && body.retryable === true) ||
      body.error === WINDOW_ENDED_CODE || body.reason === WINDOW_ENDED_CODE) &&
    !Object.hasOwn(body, "sessionId") && !Object.hasOwn(body, "roleAccess") && !Object.hasOwn(body, "responderInvitation") &&
    !Object.hasOwn(body, "responderInvitationRef"));
}

function isPlainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}
export const INVITE_BUDGET_ENV = "CLOCKCHAIN_LOCAL_ADAPTER_INVITE_BUDGET";

/**
 * The budget: the option (tests, embedders; null = no cap) or the env (a
 * positive integer ≤ 100, or "off"), else DEFAULT_INVITE_BUDGET. A malformed
 * value fails closed ({ invalid: true } — no invite is sent).
 */
export function resolveInviteBudget({ option, env }) {
  const ok = (n) => Number.isSafeInteger(n) && n >= 1 && n <= 100;
  if (option !== undefined) {
    if (option === null) return { budget: null };
    return ok(option) ? { budget: option } : { invalid: true };
  }
  const text = env?.[INVITE_BUDGET_ENV];
  if (typeof text === "string" && text.trim().length > 0) {
    const t = text.trim();
    if (t === "off") return { budget: null };
    return /^[1-9][0-9]{0,2}$/.test(t) && ok(Number(t)) ? { budget: Number(t) } : { invalid: true };
  }
  return { budget: DEFAULT_INVITE_BUDGET };
}

export const INVITE_TOOL = "agent_handshake_invite";
export const ACCEPT_TOOL = "agent_handshake_accept_invitation";
export const JOIN_TOOL = "agent_handshake_join";
export const SUBMIT_TOOL = "agent_handshake_submit";
export const CHECKPOINT_TOOL = "agent_handshake_submit_checkpoint";

// Tools that take the role access. status/get_certificate/next take nothing else.
export const ACCESS_TOOLS = Object.freeze(new Set([
  JOIN_TOOL,
  "agent_handshake_status",
  "agent_handshake_next",
  CHECKPOINT_TOOL,
  SUBMIT_TOOL,
  "agent_handshake_get_certificate",
]));

// The documented filled set per tool (R8 condition 3: the filled fields must be
// exactly a subset of this list). accept_invitation's `invitation` is the
// 2.1.12 ref expansion.
export const FILLABLE_FIELDS = Object.freeze({
  [INVITE_TOOL]: Object.freeze(["reference", "statement", "validForSeconds", "identityPolicy"]),
  [ACCEPT_TOOL]: Object.freeze(["invitation"]),
  [JOIN_TOOL]: Object.freeze(["access", "helperVersion", "sessionKeyAddress", "policyDigest"]),
  [SUBMIT_TOOL]: Object.freeze(["access", "policyDigest", "signatureHex"]),
  [CHECKPOINT_TOOL]: Object.freeze(["access", "artifactSignatureHex", "checkpoint"]),
  "agent_handshake_next": Object.freeze(["access"]),
  "agent_handshake_status": Object.freeze(["access"]),
  "agent_handshake_get_certificate": Object.freeze(["access"]),
});

// The hosted coordinator's fixed published session terms (the terms_mismatch
// reply's publishedTerms; travel_mvp DIRECT_HANDSHAKE_V2_TERMS). Pinned, never
// adopted from a reply at runtime (WS-11 architect ruling 03a §1). They apply
// by default only to the default hosted endpoint; INVITE_TERMS_ENV overrides.
export const PUBLISHED_INVITE_TERMS = Object.freeze({
  reference: "NS-1847",
  statement:
    "Northstar Logistics and Harbor Supply authorize these two independently controlled agents " +
    "to communicate about shipment reference NS-1847 for 90 seconds.",
  validForSeconds: "90",
  identityPolicy: Object.freeze({
    erc8004: "required_fresh",
    chainId: "eip155:11155111",
    registryAddress: "0x8004a818bfb912233c491871b3d84c89a494bd9e",
  }),
});
export const INVITE_TERMS_ENV = "CLOCKCHAIN_LOCAL_ADAPTER_INVITE_TERMS";

export const ADAPTER_FORWARDS_DIR = ".clockchain/adapter-forwards";
export const ADAPTER_FORWARDS_FILE = `${ADAPTER_FORWARDS_DIR}/forwards.jsonl`;

const ADDRESS = /^0x[0-9a-fA-F]{40}$/;
const DIGEST = /^[0-9a-f]{64}$/;
const SIGNATURE = /^0x[0-9a-f]{130}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const NONCE = /^0x[0-9a-f]{16,128}$/;
const VALID_FOR = /^(?:[1-9]|[1-8][0-9]|90)$/;
const REGISTRY = "0x8004a818bfb912233c491871b3d84c89a494bd9e";
const SEPOLIA = "eip155:11155111";
const MAX_SIGN_RESULTS = 64;
// How long a role access counts as live for the access default: the
// coordinator's session lasts 10 minutes; the margin covers clock skew.
export const HANDSHAKE_SESSION_TTL_MS = 15 * 60_000;
const SIGN_RESULT_TTL_MS = 20 * 60_000;
const REDACT_PREFIX = 10;

function isPlain(value) {
  return (
    value !== null && typeof value === "object" && !Array.isArray(value) &&
    !types.isProxy(value) &&
    [Object.prototype, null].includes(Object.getPrototypeOf(value))
  );
}

/** Stable JSON: object keys sorted at every level. Used for equality and hashing. */
export function sortedJson(value) {
  if (Array.isArray(value)) return `[${value.map(sortedJson).join(",")}]`;
  if (value !== null && typeof value === "object") {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${sortedJson(value[key])}`).join(",")}}`;
  }
  return JSON.stringify(value ?? null);
}

// --- invite terms pin -------------------------------------------------------------

function validIdentityPolicy(value) {
  if (!isPlain(value)) return false;
  const keys = Object.keys(value).sort();
  if (keys.join(",") !== "chainId,erc8004,registryAddress") return false;
  if (value.erc8004 === "not_required") return value.chainId === null && value.registryAddress === null;
  return ["required_fresh", "required_existing_or_fresh"].includes(value.erc8004) &&
    value.chainId === SEPOLIA && value.registryAddress === REGISTRY;
}

/** Strictly validates a terms pin; returns a frozen copy or null when invalid. */
export function validateInviteTerms(value) {
  if (!isPlain(value)) return null;
  const keys = Object.keys(value).sort();
  if (keys.join(",") !== "identityPolicy,reference,statement,validForSeconds") return null;
  if (
    typeof value.reference !== "string" || value.reference.length < 1 || value.reference.length > 128 ||
    typeof value.statement !== "string" || value.statement.length < 1 || value.statement.length > 512 ||
    typeof value.validForSeconds !== "string" || !VALID_FOR.test(value.validForSeconds) ||
    !validIdentityPolicy(value.identityPolicy)
  ) return null;
  return Object.freeze({
    reference: value.reference,
    statement: value.statement,
    validForSeconds: value.validForSeconds,
    identityPolicy: Object.freeze({ ...value.identityPolicy }),
  });
}

/**
 * Resolves the invite terms pin: { terms } (pinned), { terms: null } (no pin —
 * invite args pass through), or { invalid: true } (a configured pin that does
 * not validate: invites are refused, never forwarded with guessed terms).
 */
export function resolveInviteTerms({ option, env, endpoint, defaultEndpoint }) {
  if (option !== undefined) {
    if (option === null) return { terms: null };
    const terms = validateInviteTerms(option);
    return terms === null ? { invalid: true } : { terms };
  }
  const text = env?.[INVITE_TERMS_ENV];
  if (typeof text === "string" && text.trim().length > 0) {
    let parsed;
    try { parsed = JSON.parse(text); } catch { return { invalid: true }; }
    const terms = validateInviteTerms(parsed);
    return terms === null ? { invalid: true } : { terms };
  }
  return { terms: endpoint === defaultEndpoint ? PUBLISHED_INVITE_TERMS : null };
}

// --- refusal texts ----------------------------------------------------------------

export function localFillRefusalText(code, detail = {}) {
  if (code === LOCAL_FILL_REFUSALS.mismatch) {
    return `${LOCAL_FILL_REFUSALS.mismatch}: the ${detail.field} you passed to ${detail.tool} differs from the value ` +
      "this adapter holds locally, so nothing was sent to the coordinator. Omit it: the adapter fills " +
      `${detail.field} from its own staged results. Never retype a long value.`;
  }
  if (code === LOCAL_FILL_REFUSALS.ambiguous) {
    return `${LOCAL_FILL_REFUSALS.ambiguous}: this adapter holds ${detail.count} live handshake sessions, so it cannot ` +
      `choose one for ${detail.tool}. Pass access: the roleAccess from the invite or accept result of the session ` +
      "you mean. Nothing was sent to the coordinator.";
  }
  if (code === LOCAL_FILL_REFUSALS.inviteBudget) {
    return `${LOCAL_FILL_REFUSALS.inviteBudget}: this run already sent ${detail.sent} of its ${detail.budget} allowed ` +
      "handshake invitations, so this adapter will not create another. Nothing was sent to the coordinator. " +
      "Continue the handshake you already opened (its roleAccess and the invitation you delivered), or stop and " +
      `report to your operator. ${JSON.stringify({ refusal: LOCAL_FILL_REFUSALS.inviteBudget, tool: INVITE_TOOL, sent: detail.sent, budget: detail.budget })}`;
  }
  if (code === LOCAL_FILL_REFUSALS.budgetPin) {
    return `${LOCAL_FILL_REFUSALS.budgetPin}: this adapter's invite budget (${INVITE_BUDGET_ENV}) is malformed, ` +
      "so it will not create an invitation. Report this to your operator.";
  }
  return `${LOCAL_FILL_REFUSALS.termsPin}: this adapter's pinned invite terms (${INVITE_TERMS_ENV}) are malformed, ` +
    "so it will not create an invitation. Report this to your operator; do not type the terms yourself.";
}

// --- tools/list rewrite -------------------------------------------------------------

const ACCESS_PROPERTY = Object.freeze({
  type: "string",
  minLength: 27,
  maxLength: 4096,
  description:
    "Optional. Defaults to the one live role access this adapter holds (from your invite or accept " +
    "result); pass it only when the adapter reports SESSION_AMBIGUOUS.",
});

const FILLED_DESCRIPTION = Object.freeze({
  [JOIN_TOOL]: "Call with no arguments: the adapter fills access, helperVersion, sessionKeyAddress and policyDigest from its own staged init/policy/inspect results.",
  [SUBMIT_TOOL]: "Call with no arguments: the adapter fills access, policyDigest and the signature from the sign step it executed (oldest unsubmitted first).",
  [CHECKPOINT_TOOL]: "Call with no arguments: the adapter fills access, the artifact signature and the signed checkpoint from the sign step it executed.",
  "agent_handshake_next": "access is optional: the adapter fills it.",
  "agent_handshake_status": "access is optional: the adapter fills it.",
  "agent_handshake_get_certificate": "access is optional: the adapter fills it.",
});

function appendDescription(tool, text) {
  return `${typeof tool.description === "string" && tool.description.length > 0 ? `${tool.description} ` : ""}${text}`;
}

/**
 * Rewrites one proxied tool definition for the by-reference surface. Filled
 * properties leave the advertised schema (the adapter still accepts them and
 * checks them against its local value); access becomes optional.
 */
export function withLocalFills(tool, { inviteTerms }) {
  if (!isPlain(tool) || typeof tool.name !== "string" || !isPlain(tool.inputSchema)) return tool;
  const schema = tool.inputSchema;
  const properties = isPlain(schema.properties) ? { ...schema.properties } : {};
  const required = Array.isArray(schema.required) ? [...schema.required] : [];
  if (tool.name === INVITE_TOOL) {
    if (inviteTerms === null) return tool;
    for (const key of ["statement", "validForSeconds", "identityPolicy"]) delete properties[key];
    if (isPlain(properties.reference)) {
      properties.reference = {
        ...properties.reference,
        description: `Optional. The adapter fills the coordinator's pinned published terms; if given, it must equal "${inviteTerms.reference}".`,
      };
    }
    return {
      ...tool,
      description: appendDescription(tool, "Call with no arguments: the adapter fills the coordinator's fixed published terms (reference, statement, validForSeconds, identityPolicy)."),
      inputSchema: { ...schema, properties, required: [] },
    };
  }
  if (!ACCESS_TOOLS.has(tool.name)) return tool;
  const drop = FILLABLE_FIELDS[tool.name].filter((key) => key !== "access");
  for (const key of drop) delete properties[key];
  if (Object.hasOwn(properties, "access")) properties.access = ACCESS_PROPERTY;
  return {
    ...tool,
    description: appendDescription(tool, FILLED_DESCRIPTION[tool.name]),
    inputSchema: {
      ...schema,
      properties,
      required: required.filter((key) => key !== "access" && !drop.includes(key)),
    },
  };
}

// --- helper-result redaction -----------------------------------------------------------

function redactValue(value, depth = 0) {
  if (depth > 32) return null;
  if (typeof value === "string") {
    if (value.length > 64 || /^(?:0x)?[0-9a-fA-F]{40,}$/.test(value)) {
      return `${value.slice(0, REDACT_PREFIX)}…`;
    }
    return value;
  }
  if (Array.isArray(value)) return value.map((entry) => redactValue(entry, depth + 1));
  if (value !== null && typeof value === "object") {
    const out = {};
    for (const key of Object.keys(value)) out[key] = redactValue(value[key], depth + 1);
    return out;
  }
  return value;
}

/**
 * The model-visible copy of a validated helper result. A sign result keeps
 * only that it signed; every other result keeps its shape with long hex
 * (addresses, digests, transaction hashes) cut to a short prefix.
 */
export function redactHelperResult(record, { signingOperation = null } = {}) {
  if (record.operation === "sign") {
    const checkpoint = isPlain(record.checkpoint);
    return {
      schema: record.schema,
      helperVersion: record.helperVersion,
      operation: "sign",
      ...(signingOperation !== null ? { signingOperation } : {}),
      signed: true,
      heldLocally: true,
      checkpointHeldLocally: checkpoint,
      next: checkpoint
        ? "The adapter holds the signature and the signed checkpoint. Call agent_handshake_submit_checkpoint, then agent_handshake_submit, with no signature arguments."
        : "The adapter holds the signature. Call agent_handshake_submit with no signature arguments.",
    };
  }
  const redacted = redactValue(record);
  const changed = sortedJson(redacted) !== sortedJson(record);
  return changed ? { ...redacted, heldLocally: true } : redacted;
}

// --- local values ------------------------------------------------------------------------

/** Per-adapter memory of role accesses and helper results, keyed by session and role. */
export function createLocalValues({ now }) {
  const sessions = new Map(); // access -> { access, role, sessionId, seenAtMs }
  const values = new Map(); // `${sessionId}/${role}` -> { address, policyDigest }
  const signs = []; // { key, signatureHex, checkpoint, policyDigest, signingOperation, atMs, spent, checkpointSent }

  const keyOf = (sessionId, role) => `${sessionId}/${role}`;
  const fresh = (entry) => now() - entry.atMs <= SIGN_RESULT_TTL_MS;

  function recordRoleAccess({ access, role, sessionId }) {
    if (typeof access !== "string" || access.length < 1 || access.length > 4096) return;
    if (!["initiator", "responder"].includes(role)) return;
    sessions.set(access, Object.freeze({
      access,
      role,
      sessionId: typeof sessionId === "string" && UUID.test(sessionId) ? sessionId : null,
      seenAtMs: now(),
    }));
  }

  function liveSessions(isAbandoned) {
    return [...sessions.values()].filter((entry) =>
      now() - entry.seenAtMs <= HANDSHAKE_SESSION_TTL_MS && !isAbandoned(entry));
  }

  function recordHelperResult({ step, record, signRequest }) {
    const key = keyOf(step.sessionId, step.role);
    const current = values.get(key) ?? { address: null, policyDigest: null };
    if (typeof record.address === "string" && ADDRESS.test(record.address) && step.operation !== "sign") {
      current.address = record.address.toLowerCase();
    }
    if (typeof record.policyDigest === "string" && DIGEST.test(record.policyDigest)) {
      current.policyDigest = record.policyDigest;
    }
    values.set(key, current);
    if (step.operation !== "sign" || typeof record.signatureHex !== "string" || !SIGNATURE.test(record.signatureHex)) return;
    while (signs.length > 0 && (signs[0].spent || !fresh(signs[0]))) signs.shift();
    if (signs.length >= MAX_SIGN_RESULTS) signs.shift();
    signs.push({
      key,
      signatureHex: record.signatureHex,
      checkpoint: isPlain(record.checkpoint) ? record.checkpoint : null,
      policyDigest: typeof signRequest?.policyDigest === "string" && DIGEST.test(signRequest.policyDigest)
        ? signRequest.policyDigest
        : current.policyDigest,
      signingOperation: typeof signRequest?.operation === "string" ? signRequest.operation : null,
      atMs: now(),
      spent: false,
      checkpointSent: false,
    });
  }

  return Object.freeze({
    recordRoleAccess,
    recordHelperResult,
    sessionFor: (access) => sessions.get(access),
    liveSessions,
    valuesFor: (entry) => (entry.sessionId === null ? null : values.get(keyOf(entry.sessionId, entry.role)) ?? null),
    oldestUnspentSign: (entry) => (entry.sessionId === null
      ? null
      : signs.find((sign) => sign.key === keyOf(entry.sessionId, entry.role) && !sign.spent && fresh(sign)) ?? null),
    oldestUnsentCheckpoint: (entry) => (entry.sessionId === null
      ? null
      : signs.find((sign) => sign.key === keyOf(entry.sessionId, entry.role) && sign.checkpoint !== null &&
          !sign.checkpointSent && !sign.spent && fresh(sign)) ?? null),
  });
}

// --- fill ---------------------------------------------------------------------------------

function sameValue(field, supplied, local) {
  if (field === "sessionKeyAddress" && typeof supplied === "string" && typeof local === "string") {
    return supplied.toLowerCase() === local.toLowerCase();
  }
  if (typeof local === "object" && local !== null) return sortedJson(supplied) === sortedJson(local);
  return supplied === local;
}

/**
 * Fills `field` into `forwarded` from `local` (when the adapter holds one).
 * Returns a refusal object on mismatch, else null.
 */
function fill({ tool, field, args, forwarded, filled, local }) {
  if (local === null || local === undefined) return null;
  if (Object.hasOwn(args, field)) {
    return sameValue(field, args[field], local) ? null : { code: LOCAL_FILL_REFUSALS.mismatch, detail: { tool, field } };
  }
  forwarded[field] = local;
  filled.push(field);
  return null;
}

/**
 * Plans the forwarded args for an access tool once the session is resolved.
 * Returns { forwarded, filled, onSuccess } or { refusal }.
 */
export function planAccessFill({ tool, args, entry, accessFilled, localValues, helperVersion }) {
  const forwarded = { ...args };
  const filled = [];
  if (accessFilled) {
    forwarded.access = entry.access;
    filled.push("access");
  }
  let onSuccess = () => {};
  const local = localValues.valuesFor(entry);
  const steps = [];
  if (tool === JOIN_TOOL) {
    steps.push(["helperVersion", helperVersion]);
    steps.push(["sessionKeyAddress", local?.address ?? null]);
    steps.push(["policyDigest", local?.policyDigest ?? null]);
  } else if (tool === SUBMIT_TOOL) {
    const sign = localValues.oldestUnspentSign(entry);
    steps.push(["policyDigest", sign?.policyDigest ?? local?.policyDigest ?? null]);
    steps.push(["signatureHex", sign?.signatureHex ?? null]);
    if (sign !== null) onSuccess = () => { sign.spent = true; };
  } else if (tool === CHECKPOINT_TOOL) {
    const sign = localValues.oldestUnsentCheckpoint(entry);
    steps.push(["artifactSignatureHex", sign?.signatureHex ?? null]);
    steps.push(["checkpoint", sign?.checkpoint ?? null]);
    if (sign !== null) onSuccess = () => { sign.checkpointSent = true; };
  }
  for (const [field, value] of steps) {
    const refusal = fill({ tool, field, args, forwarded, filled, local: value });
    if (refusal !== null) return { refusal };
  }
  return { forwarded, filled, onSuccess };
}

/** Plans the forwarded invite args from the terms pin. */
export function planInviteFill({ args, terms }) {
  const forwarded = { ...args };
  const filled = [];
  for (const field of FILLABLE_FIELDS[INVITE_TOOL]) {
    const refusal = fill({ tool: INVITE_TOOL, field, args, forwarded, filled, local: terms[field] });
    if (refusal !== null) return { refusal };
  }
  return { forwarded, filled };
}

// --- results ------------------------------------------------------------------------------

function parsedTextItems(result) {
  const out = [];
  if (!isPlain(result) || !Array.isArray(result.content)) return out;
  for (const item of result.content) {
    if (!isPlain(item) || item.type !== "text" || typeof item.text !== "string") continue;
    try { out.push(JSON.parse(item.text)); } catch { /* not JSON */ }
  }
  return out;
}

/** The role access, its sessionId and role from an invite/accept result, or null. */
export function roleAccessFromResult(result, { role }) {
  const candidates = [...parsedTextItems(result), ...(isPlain(result?.structuredContent) ? [result.structuredContent] : [])];
  for (const parsed of candidates) {
    if (!isPlain(parsed) || typeof parsed.roleAccess !== "string") continue;
    let sessionId = typeof parsed.sessionId === "string" && UUID.test(parsed.sessionId) ? parsed.sessionId : null;
    if (sessionId === null) {
      // Fall back to the session the staged helper steps in the same result name.
      const steps = parsed.localAction?.helperSteps ?? (parsed.localAction?.helperStep ? [parsed.localAction.helperStep] : []);
      const ids = new Set((Array.isArray(steps) ? steps : []).map((step) => step?.sessionId).filter((id) => typeof id === "string" && UUID.test(id)));
      if (ids.size === 1) sessionId = [...ids][0];
    }
    return { access: parsed.roleAccess, role, sessionId };
  }
  return null;
}

/** The coordinator receipt nonce carried by a tool result, or null. */
export function serverNonceFromResult(result) {
  const candidates = [
    result?.serverNonce,
    result?._meta?.serverNonce,
    isPlain(result?.structuredContent) ? result.structuredContent.serverNonce : undefined,
    ...parsedTextItems(result).map((parsed) => (isPlain(parsed) ? parsed.serverNonce : undefined)),
  ];
  for (const value of candidates) if (typeof value === "string" && NONCE.test(value)) return value;
  return null;
}

// --- forwarding journal -------------------------------------------------------------------

export function forwardEntryHash(entry) {
  const { hash: _hash, ...rest } = entry;
  return createHash("sha256").update(sortedJson(rest)).digest("hex");
}

/**
 * Append-only, hash-chained journal of forwarded-args rewrites:
 * <TMPDIR>/.clockchain/adapter-forwards/forwards.jsonl (dir 0700, file 0600,
 * O_NOFOLLOW, fsync'd). The harness exports it with the signer's delegation
 * journal. It holds the signatures, checkpoints and (for accept by reference)
 * the spent responder invitation — the same bytes the run bundle already
 * carries — and lives in the company's private TMPDIR.
 */
export function createForwardJournal({ tmpRoot, now }) {
  const dir = join(tmpRoot, ADAPTER_FORWARDS_DIR);
  const path = join(tmpRoot, ADAPTER_FORWARDS_FILE);
  let state = null; // { seq, prevHash }
  let chain = Promise.resolve();
  const uid = typeof process.getuid === "function" ? process.getuid() : undefined;

  async function ensureDir() {
    for (const [target, mode] of [[join(tmpRoot, ".clockchain"), 0o022], [dir, 0o077]]) {
      try { await mkdir(target, { mode: 0o700 }); } catch (error) { if (error?.code !== "EEXIST") throw error; }
      const stats = await lstat(target);
      if (!stats.isDirectory() || stats.isSymbolicLink() || (uid !== undefined && stats.uid !== uid) || (stats.mode & mode) !== 0) {
        throw new Error("journal directory is not private");
      }
    }
  }

  async function loadState() {
    let text = "";
    try { text = await readFile(path, "utf8"); } catch (error) { if (error?.code !== "ENOENT") throw error; }
    const lines = text.split("\n").filter((line) => line.length > 0);
    if (lines.length === 0) return { seq: 0, prevHash: null };
    const last = JSON.parse(lines.at(-1));
    if (typeof last?.hash !== "string" || !Number.isSafeInteger(last?.seq)) throw new Error("journal tail unreadable");
    return { seq: last.seq + 1, prevHash: last.hash };
  }

  async function write(record) {
    await ensureDir();
    state ??= await loadState();
    const entry = { v: 1, seq: state.seq, prevHash: state.prevHash, ts: new Date(now()).toISOString(), ...record };
    entry.hash = forwardEntryHash(entry);
    const handle = await open(path, fsConstants.O_WRONLY | fsConstants.O_APPEND | fsConstants.O_CREAT | fsConstants.O_NOFOLLOW, 0o600);
    try {
      await handle.write(`${JSON.stringify(entry)}\n`);
      await handle.sync();
    } finally {
      await handle.close();
    }
    state = { seq: entry.seq + 1, prevHash: entry.hash };
  }

  return Object.freeze({
    path,
    /**
     * How many entries of this epoch's journal name `tool` (the invite-budget
     * seed), leaving out the ones journaled as a transient refusal (they minted
     * nothing). An absent journal is 0; an unreadable line counts nothing for itself.
     */
    async count(tool) {
      let text = "";
      try { text = await readFile(path, "utf8"); } catch (error) { if (error?.code !== "ENOENT") throw error; }
      let n = 0;
      for (const line of text.split("\n")) {
        if (line.length === 0) continue;
        try {
          const entry = JSON.parse(line);
          if (entry?.tool === tool && entry?.outcome !== TRANSIENT_OUTCOME) n += 1;
        } catch { /* not an entry */ }
      }
      return n;
    },
    /** Appends one entry; resolves false (never throws) when it could not be written. */
    append(record) {
      const run = chain.then(() => write(record)).then(() => true, () => { state = null; return false; });
      chain = run;
      return run;
    },
  });
}
