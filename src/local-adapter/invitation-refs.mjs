// 2.1.12 invitation pass-by-reference (live p6-l-2026-10-02-1).
//
// The responder invitation is a ~670-character bearer token. Twice in live
// runs (p6-l-2026-10-01-7 and p6-l-2026-10-02-1) the glm-5.3-flash provider
// re-typed it from the opened rendezvous box and changed one base64url
// character (payload key "expMs" became "expms", identical length), so the
// invitation could never be accepted. The durable fix is that the model never
// carries the invitation at all: the company's local services hand it to each
// other through a private, company-scoped store, and the model only carries a
// short, single-use handle.
//
// Store format (v1) — shared byte-for-byte with the company signer
// (travel_mvp src/lib/agent-signer/invitation-refs.ts):
//
//   <TMPDIR>/.clockchain/invitation-refs/            0700, owned by this uid
//   <TMPDIR>/.clockchain/invitation-refs/<ref>.json  0600, O_EXCL|O_NOFOLLOW
//
//   <ref>   = "invref_" + 32 lowercase hex (128 random bits)
//   record  = {"v":1,"kind":"received"|"issued","invitation":"<string>",
//              "createdMs":"<decimal>","expMs":"<decimal>"}
//
//   kind "received": written by the signer's open_sealed (the counterparty's
//                    invitation); consumed by agent_handshake_accept_invitation.
//   kind "issued":   written by this adapter after agent_handshake_invite
//                    (refs mode); consumed by the signer's seal_to.
//
// Claiming is an atomic rename of <ref>.json to <ref>.claimed-<random>, so a
// ref is used by exactly one call; the claimer either consumes it (unlink, on
// success) or releases it (rename back, on a failure that left the invitation
// unspent). Both company services run as the same <U>-svc uid with the same
// TMPDIR, which is private to that uid; another company's ref names a file in
// another uid's private directory and never resolves here. The invitation
// bytes never leave the company's trust domain: the store is local, and the
// only thing returned to the model is the ref.

import { randomBytes } from "node:crypto";
import { constants as fsConstants } from "node:fs";
import { lstat, mkdir, open, readdir, rename, unlink } from "node:fs/promises";
import { join } from "node:path";

export const INVITATION_REF_RE = /^invref_[0-9a-f]{32}$/;
export const INVITATION_REF_TTL_MS = 15 * 60_000;
export const INVITATION_REF_KINDS = Object.freeze(["received", "issued"]);
export const INVITATION_REF_DIR = ".clockchain/invitation-refs";

const MAX_RECORD_BYTES = 8192;
const MAX_INVITATION_CHARS = 4096;
const RECORD_KEYS = Object.freeze(["createdMs", "expMs", "invitation", "kind", "v"]);
const PRINTABLE_ASCII = /^[\x21-\x7e]+$/;
const DECIMAL = /^(?:0|[1-9][0-9]{0,15})$/;
const CLAIMED_RE = /^(invref_[0-9a-f]{32})\.claimed-[0-9a-f]{16}$/;
const RECORD_FILE_RE = /^(invref_[0-9a-f]{32})\.json$/;

export const INVITATION_REF_REFUSALS = Object.freeze({
  unknown: "INVITATION_REF_UNKNOWN",
  expired: "INVITATION_REF_EXPIRED",
  store: "INVITATION_REF_STORE_UNAVAILABLE",
  invalid: "INVITATION_REF_INVALID",
});

export class InvitationRefError extends Error {
  constructor(code) {
    super(code);
    this.name = "InvitationRefError";
    this.code = code;
  }
}

function refuse(code) {
  throw new InvitationRefError(code);
}

function currentUid() {
  return typeof process.getuid === "function" ? process.getuid() : undefined;
}

function ownedDir(stats, uid) {
  return stats.isDirectory() && !stats.isSymbolicLink() && (uid === undefined || stats.uid === uid);
}

// The store's ancestry inside TMPDIR: .clockchain must be a real directory
// owned by this uid and not writable by group/other; invitation-refs must be
// private (0700). TMPDIR itself is private to the <U>-svc uid on the fleet
// (and is the macOS per-user TMPDIR elsewhere) — the same trust root the
// adapter's handshake state and sign_agent_contract_bind already rely on.
async function storeDir({ tmpRoot, uid, create }) {
  if (typeof tmpRoot !== "string" || tmpRoot.length === 0) refuse(INVITATION_REF_REFUSALS.store);
  const clockchain = join(tmpRoot, ".clockchain");
  const dir = join(clockchain, "invitation-refs");
  try {
    for (const [path, privateOnly] of [[clockchain, false], [dir, true]]) {
      if (create) {
        try {
          await mkdir(path, { mode: 0o700 });
        } catch (error) {
          if (error?.code !== "EEXIST") throw error;
        }
      }
      const stats = await lstat(path);
      if (!ownedDir(stats, uid)) refuse(INVITATION_REF_REFUSALS.store);
      if ((stats.mode & (privateOnly ? 0o077 : 0o022)) !== 0) refuse(INVITATION_REF_REFUSALS.store);
    }
  } catch (error) {
    if (error instanceof InvitationRefError) throw error;
    if (!create && error?.code === "ENOENT") refuse(INVITATION_REF_REFUSALS.unknown);
    refuse(INVITATION_REF_REFUSALS.store);
  }
  return dir;
}

function validInvitationText(invitation) {
  return typeof invitation === "string" &&
    invitation.length > 0 && invitation.length <= MAX_INVITATION_CHARS &&
    PRINTABLE_ASCII.test(invitation);
}

async function sweepExpired(dir, nowMs) {
  // Best effort: drop expired records and stale claims so the store never
  // accumulates bearer material. A failure here never fails the caller.
  let names;
  try { names = await readdir(dir); } catch { return; }
  for (const name of names) {
    const path = join(dir, name);
    try {
      if (RECORD_FILE_RE.test(name)) {
        const record = await readRecord(path, undefined);
        if (record === null || BigInt(record.expMs) <= BigInt(nowMs)) await unlink(path);
      } else if (CLAIMED_RE.test(name)) {
        const stats = await lstat(path);
        if (nowMs - stats.mtimeMs > INVITATION_REF_TTL_MS) await unlink(path);
      }
    } catch { /* ignore */ }
  }
}

async function readRecord(path, uid) {
  let handle;
  try {
    handle = await open(path, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
    const stats = await handle.stat();
    if (
      !stats.isFile() || (uid !== undefined && stats.uid !== uid) ||
      (stats.mode & 0o077) !== 0 || stats.size <= 0 || stats.size > MAX_RECORD_BYTES
    ) return null;
    const text = (await handle.readFile({ encoding: "utf8" }));
    const record = JSON.parse(text);
    if (record === null || typeof record !== "object" || Array.isArray(record)) return null;
    const keys = Object.keys(record).sort();
    if (keys.length !== RECORD_KEYS.length || keys.some((key, index) => key !== RECORD_KEYS[index])) return null;
    if (
      record.v !== 1 || !INVITATION_REF_KINDS.includes(record.kind) ||
      !validInvitationText(record.invitation) ||
      typeof record.createdMs !== "string" || !DECIMAL.test(record.createdMs) ||
      typeof record.expMs !== "string" || !DECIMAL.test(record.expMs)
    ) return null;
    return record;
  } catch {
    return null;
  } finally {
    await handle?.close().catch(() => {});
  }
}

/**
 * Store an invitation for the company's other local service and return its
 * single-use ref. Never echoes the invitation.
 */
export async function putInvitationRef({ tmpRoot, kind, invitation, nowMs = Date.now(), uid = currentUid() } = {}) {
  if (!INVITATION_REF_KINDS.includes(kind) || !validInvitationText(invitation) || !Number.isSafeInteger(nowMs)) {
    refuse(INVITATION_REF_REFUSALS.invalid);
  }
  const dir = await storeDir({ tmpRoot, uid, create: true });
  await sweepExpired(dir, nowMs);
  const ref = `invref_${randomBytes(16).toString("hex")}`;
  const body = JSON.stringify({
    v: 1,
    kind,
    invitation,
    createdMs: String(nowMs),
    expMs: String(nowMs + INVITATION_REF_TTL_MS),
  });
  let handle;
  try {
    handle = await open(
      join(dir, `${ref}.json`),
      fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL | fsConstants.O_NOFOLLOW,
      0o600,
    );
    await handle.writeFile(body, "utf8");
    await handle.sync().catch(() => {});
  } catch {
    refuse(INVITATION_REF_REFUSALS.store);
  } finally {
    await handle?.close().catch(() => {});
  }
  return ref;
}

/**
 * Claim a ref of `kind` for exactly one use. Resolves to
 *   { invitation, consume(), release() }
 * — call consume() once the invitation has been spent (or is known bad) and
 * release() when the attempt failed without spending it. A ref that is
 * unknown, already used, in flight, foreign, or of the wrong kind refuses
 * INVITATION_REF_UNKNOWN; an expired one INVITATION_REF_EXPIRED.
 */
export async function claimInvitationRef({ tmpRoot, ref, kind, nowMs = Date.now(), uid = currentUid() } = {}) {
  if (typeof ref !== "string" || !INVITATION_REF_RE.test(ref) || !INVITATION_REF_KINDS.includes(kind)) {
    refuse(INVITATION_REF_REFUSALS.unknown);
  }
  const dir = await storeDir({ tmpRoot, uid, create: false });
  const source = join(dir, `${ref}.json`);
  const claimed = join(dir, `${ref}.claimed-${randomBytes(8).toString("hex")}`);
  try {
    await rename(source, claimed);
  } catch (error) {
    refuse(error?.code === "ENOENT" ? INVITATION_REF_REFUSALS.unknown : INVITATION_REF_REFUSALS.store);
  }
  const record = await readRecord(claimed, uid);
  if (record === null) {
    await unlink(claimed).catch(() => {});
    refuse(INVITATION_REF_REFUSALS.unknown);
  }
  if (record.kind !== kind) {
    // Presented to the wrong tool: put it back for the right one.
    await rename(claimed, source).catch(() => {});
    refuse(INVITATION_REF_REFUSALS.unknown);
  }
  if (BigInt(record.expMs) <= BigInt(nowMs)) {
    await unlink(claimed).catch(() => {});
    refuse(INVITATION_REF_REFUSALS.expired);
  }
  let settled = false;
  return Object.freeze({
    invitation: record.invitation,
    async consume() {
      if (settled) return;
      settled = true;
      await unlink(claimed).catch(() => {});
    },
    async release() {
      if (settled) return;
      settled = true;
      await rename(claimed, source).catch(() => unlink(claimed).catch(() => {}));
    },
  });
}

/** Human-safe shape of an opaque token: segment lengths only, never bytes. */
export function invitationShape(invitation) {
  return typeof invitation === "string"
    ? invitation.split(".").map((part) => part.length).join(".")
    : typeof invitation;
}

// 2.1.13 deliver-first guard (live p6-l-2026-10-02-2). The adapter issued
// `ref` (kind "issued") from agent_handshake_invite; the company signer's
// seal_to claims and consumes it once the invitation is sealed to the
// provider. The record's absence is therefore the delivery signal:
//
//   "consumed" — <ref>.json is gone (sealed, or a seal_to is in flight);
//   "pending"  — the record is still there and has not expired, or the store
//                cannot be read (fail closed: nothing proves delivery);
//   "expired"  — the record is still there but past its TTL (or `expMs`, the
//                adapter's own record of it, has passed) or unreadable, so it
//                can never be sealed: the caller must start a fresh invitation.
export async function issuedInvitationRefState({ tmpRoot, ref, expMs, nowMs = Date.now(), uid = currentUid() } = {}) {
  if (typeof ref !== "string" || !INVITATION_REF_RE.test(ref) || typeof tmpRoot !== "string" || tmpRoot.length === 0) {
    return "pending";
  }
  const path = join(tmpRoot, INVITATION_REF_DIR, `${ref}.json`);
  try {
    await lstat(path);
  } catch (error) {
    return error?.code === "ENOENT" ? "consumed" : "pending";
  }
  if (Number.isSafeInteger(expMs) && expMs <= nowMs) return "expired";
  const record = await readRecord(path, uid);
  if (record === null || record.kind !== "issued") return "expired";
  return BigInt(record.expMs) <= BigInt(nowMs) ? "expired" : "pending";
}

/** Remove an issued record that can no longer be delivered. Best effort. */
export async function discardIssuedInvitationRef({ tmpRoot, ref } = {}) {
  if (typeof ref !== "string" || !INVITATION_REF_RE.test(ref) || typeof tmpRoot !== "string") return;
  await unlink(join(tmpRoot, INVITATION_REF_DIR, `${ref}.json`)).catch(() => {});
}
