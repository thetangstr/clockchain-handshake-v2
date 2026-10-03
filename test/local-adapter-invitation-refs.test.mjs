// 2.1.12: the company-private invitation ref store (live p6-l-2026-10-02-1).
// The model never carries the responder invitation; the company's local
// services hand it to each other through this store and the model carries a
// single-use ref.

import assert from "node:assert/strict";
import { chmod, lstat, mkdir, mkdtemp, readdir, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { LOCAL_ADAPTER_VERSION } from "../src/agent-handshake/v2/constants.mjs";
import { checkInvitationShape } from "../src/local-adapter/server.mjs";
import {
  INVITATION_REF_RE,
  INVITATION_REF_TTL_MS,
  claimInvitationRef,
  putInvitationRef,
} from "../src/local-adapter/invitation-refs.mjs";

const INVITATION = `${"eyJhbGciOiJIUzI1NiJ9".padEnd(628, "A")}.${"B".repeat(43)}`;

async function root(t) {
  const dir = await mkdtemp(join(tmpdir(), "invref-"));
  t.after(() => rm(dir, { recursive: true, force: true }));
  return dir;
}

async function refusal(promise) {
  try {
    await promise;
  } catch (error) {
    return error.code;
  }
  return "no refusal";
}

test("version is 2.2.0", () => {
  assert.equal(LOCAL_ADAPTER_VERSION, "2.2.0");
});

test("put returns a short ref, writes a private record, and claim returns the exact bytes once", async (t) => {
  const tmpRoot = await root(t);
  const ref = await putInvitationRef({ tmpRoot, kind: "received", invitation: INVITATION, nowMs: 1_000 });
  assert.match(ref, INVITATION_REF_RE);
  assert.ok(ref.length < 48);
  const dir = join(tmpRoot, ".clockchain", "invitation-refs");
  assert.equal((await lstat(dir)).mode & 0o777, 0o700);
  assert.equal((await lstat(join(dir, `${ref}.json`))).mode & 0o777, 0o600);
  const record = JSON.parse(await readFile(join(dir, `${ref}.json`), "utf8"));
  assert.deepEqual(record, {
    v: 1, kind: "received", invitation: INVITATION, createdMs: "1000", expMs: String(1_000 + INVITATION_REF_TTL_MS),
  });

  const claim = await claimInvitationRef({ tmpRoot, ref, kind: "received", nowMs: 2_000 });
  assert.equal(claim.invitation, INVITATION);
  // In flight: a concurrent second claim cannot see it.
  assert.equal(await refusal(claimInvitationRef({ tmpRoot, ref, kind: "received", nowMs: 2_000 })), "INVITATION_REF_UNKNOWN");
  await claim.consume();
  assert.equal(await refusal(claimInvitationRef({ tmpRoot, ref, kind: "received", nowMs: 2_000 })), "INVITATION_REF_UNKNOWN");
  assert.deepEqual(await readdir(dir), []);
});

test("release puts an unspent invitation back for one more claim", async (t) => {
  const tmpRoot = await root(t);
  const ref = await putInvitationRef({ tmpRoot, kind: "received", invitation: INVITATION, nowMs: 1_000 });
  const first = await claimInvitationRef({ tmpRoot, ref, kind: "received", nowMs: 1_001 });
  await first.release();
  const second = await claimInvitationRef({ tmpRoot, ref, kind: "received", nowMs: 1_002 });
  assert.equal(second.invitation, INVITATION);
  await second.consume();
});

test("a ref presented to the wrong tool is refused and left for the right one", async (t) => {
  const tmpRoot = await root(t);
  const ref = await putInvitationRef({ tmpRoot, kind: "issued", invitation: INVITATION, nowMs: 1_000 });
  assert.equal(await refusal(claimInvitationRef({ tmpRoot, ref, kind: "received", nowMs: 1_001 })), "INVITATION_REF_UNKNOWN");
  const claim = await claimInvitationRef({ tmpRoot, ref, kind: "issued", nowMs: 1_002 });
  assert.equal(claim.invitation, INVITATION);
});

test("expired refs are refused and removed; malformed refs never touch the filesystem", async (t) => {
  const tmpRoot = await root(t);
  const ref = await putInvitationRef({ tmpRoot, kind: "received", invitation: INVITATION, nowMs: 1_000 });
  assert.equal(
    await refusal(claimInvitationRef({ tmpRoot, ref, kind: "received", nowMs: 1_000 + INVITATION_REF_TTL_MS })),
    "INVITATION_REF_EXPIRED",
  );
  assert.deepEqual(await readdir(join(tmpRoot, ".clockchain", "invitation-refs")), []);
  for (const bad of [undefined, "", "invref_x", `invref_${"A".repeat(32)}`, `../${"a".repeat(32)}`, INVITATION]) {
    assert.equal(await refusal(claimInvitationRef({ tmpRoot, ref: bad, kind: "received" })), "INVITATION_REF_UNKNOWN");
  }
});

test("another company's ref (a different private TMPDIR) never resolves", async (t) => {
  const companyA = await root(t);
  const companyB = await root(t);
  const ref = await putInvitationRef({ tmpRoot: companyA, kind: "received", invitation: INVITATION });
  await putInvitationRef({ tmpRoot: companyB, kind: "received", invitation: INVITATION });
  assert.equal(await refusal(claimInvitationRef({ tmpRoot: companyB, ref, kind: "received" })), "INVITATION_REF_UNKNOWN");
});

test("a store that is not private, or is a symlink, is refused", async (t) => {
  const open = await root(t);
  await mkdir(join(open, ".clockchain", "invitation-refs"), { recursive: true });
  await chmod(join(open, ".clockchain", "invitation-refs"), 0o755);
  assert.equal(
    await refusal(putInvitationRef({ tmpRoot: open, kind: "received", invitation: INVITATION })),
    "INVITATION_REF_STORE_UNAVAILABLE",
  );

  const linked = await root(t);
  const elsewhere = await root(t);
  await mkdir(join(linked, ".clockchain"), { mode: 0o700 });
  await symlink(elsewhere, join(linked, ".clockchain", "invitation-refs"));
  assert.equal(
    await refusal(putInvitationRef({ tmpRoot: linked, kind: "received", invitation: INVITATION })),
    "INVITATION_REF_STORE_UNAVAILABLE",
  );
});

test("a planted record that is a symlink or group-readable is not honoured", async (t) => {
  const tmpRoot = await root(t);
  const ref = await putInvitationRef({ tmpRoot, kind: "received", invitation: INVITATION });
  const dir = join(tmpRoot, ".clockchain", "invitation-refs");
  await chmod(join(dir, `${ref}.json`), 0o644);
  assert.equal(await refusal(claimInvitationRef({ tmpRoot, ref, kind: "received" })), "INVITATION_REF_UNKNOWN");

  const target = join(tmpRoot, "target.json");
  await writeFile(target, JSON.stringify({ v: 1, kind: "received", invitation: INVITATION, createdMs: "1", expMs: "9999999999999" }), { mode: 0o600 });
  const planted = `invref_${"c".repeat(32)}`;
  await symlink(target, join(dir, `${planted}.json`));
  assert.equal(await refusal(claimInvitationRef({ tmpRoot, ref: planted, kind: "received" })), "INVITATION_REF_UNKNOWN");
});

test("put refuses non-invitation text and unknown kinds", async (t) => {
  const tmpRoot = await root(t);
  for (const [kind, invitation] of [["received", ""], ["received", "has space"], ["received", "x".repeat(4097)], ["other", INVITATION]]) {
    assert.equal(await refusal(putInvitationRef({ tmpRoot, kind, invitation })), "INVITATION_REF_INVALID");
  }
});

test("the guard names the altered field when the length is unchanged (live p6-l-2026-10-02-1)", () => {
  const payload = Buffer.from(JSON.stringify({
    alg: "HS256", allowedTools: ["agent_handshake_accept_invitation"], aud: "clockchain-agent-handshake",
    expMs: "1790952802473", iss: "https://mcp.clockchain.network", jti: "a982c093-0000-4000-8000-000000000000",
    kid: "role-2026-08-active", nbfMs: "1790952622473", role: "responder", sessionId: "e3f35ea4-0000-4491-89eb-2af8c02abd75",
    statementDigest: "e".repeat(64), typ: "clockchain-agent-handshake-role-access", v: 1,
  })).toString("base64url");
  const altered = Buffer.from(Buffer.from(payload, "base64url").toString().replace('"expMs"', '"expms"')).toString("base64url");
  const text = checkInvitationShape(`${altered}.${"A".repeat(43)}`);
  assert.match(text, /^INVITATION_CORRUPTED: /);
  assert.match(text, /same length/);
  assert.match(text, /"expms"/);
  assert.match(text, /"expMs"/);
  assert.equal(text.includes(altered), false);
});

// 2.1.13 deliver-first guard: the issued record's absence is the delivery signal.
const { issuedInvitationRefState, discardIssuedInvitationRef } = await import("../src/local-adapter/invitation-refs.mjs");

test("2.1.13 issuedInvitationRefState: pending, consumed by seal_to, expired, and discarded", async (t) => {
  const tmpRoot = await root(t);
  const ref = await putInvitationRef({ tmpRoot, kind: "issued", invitation: INVITATION, nowMs: 1_000 });
  assert.equal(await issuedInvitationRefState({ tmpRoot, ref, nowMs: 2_000 }), "pending");
  assert.equal(await issuedInvitationRefState({ tmpRoot, ref, nowMs: 1_000 + INVITATION_REF_TTL_MS }), "expired");
  assert.equal(await issuedInvitationRefState({ tmpRoot, ref, expMs: 1_500, nowMs: 2_000 }), "expired");
  const claim = await claimInvitationRef({ tmpRoot, ref, kind: "issued", nowMs: 2_000 });
  assert.equal(await issuedInvitationRefState({ tmpRoot, ref, nowMs: 2_000 }), "consumed", "a seal_to in flight counts");
  await claim.release();
  assert.equal(await issuedInvitationRefState({ tmpRoot, ref, nowMs: 2_000 }), "pending", "a released claim is undelivered");
  await (await claimInvitationRef({ tmpRoot, ref, kind: "issued", nowMs: 2_000 })).consume();
  assert.equal(await issuedInvitationRefState({ tmpRoot, ref, nowMs: 2_000 }), "consumed");

  const other = await putInvitationRef({ tmpRoot, kind: "issued", invitation: INVITATION, nowMs: 1_000 });
  await discardIssuedInvitationRef({ tmpRoot, ref: other });
  assert.equal(await issuedInvitationRefState({ tmpRoot, ref: other, nowMs: 2_000 }), "consumed");
  const received = await putInvitationRef({ tmpRoot, kind: "received", invitation: INVITATION, nowMs: 1_000 });
  assert.equal(await issuedInvitationRefState({ tmpRoot, ref: received, nowMs: 2_000 }), "expired", "not an issued record: can never be sealed");
});
