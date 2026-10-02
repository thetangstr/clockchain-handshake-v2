// 2.1.11: the adapter refuses a responder invitation that was altered while
// the model copied it (live p6-l-2026-10-01-7: payload key "expMs" came back
// as "expms" — a one-character base64url substitution at identical length),
// locally, before it reaches the coordinator.

import assert from "node:assert/strict";
import { createHmac } from "node:crypto";
import test from "node:test";

import { LOCAL_ADAPTER_VERSION } from "../src/agent-handshake/v2/constants.mjs";
import { checkInvitationShape } from "../src/local-adapter/server.mjs";

const PAYLOAD = {
  alg: "HS256",
  allowedTools: ["agent_handshake_accept_invitation"],
  aud: "clockchain-agent-handshake",
  expMs: "1790911474141",
  iss: "https://mcp.clockchain.network",
  jti: "b532fc9a-385f-448f-a90f-a16f26056f37",
  kid: "role-2026-08-active",
  nbfMs: "1790911292380",
  role: "responder",
  sessionId: "c67e3a39-832f-4c8c-bbcc-2c5e63264c82",
  statementDigest: "e25f0da08907ee8a3b3e2a2d316eea3413effb60eb74d196a4f63c8d8a5f56d9",
  typ: "clockchain-agent-handshake-role-access",
  v: 1,
};

function mint(payload = PAYLOAD) {
  const segment = Buffer.from(JSON.stringify(payload)).toString("base64url");
  const sig = createHmac("sha256", Buffer.alloc(32, 7)).update(segment, "ascii").digest("base64url");
  return `${segment}.${sig}`;
}

test("version is 2.1.13 (the 2.1.11 guard ships unchanged in behaviour)", () => {
  assert.equal(LOCAL_ADAPTER_VERSION, "2.1.13");
});

test("a well-formed invitation passes the shape check", () => {
  assert.equal(checkInvitationShape(mint()), null);
});

test("the live corruption (expMs -> expms, same length) is refused with lengths", () => {
  const good = mint();
  const [segment, sig] = good.split(".");
  const bad = `${Buffer.from(Buffer.from(segment, "base64url").toString().replace('"expMs"', '"expms"')).toString("base64url")}.${sig}`;
  assert.notEqual(bad, good);
  assert.equal(bad.length, good.length);
  const refusal = checkInvitationShape(bad);
  assert.match(refusal, /^INVITATION_CORRUPTED: /);
  assert.match(refusal, new RegExp(`expected ${good.split(".")[0].length}\\.43`));
  assert.equal(refusal.includes(bad), false, "never echo the token");
});

test("truncation, a dropped character, and a missing signature are refused", () => {
  const good = mint();
  for (const bad of [good.slice(0, 200), good.slice(0, 100) + good.slice(101), good.split(".")[0], `${good}x`, `a.${good}`]) {
    assert.match(checkInvitationShape(bad) ?? "", /^INVITATION_CORRUPTED: /, bad.slice(-10));
  }
});

test("non-strings and wrong role/tools are refused", () => {
  assert.match(checkInvitationShape(42), /^INVITATION_CORRUPTED/);
  assert.match(checkInvitationShape(mint({ ...PAYLOAD, role: "initiator" })), /^INVITATION_CORRUPTED/);
  assert.match(checkInvitationShape(mint({ ...PAYLOAD, allowedTools: ["agent_handshake_join"] })), /^INVITATION_CORRUPTED/);
});
