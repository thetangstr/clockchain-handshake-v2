import assert from "node:assert/strict";
import test from "node:test";

import {
  validateHostRootKeyRing,
  verifyPinnedHostSessionKey,
} from "../src/agent-cli/trust-roots.mjs";
import { buildAgentCliFixture } from "./support/agent-cli-fixture.mjs";

test("accepts only a current or previous pinned root with exact validity", async () => {
  const fixture = await buildAgentCliFixture();
  const ring = validateHostRootKeyRing(fixture.rootKeyRing, { nowMs: fixture.nowMs });
  assert.equal(ring.length, 1);
  assert.equal(verifyPinnedHostSessionKey(fixture.hostSessionKeyCertificate, {
    expectedRepositorySha: fixture.request.repositorySha,
    expectedSessionId: fixture.request.sessionId,
    nowMs: fixture.nowMs,
    rootKeyRing: ring,
    sessionDeadlineMs: Number(fixture.request.sessionDeadlineMs),
  }).certificate.sessionId, fixture.request.sessionId);
});

test("rejects unknown, stale, future, duplicate, mismatched fingerprint, and oversized rings", async () => {
  const fixture = await buildAgentCliFixture();
  const root = fixture.rootKeyRing[0];
  for (const ring of [
    [{ ...root, notAfterMs: String(fixture.nowMs) }],
    [{ ...root, notBeforeMs: String(fixture.nowMs + 1) }],
    [{ ...root, fingerprint: "f".repeat(64) }],
    [root, root],
    [root, { ...root, kid: "previous" }, { ...root, kid: "older" }],
  ]) assert.throws(() => validateHostRootKeyRing(ring, { nowMs: fixture.nowMs }));
  assert.throws(() => verifyPinnedHostSessionKey(fixture.hostSessionKeyCertificate, {
    expectedRepositorySha: fixture.request.repositorySha,
    expectedSessionId: fixture.request.sessionId,
    nowMs: fixture.nowMs,
    rootKeyRing: [{ ...root, kid: "unknown" }],
    sessionDeadlineMs: Number(fixture.request.sessionDeadlineMs),
  }));
});
