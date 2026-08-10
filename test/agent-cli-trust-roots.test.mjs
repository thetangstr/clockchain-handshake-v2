import assert from "node:assert/strict";
import test from "node:test";

import {
  EMBEDDED_HOST_ROOT_KEY_RING,
  validateHostRootKeyRing,
  verifyPinnedHostSessionKey,
} from "../src/agent-cli/trust-roots.mjs";
import { buildAgentCliFixture } from "./support/agent-cli-fixture.mjs";

test("production helper embeds the public half of the SSM-backed host root", () => {
  assert.deepEqual(EMBEDDED_HOST_ROOT_KEY_RING, [{
    kid: "root-2026-08",
    publicKey: "mjsBe8vyv46uEu0Fa+oH5kCOlJRbZ8nbfIrBSp4aV8Q=",
    fingerprint: "da2771c36bf2298525d2bbd8351b6122bb67115e9979624e8bb56537bcf71ed8",
    notBeforeMs: "1785542400000",
    notAfterMs: "1943308800000",
  }]);
  assert.equal(validateHostRootKeyRing(EMBEDDED_HOST_ROOT_KEY_RING, {
    nowMs: Date.UTC(2026, 7, 10),
  }).length, 1);
});

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
