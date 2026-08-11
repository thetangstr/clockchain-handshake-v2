import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";
import { gzipSync } from "node:zlib";

import { executeAgentSigningRequest } from "../src/agent-cli/signing-request.mjs";
import { canonicalBytes } from "../src/core/canonical.mjs";
import { buildAgentCliFixture } from "./support/agent-cli-fixture.mjs";

test("signs exact decompressed canonical bytes only after every local binding passes", async () => {
  const fixture = await buildAgentCliFixture();
  let calls = 0;
  const result = await executeAgentSigningRequest({
    address: fixture.parties.initiator.sessionKeyAddress,
    localPolicy: fixture.policy,
    nowMs: fixture.nowMs,
    request: fixture.request,
    rootKeyRing: fixture.rootKeyRing,
    sign: async (input) => {
      calls += 1;
      assert.equal(input.bytesGzipBase64Url, fixture.request.bytesGzipBase64Url);
      return {
        address: fixture.parties.initiator.sessionKeyAddress,
        bytesSha256: fixture.request.bytesSha256,
        signatureHex: "0x" + "1".repeat(130),
      };
    },
  });
  assert.equal(calls, 1);
  assert.equal(result.bytesSha256, fixture.request.bytesSha256);
});

test("signs session-bound evidence whose schema binds through sessionDigest rather than sessionId", async () => {
  const fixture = await buildAgentCliFixture();
  const payload = fixture.evidence.initiator.result;
  const bytes = canonicalBytes(payload);
  const request = {
    ...fixture.request,
    operation: "evidence",
    bytesGzipBase64Url: gzipSync(bytes).toString("base64url"),
    bytesSha256: createHash("sha256").update(bytes).digest("hex"),
  };
  let calls = 0;

  await executeAgentSigningRequest({
    address: fixture.parties.initiator.sessionKeyAddress,
    localPolicy: fixture.policy,
    nowMs: fixture.nowMs,
    request,
    rootKeyRing: fixture.rootKeyRing,
    sign: async (input) => {
      calls += 1;
      return {
        address: fixture.parties.initiator.sessionKeyAddress,
        bytesSha256: request.bytesSha256,
        signatureHex: "0x" + "1".repeat(130),
      };
    },
  });

  assert.equal(calls, 1);
});

test("never reaches the signer for policy, trust, schema, operation, role, session, bytes, or action drift", async () => {
  const fixture = await buildAgentCliFixture();
  let calls = 0;
  const sign = async () => { calls += 1; return {}; };
  const mutations = [
    { ...fixture.request, helperVersion: "2.1.1" },
    { ...fixture.request, schema: "clockchain.agent-handshake-signing-request/v2" },
    { ...fixture.request, operation: "acceptance" },
    { ...fixture.request, role: "responder" },
    { ...fixture.request, sessionId: "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee" },
    { ...fixture.request, repositorySha: "e".repeat(40) },
    { ...fixture.request, bytesSha256: "f".repeat(64) },
    { ...fixture.request, externalBusinessActionPerformed: true },
    { ...fixture.request, policyDigest: "f".repeat(64) },
    { ...fixture.request, terms: { ...fixture.request.terms, statement: "Other terms" } },
    { ...fixture.request, extra: true },
  ];
  for (const request of mutations) {
    await assert.rejects(() => executeAgentSigningRequest({
      address: fixture.parties.initiator.sessionKeyAddress,
      localPolicy: fixture.policy,
      nowMs: fixture.nowMs,
      request,
      rootKeyRing: fixture.rootKeyRing,
      sign,
    }));
  }
  await assert.rejects(() => executeAgentSigningRequest({
    address: fixture.parties.initiator.sessionKeyAddress,
    localPolicy: fixture.policy,
    nowMs: fixture.nowMs,
    request: fixture.request,
    rootKeyRing: [{ ...fixture.rootKeyRing[0], fingerprint: "f".repeat(64) }],
    sign,
  }));
  assert.equal(calls, 0);
});
