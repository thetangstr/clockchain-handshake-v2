import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { gzipSync } from "node:zlib";
import test from "node:test";

import {
  executeDirectAgentSigningRequest,
  validateDirectAgentSigningRequest,
  validateDirectAgentSigningResult,
} from "../src/direct-agent-signer/adapter.mjs";
import { canonicalBytes } from "../src/core/canonical.mjs";
import { buildAgentCliFixture } from "./support/agent-cli-fixture.mjs";

const SCHEMA = "clockchain.direct-agent-signer-request/v1";
const PURPOSE = "agent_contract_direct_signature";
const IDENTITY_PURPOSE = "agent_contract_direct_identity";

function directRequest(fixture, payload = { schema: "local.test/v1", value: "sign exactly this" }) {
  const bytes = canonicalBytes(payload);
  return {
    schema: SCHEMA,
    role: "initiator",
    purpose: PURPOSE,
    sessionId: fixture.request.sessionId,
    repositorySha: fixture.request.repositorySha,
    sessionDeadlineMs: fixture.request.sessionDeadlineMs,
    retainedV2Certificate: fixture.resultEnvelope,
    bytesGzipBase64Url: gzipSync(bytes).toString("base64url"),
    bytesSha256: createHash("sha256").update(bytes).digest("hex"),
    externalBusinessActionPerformed: false,
  };
}

test("signs exact canonical JSON bytes after local wallet, policy, and v2 certificate bindings match", async () => {
  const fixture = await buildAgentCliFixture();
  const request = directRequest(fixture);
  let calls = 0;

  const result = await executeDirectAgentSigningRequest({
    address: fixture.parties.initiator.sessionKeyAddress,
    localPolicy: fixture.policy,
    nowMs: fixture.nowMs,
    registration: fixture.parties.initiator.erc8004,
    request,
    rootKeyRing: fixture.rootKeyRing,
    sign: async (input) => {
      calls += 1;
      assert.equal(input.bytesGzipBase64Url, request.bytesGzipBase64Url);
      return {
        address: fixture.parties.initiator.sessionKeyAddress,
        bytesSha256: request.bytesSha256,
        signatureHex: "0x" + "2".repeat(130),
      };
    },
  });

  assert.deepEqual(result, {
    schema: "clockchain.direct-agent-signer-result/v1",
    adapterVersion: "1.1.0",
    address: fixture.parties.initiator.sessionKeyAddress,
    bytesSha256: request.bytesSha256,
    purpose: PURPOSE,
    role: "initiator",
    sessionId: fixture.request.sessionId,
    signatureHex: "0x" + "2".repeat(130),
  });
  assert.equal(calls, 1);
});

test("signs canonical Agent Contract business JSON containing finite numeric fields", async () => {
  const fixture = await buildAgentCliFixture();
  const bytes = Buffer.from(
    '{"deliveryHours":12,"schema":"agent-contract/v1","sequence":1}',
    "utf8",
  );
  const request = {
    ...directRequest(fixture),
    bytesGzipBase64Url: gzipSync(bytes).toString("base64url"),
    bytesSha256: createHash("sha256").update(bytes).digest("hex"),
  };
  let calls = 0;

  const result = await executeDirectAgentSigningRequest({
    address: fixture.parties.initiator.sessionKeyAddress,
    localPolicy: fixture.policy,
    nowMs: fixture.nowMs,
    registration: fixture.parties.initiator.erc8004,
    request,
    rootKeyRing: fixture.rootKeyRing,
    sign: async () => {
      calls += 1;
      return {
        address: fixture.parties.initiator.sessionKeyAddress,
        bytesSha256: request.bytesSha256,
        signatureHex: "0x" + "3".repeat(130),
      };
    },
  });

  assert.equal(result.bytesSha256, request.bytesSha256);
  assert.equal(calls, 1);
});

test("validates exact public result provenance for endpoint adapters", async () => {
  const fixture = await buildAgentCliFixture();
  const result = {
    schema: "clockchain.direct-agent-signer-result/v1",
    adapterVersion: "1.1.0",
    address: fixture.parties.initiator.sessionKeyAddress,
    bytesSha256: fixture.request.bytesSha256,
    purpose: PURPOSE,
    role: "initiator",
    sessionId: fixture.request.sessionId,
    signatureHex: "0x" + "2".repeat(130),
  };

  assert.deepEqual(validateDirectAgentSigningResult(result), result);
  for (const mutated of [
    { ...result, schema: "clockchain.direct-agent-signer-result/v2" },
    { ...result, adapterVersion: "1.0.0" },
    { ...result, purpose: "unknown" },
    { ...result, extra: true },
    Object.fromEntries(Object.entries(result).filter(([key]) => key !== "adapterVersion")),
  ]) {
    assert.throws(() => validateDirectAgentSigningResult(mutated));
  }
});

test("rejects request and binding mutations before the signer is reached", async () => {
  const fixture = await buildAgentCliFixture();
  const request = directRequest(fixture);
  let calls = 0;
  const sign = async () => {
    calls += 1;
    return {};
  };
  const mutations = [
    { ...request, schema: "clockchain.direct-agent-signer-request/v2" },
    { ...request, role: "responder" },
    { ...request, purpose: "unknown" },
    { ...request, sessionId: "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee" },
    { ...request, repositorySha: "e".repeat(40) },
    { ...request, sessionDeadlineMs: "1786337000000" },
    { ...request, retainedV2Certificate: { ...request.retainedV2Certificate, extra: true } },
    { ...request, bytesSha256: "f".repeat(64) },
    { ...request, externalBusinessActionPerformed: true },
    { ...request, extra: true },
  ];

  for (const mutated of mutations) {
    await assert.rejects(() => executeDirectAgentSigningRequest({
      address: fixture.parties.initiator.sessionKeyAddress,
      localPolicy: fixture.policy,
      nowMs: fixture.nowMs,
      registration: fixture.parties.initiator.erc8004,
      request: mutated,
      rootKeyRing: fixture.rootKeyRing,
      sign,
    }));
  }

  await assert.rejects(() => executeDirectAgentSigningRequest({
    address: fixture.parties.responder.sessionKeyAddress,
    localPolicy: fixture.policy,
    nowMs: fixture.nowMs,
    registration: fixture.parties.initiator.erc8004,
    request,
    rootKeyRing: fixture.rootKeyRing,
    sign,
  }));
  await assert.rejects(() => executeDirectAgentSigningRequest({
    address: fixture.parties.initiator.sessionKeyAddress,
    localPolicy: { ...fixture.policy, role: "responder" },
    nowMs: fixture.nowMs,
    registration: fixture.parties.initiator.erc8004,
    request,
    rootKeyRing: fixture.rootKeyRing,
    sign,
  }));

  assert.equal(calls, 0);
});

test("signs exact canonical identity JSON before a retained v2 certificate exists", async () => {
  const fixture = await buildAgentCliFixture();
  const request = {
    ...directRequest(fixture, {
      schema: "local.identity/v1",
      role: "initiator",
      sessionId: fixture.request.sessionId,
      repositorySha: fixture.request.repositorySha,
      sessionDeadlineMs: fixture.request.sessionDeadlineMs,
    }),
    purpose: IDENTITY_PURPOSE,
    retainedV2Certificate: null,
  };
  let calls = 0;

  const result = await executeDirectAgentSigningRequest({
    address: fixture.parties.initiator.sessionKeyAddress,
    localPolicy: fixture.policy,
    nowMs: fixture.nowMs,
    registration: fixture.parties.initiator.erc8004,
    request,
    rootKeyRing: fixture.rootKeyRing,
    sign: async (input) => {
      calls += 1;
      assert.equal(input.bytesGzipBase64Url, request.bytesGzipBase64Url);
      return {
        address: fixture.parties.initiator.sessionKeyAddress,
        bytesSha256: request.bytesSha256,
        signatureHex: "0x" + "4".repeat(130),
      };
    },
  });

  assert.deepEqual(result, {
    schema: "clockchain.direct-agent-signer-result/v1",
    adapterVersion: "1.1.0",
    address: fixture.parties.initiator.sessionKeyAddress,
    bytesSha256: request.bytesSha256,
    purpose: IDENTITY_PURPOSE,
    role: "initiator",
    sessionId: fixture.request.sessionId,
    signatureHex: "0x" + "4".repeat(130),
  });
  assert.equal(calls, 1);
});

test("keeps business signing certificate-required and rejects purpose/certificate substitution", async () => {
  const fixture = await buildAgentCliFixture();
  const businessRequest = directRequest(fixture);
  const identityRequest = {
    ...businessRequest,
    purpose: IDENTITY_PURPOSE,
    retainedV2Certificate: null,
  };
  let calls = 0;
  const sign = async () => {
    calls += 1;
    return {};
  };

  for (const request of [
    { ...businessRequest, retainedV2Certificate: null },
    { ...identityRequest, retainedV2Certificate: fixture.resultEnvelope },
    { ...identityRequest, purpose: PURPOSE, retainedV2Certificate: null },
    { ...businessRequest, purpose: IDENTITY_PURPOSE },
  ]) {
    await assert.rejects(() => executeDirectAgentSigningRequest({
      address: fixture.parties.initiator.sessionKeyAddress,
      localPolicy: fixture.policy,
      nowMs: fixture.nowMs,
      registration: fixture.parties.initiator.erc8004,
      request,
      rootKeyRing: fixture.rootKeyRing,
      sign,
    }));
  }

  assert.equal(calls, 0);
});

test("rejects non-canonical JSON bytes without inspecting business semantics", async () => {
  const fixture = await buildAgentCliFixture();
  const raw = Buffer.from("{\"value\":\"sign exactly this\",\"schema\":\"local.test/v1\"}", "utf8");
  const request = {
    ...directRequest(fixture),
    bytesGzipBase64Url: gzipSync(raw).toString("base64url"),
    bytesSha256: createHash("sha256").update(raw).digest("hex"),
  };
  let calls = 0;

  await assert.rejects(() => executeDirectAgentSigningRequest({
    address: fixture.parties.initiator.sessionKeyAddress,
    localPolicy: fixture.policy,
    nowMs: fixture.nowMs,
    registration: fixture.parties.initiator.erc8004,
    request,
    rootKeyRing: fixture.rootKeyRing,
    sign: async () => {
      calls += 1;
      return {};
    },
  }));

  assert.equal(calls, 0);
});

test("classifies safe validation failures without exposing request material", async () => {
  const fixture = await buildAgentCliFixture("responder");
  const request = {
    ...directRequest(fixture),
    role: "responder",
  };
  const base = {
    address: fixture.parties.responder.sessionKeyAddress,
    localPolicy: fixture.policies.responder,
    nowMs: fixture.nowMs,
    registration: fixture.parties.responder.erc8004,
    request,
    rootKeyRing: fixture.rootKeyRing,
  };
  const expectCode = (input, diagnosticCode) => assert.throws(
    () => validateDirectAgentSigningRequest(input),
    (error) => {
      assert.equal(error.message, "Direct agent signer failed safely.");
      assert.equal(error.diagnosticCode, diagnosticCode);
      assert.equal(error.message.includes(request.sessionId), false);
      return true;
    },
  );

  const noncanonical = Buffer.from('{"value":"x","schema":"local.test/v1"}', "utf8");
  expectCode({
    ...base,
    request: {
      ...request,
      bytesGzipBase64Url: gzipSync(noncanonical).toString("base64url"),
      bytesSha256: createHash("sha256").update(noncanonical).digest("hex"),
    },
  }, "DIRECT_SIGNER_CANONICAL_BYTES_MISMATCH");
  const outsideDomain = Buffer.from('["top-level arrays are not signable"]', "utf8");
  expectCode({
    ...base,
    request: {
      ...request,
      bytesGzipBase64Url: gzipSync(outsideDomain).toString("base64url"),
      bytesSha256: createHash("sha256").update(outsideDomain).digest("hex"),
    },
  }, "DIRECT_SIGNER_CANONICAL_DOMAIN_INVALID");
  const invalidJson = Buffer.from('{"schema":', "utf8");
  expectCode({
    ...base,
    request: {
      ...request,
      bytesGzipBase64Url: gzipSync(invalidJson).toString("base64url"),
      bytesSha256: createHash("sha256").update(invalidJson).digest("hex"),
    },
  }, "DIRECT_SIGNER_JSON_BYTES_INVALID");
  expectCode({
    ...base,
    request: {
      ...request,
      bytesSha256: "f".repeat(64),
    },
  }, "DIRECT_SIGNER_BYTES_DIGEST_MISMATCH");
  expectCode({
    ...base,
    request: {
      ...request,
      retainedV2Certificate: { ...request.retainedV2Certificate, extra: true },
    },
  }, "DIRECT_SIGNER_CERTIFICATE_INVALID");
  expectCode({
    ...base,
    rootKeyRing: [{ ...fixture.rootKeyRing[0], fingerprint: "f".repeat(64) }],
  }, "DIRECT_SIGNER_ROOT_RING_INVALID");
  expectCode({
    ...base,
    nowMs: Number(request.sessionDeadlineMs),
  }, "DIRECT_SIGNER_SESSION_EXPIRED");
});

test("classifies a canonical byte comparison runtime failure without exposing bytes", async () => {
  const fixture = await buildAgentCliFixture();
  const request = directRequest(fixture);
  const originalEquals = Buffer.prototype.equals;
  Buffer.prototype.equals = () => {
    throw new Error("runtime comparison failure with protected bytes");
  };
  try {
    assert.throws(
      () => validateDirectAgentSigningRequest({
        address: fixture.parties.initiator.sessionKeyAddress,
        localPolicy: fixture.policy,
        nowMs: fixture.nowMs,
        registration: fixture.parties.initiator.erc8004,
        request,
        rootKeyRing: fixture.rootKeyRing,
      }),
      (error) => {
        assert.equal(error.message, "Direct agent signer failed safely.");
        assert.equal(
          error.diagnosticCode,
          "DIRECT_SIGNER_CANONICAL_COMPARISON_INTERNAL_FAILURE",
        );
        assert.equal(error.message.includes(request.bytesSha256), false);
        return true;
      },
    );
  } finally {
    Buffer.prototype.equals = originalEquals;
  }
});
