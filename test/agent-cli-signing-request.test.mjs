import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";
import { gzipSync } from "node:zlib";

import { executeAgentSigningRequest } from "../src/agent-cli/signing-request.mjs";
import { canonicalBytes } from "../src/core/canonical.mjs";
import {
  agentHandshakeV2DescriptorDigest,
  createAgentHandshakeV2DescriptorEnvelope,
} from "../src/agent-handshake/v2/descriptor.mjs";
import { buildAgentCliFixture } from "./support/agent-cli-fixture.mjs";
import {
  SESSION_DEADLINE_MS,
  ed25519,
} from "./support/agent-handshake-v2-fixture.mjs";

function evidenceRequest(fixture, overrides = {}) {
  const result = fixture.evidence.initiator.result;
  const bytes = canonicalBytes(result);
  return {
    ...fixture.request,
    operation: "evidence",
    descriptorEnvelope: fixture.descriptorEnvelope,
    bytesGzipBase64Url: gzipSync(bytes).toString("base64url"),
    bytesSha256: createHash("sha256").update(bytes).digest("hex"),
    ...overrides,
  };
}

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
    { ...fixture.request, descriptorEnvelope: fixture.descriptorEnvelope },
    { ...fixture.request, descriptorEnvelope: {} },
    { ...fixture.request, extra: true },
    Object.fromEntries(Object.entries(fixture.request).filter(([key]) => key !== "descriptorEnvelope")),
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

test("evidence signing requires the verified host-signed descriptor bound to the session", async () => {
  const fixture = await buildAgentCliFixture();
  const address = fixture.parties.initiator.sessionKeyAddress;
  const request = evidenceRequest(fixture);
  const result = await executeAgentSigningRequest({
    address,
    localPolicy: fixture.policy,
    nowMs: fixture.nowMs,
    request,
    rootKeyRing: fixture.rootKeyRing,
    sign: async (input) => {
      assert.equal(input.bytesGzipBase64Url, request.bytesGzipBase64Url);
      return { address, bytesSha256: request.bytesSha256, signatureHex: "0x" + "1".repeat(130) };
    },
  });
  assert.equal(result.bytesSha256, request.bytesSha256);
  assert.equal(
    agentHandshakeV2DescriptorDigest(fixture.descriptorEnvelope.descriptor),
    fixture.evidence.initiator.result.sessionDigest,
  );

  let calls = 0;
  const countingSign = async () => { calls += 1; return {}; };
  const resign = (descriptor) => createAgentHandshakeV2DescriptorEnvelope(descriptor, {
    keyId: fixture.host.keyId,
    privateKeyPem: fixture.host.privateKeyPem,
  });
  const base = fixture.descriptorEnvelope.descriptor;
  const wrongSigner = ed25519("not-the-host");
  const responderParty = fixture.parties.responder;
  const tamperedSignature = {
    ...fixture.descriptorEnvelope,
    operator: { ...fixture.descriptorEnvelope.operator, signature: Buffer.from("f".repeat(64), "hex").toString("base64") },
  };
  const wrongSignerEnvelope = createAgentHandshakeV2DescriptorEnvelope(
    { ...base, operatorPublicKey: wrongSigner.publicKey },
    { keyId: wrongSigner.keyId, privateKeyPem: wrongSigner.privateKeyPem },
  );
  const wrongPartyBytes = canonicalBytes({
    ...fixture.evidence.initiator.result,
    party: responderParty,
    policyDigest: responderParty.policyDigest,
  });
  const wrongSessionDigestBytes = canonicalBytes({
    ...fixture.evidence.initiator.result,
    sessionDigest: "f".repeat(64),
  });
  // Registration drift with address/policyDigest intact: the descriptor digest
  // is recomputed into the payload so rejection isolates the canonical
  // descriptor[role] === payload.party binding, including ERC-8004 fields.
  const driftedRegistrationEnvelope = resign({
    ...base,
    initiator: {
      ...base.initiator,
      erc8004: {
        ...base.initiator.erc8004,
        agentId: "9999",
        reference: `${base.initiator.erc8004.chainId}:${base.initiator.erc8004.registryAddress}:9999`,
      },
    },
  });
  const driftedRegistrationBytes = canonicalBytes({
    ...fixture.evidence.initiator.result,
    sessionDigest: agentHandshakeV2DescriptorDigest(driftedRegistrationEnvelope.descriptor),
  });
  const reject = (mutated) => assert.rejects(() => executeAgentSigningRequest({
    address,
    localPolicy: fixture.policy,
    nowMs: fixture.nowMs,
    request: mutated,
    rootKeyRing: fixture.rootKeyRing,
    sign: countingSign,
  }));
  for (const mutated of [
    evidenceRequest(fixture, { descriptorEnvelope: null }),
    evidenceRequest(fixture, { descriptorEnvelope: {} }),
    evidenceRequest(fixture, { descriptorEnvelope: tamperedSignature }),
    evidenceRequest(fixture, { descriptorEnvelope: wrongSignerEnvelope }),
    // Re-signed mutants: the signature verifies, so each rejection isolates
    // the specific binding under test.
    evidenceRequest(fixture, { descriptorEnvelope: resign({ ...base, hostSessionKeyCertificateDigest: "f".repeat(64) }) }),
    evidenceRequest(fixture, { descriptorEnvelope: resign({ ...base, sessionId: "99999999-8888-4777-8666-555555555555" }) }),
    evidenceRequest(fixture, { descriptorEnvelope: resign({ ...base, repositorySha: "e".repeat(40) }) }),
    evidenceRequest(fixture, { descriptorEnvelope: resign({ ...base, reference: "OTHER-REF" }) }),
    evidenceRequest(fixture, { descriptorEnvelope: resign({ ...base, statementDigest: "f".repeat(64) }) }),
    evidenceRequest(fixture, { descriptorEnvelope: resign({ ...base, identityPolicy: { ...base.identityPolicy, erc8004: "required_existing_or_fresh" } }) }),
    evidenceRequest(fixture, { descriptorEnvelope: resign({ ...base, agreementExpiresAtMs: String(Number(SESSION_DEADLINE_MS) + 1) }) }),
    evidenceRequest(fixture, { descriptorEnvelope: resign({ ...base, initiator: { ...base.initiator, sessionKeyAddress: "0x" + "9".repeat(40) } }) }),
    evidenceRequest(fixture, {
      descriptorEnvelope: driftedRegistrationEnvelope,
      bytesGzipBase64Url: gzipSync(driftedRegistrationBytes).toString("base64url"),
      bytesSha256: createHash("sha256").update(driftedRegistrationBytes).digest("hex"),
    }),
    // Payload-side drift: wrong party and sessionDigest mismatch.
    evidenceRequest(fixture, {
      bytesGzipBase64Url: gzipSync(wrongPartyBytes).toString("base64url"),
      bytesSha256: createHash("sha256").update(wrongPartyBytes).digest("hex"),
    }),
    evidenceRequest(fixture, {
      bytesGzipBase64Url: gzipSync(wrongSessionDigestBytes).toString("base64url"),
      bytesSha256: createHash("sha256").update(wrongSessionDigestBytes).digest("hex"),
    }),
    // Role confusion: responder request signing an initiator payload.
    evidenceRequest(fixture, { role: "responder" }),
  ]) {
    await reject(mutated);
  }
  // Non-null descriptor is forbidden on every other operation.
  for (const operation of ["identity_claim", "proposal", "acceptance"]) {
    await reject({ ...fixture.request, operation, descriptorEnvelope: fixture.descriptorEnvelope });
  }
  assert.equal(calls, 0);
});
