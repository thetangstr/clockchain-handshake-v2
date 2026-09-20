import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";
import { gzipSync } from "node:zlib";

import { executeAgentSigningRequest, isSigningWindowExpired, SIGNING_WINDOW_EXPIRED_MESSAGE } from "../src/agent-cli/signing-request.mjs";
import { canonicalBytes, digestHex } from "../src/core/canonical.mjs";
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
  const checkpointSigns = [];
  const result = await executeAgentSigningRequest({
    address: fixture.parties.initiator.sessionKeyAddress,
    localPolicy: fixture.policy,
    nowMs: fixture.nowMs,
    request: fixture.request,
    rootKeyRing: fixture.rootKeyRing,
    sign: async (input) => {
      if (input.bytesHex) {
        checkpointSigns.push(input.bytesHex);
        return {
          address: fixture.parties.initiator.sessionKeyAddress,
          bytesSha256: createHash("sha256").update(Buffer.from(input.bytesHex.slice(2), "hex")).digest("hex"),
          signatureHex: "0x" + "2".repeat(130),
        };
      }
      assert.equal(input.bytesGzipBase64Url, fixture.request.bytesGzipBase64Url);
      return {
        address: fixture.parties.initiator.sessionKeyAddress,
        bytesSha256: fixture.request.bytesSha256,
        signatureHex: "0x" + "1".repeat(130),
      };
    },
  });
  assert.equal(checkpointSigns.length, 1);
  assert.equal(result.bytesSha256, fixture.request.bytesSha256);
  // The same sign step emits the commitment checkpoint the server requires
  // before submit: sequence 1 for a proposal, no predecessor, bound to the
  // artifact envelope digest.
  const checkpoint = result.checkpoint;
  assert.equal(checkpoint.artifactType, "proposal");
  assert.equal(checkpoint.sequence, "1");
  assert.equal(checkpoint.previousCheckpointDigest, null);
  assert.equal(checkpoint.signerAddress, fixture.parties.initiator.sessionKeyAddress);
  assert.equal(checkpoint.signature.value, "0x" + "2".repeat(130));
  assert.equal(
    checkpoint.artifactDigest,
    digestHex({
      payload: fixture.proposalEnvelope.payload,
      schema: "clockchain.agent-handshake-proposal-envelope/v2",
      signature: { address: fixture.parties.initiator.sessionKeyAddress, algorithm: "eip191", value: result.signatureHex },
    }),
  );
  assert.equal(
    Buffer.from(checkpointSigns[0].slice(2), "hex").toString("utf8"),
    JSON.stringify(Object.fromEntries(Object.entries({ ...checkpoint, signature: undefined }).filter(([, v]) => v !== undefined).sort(([a], [b]) => a < b ? -1 : 1))),
  );
});

test("acceptance sign emits a sequence-2 checkpoint chained to the proposal digest", async () => {
  const fixture = await buildAgentCliFixture("responder");
  const result = await executeAgentSigningRequest({
    address: fixture.parties.responder.sessionKeyAddress,
    localPolicy: fixture.policy,
    nowMs: fixture.nowMs,
    request: fixture.request,
    rootKeyRing: fixture.rootKeyRing,
    sign: async (input) => ({
      address: fixture.parties.responder.sessionKeyAddress,
      bytesSha256: input.bytesHex
        ? createHash("sha256").update(Buffer.from(input.bytesHex.slice(2), "hex")).digest("hex")
        : fixture.request.bytesSha256,
      signatureHex: "0x" + "3".repeat(130),
    }),
  });
  assert.equal(result.checkpoint.artifactType, "acceptance");
  assert.equal(result.checkpoint.sequence, "2");
  assert.equal(result.checkpoint.previousCheckpointDigest, fixture.request.previousCheckpointDigest);
  assert.equal(result.checkpoint.role, "responder");
});

test("previousCheckpointDigest is bound to the operation: null unless acceptance, digest when acceptance", async () => {
  const initiator = await buildAgentCliFixture("initiator");
  const responder = await buildAgentCliFixture("responder");
  const neverSign = async () => { throw new Error("unreachable"); };
  const run = (fixture, request) => executeAgentSigningRequest({
    address: fixture.parties[fixture.request.role].sessionKeyAddress,
    localPolicy: fixture.policy,
    nowMs: fixture.nowMs,
    request,
    rootKeyRing: fixture.rootKeyRing,
    sign: neverSign,
  });
  // Proposal with a digest, or the key missing entirely, fails before signing.
  await assert.rejects(() => run(initiator, { ...initiator.request, previousCheckpointDigest: "c".repeat(64) }));
  const missing = { ...initiator.request };
  delete missing.previousCheckpointDigest;
  await assert.rejects(() => run(initiator, missing));
  // Acceptance without the proposal checkpoint link fails before signing.
  await assert.rejects(() => run(responder, { ...responder.request, previousCheckpointDigest: null }));
  await assert.rejects(() => run(responder, { ...responder.request, previousCheckpointDigest: "not-a-digest" }));
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

test("an expired payload window or session deadline fails with the distinct window-expired error", async () => {
  const fixture = await buildAgentCliFixture();
  let calls = 0;
  const sign = async () => { calls += 1; return {}; };
  for (const nowMs of [1786337190000, Number(SESSION_DEADLINE_MS)]) {
    const failure = await executeAgentSigningRequest({
      address: fixture.parties.initiator.sessionKeyAddress,
      localPolicy: fixture.policy,
      nowMs,
      request: fixture.request,
      rootKeyRing: fixture.rootKeyRing,
      sign,
    }).then(() => null, (error) => error);
    assert.ok(isSigningWindowExpired(failure));
    assert.equal(failure.message, SIGNING_WINDOW_EXPIRED_MESSAGE);
  }
  // A future-dated window is malformed, not lapsed — it stays generic.
  await assert.rejects(
    () => executeAgentSigningRequest({
      address: fixture.parties.initiator.sessionKeyAddress,
      localPolicy: fixture.policy,
      nowMs: 1786337099999,
      request: fixture.request,
      rootKeyRing: fixture.rootKeyRing,
      sign,
    }),
    (error) => !isSigningWindowExpired(error) && error.message === "Agent handshake operation failed safely.",
  );
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
