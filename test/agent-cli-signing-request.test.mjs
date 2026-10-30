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
import {
  agentHandshakeV2ProposalDigest,
  signAgentHandshakeV2Proposal,
} from "../src/agent-handshake/v2/protocol.mjs";
import {
  createHostSessionKeyCertificate,
  hostSessionKeyCertificateDigest,
} from "../src/agent-handshake/v2/host-key-certificate.mjs";
import { privateKeyToAccount } from "viem/accounts";
import { buildAgentCliFixture } from "./support/agent-cli-fixture.mjs";
import {
  INITIATOR,
  REPOSITORY_SHA,
  RESPONDER,
  SESSION_DEADLINE_MS,
  SESSION_ID,
  SESSION_OPENED_AT_MS,
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
    now: () => fixture.nowMs,
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
    now: () => fixture.nowMs,
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
    now: () => fixture.nowMs,
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
    { ...fixture.request, schema: "clockchain.agent-handshake-signing-request/v1" },
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
      now: () => fixture.nowMs,
      request,
      rootKeyRing: fixture.rootKeyRing,
      sign,
    }));
  }
  await assert.rejects(() => executeAgentSigningRequest({
    address: fixture.parties.initiator.sessionKeyAddress,
    localPolicy: fixture.policy,
    now: () => fixture.nowMs,
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
      now: () => nowMs,
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
      now: () => 1786337099999,
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
    now: () => fixture.nowMs,
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
    now: () => fixture.nowMs,
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

// --- H-REQ-02: the helper verifies the proposal it is asked to accept. ---

const THIRD = privateKeyToAccount("0x" + "6".repeat(64));
const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");

// One entry point for the acceptance cases below; `at` is the local time.
function signAcceptance(fixture, request, { at = fixture.nowMs, sign } = {}) {
  return executeAgentSigningRequest({
    address: fixture.parties.responder.sessionKeyAddress,
    localPolicy: fixture.policy,
    now: () => at,
    request,
    rootKeyRing: fixture.rootKeyRing,
    sign,
  });
}

function honestSigner(fixture, role, request, calls = []) {
  return async (input) => {
    calls.push(input);
    return {
      address: fixture.parties[role].sessionKeyAddress,
      bytesSha256: input.bytesHex ? sha256(Buffer.from(input.bytesHex.slice(2), "hex")) : request.bytesSha256,
      signatureHex: "0x" + "3".repeat(130),
    };
  };
}

// An acceptance request whose bytes are `acceptance` and whose carried
// proposal is `proposalEnvelope`.
function acceptanceRequest(fixture, { acceptance = fixture.acceptanceEnvelope.payload, proposalEnvelope = fixture.proposalEnvelope, ...overrides } = {}) {
  const bytes = canonicalBytes(acceptance);
  return {
    ...fixture.request,
    proposalEnvelope,
    bytesGzipBase64Url: gzipSync(bytes).toString("base64url"),
    bytesSha256: sha256(bytes),
    ...overrides,
  };
}

async function proposalSignedBy(account, payload, address = INITIATOR.address.toLowerCase()) {
  return {
    payload,
    schema: "clockchain.agent-handshake-proposal-envelope/v2",
    signature: { address, algorithm: "eip191", value: await account.signMessage({ message: { raw: canonicalBytes(payload) } }) },
  };
}

// A re-signed proposal with one change, and the acceptance re-bound to its
// digest so the only disagreement is the change under test.
async function reboundPair(fixture, proposalChange, { account = INITIATOR, address } = {}) {
  const payload = { ...fixture.proposalEnvelope.payload, ...proposalChange };
  const proposalEnvelope = await proposalSignedBy(account, payload, address);
  return acceptanceRequest(fixture, {
    acceptance: { ...fixture.acceptanceEnvelope.payload, proposalDigest: agentHandshakeV2ProposalDigest(proposalEnvelope) },
    proposalEnvelope,
  });
}

test("acceptance requires a v2 request carrying the proposal envelope", async () => {
  const fixture = await buildAgentCliFixture("responder");
  assert.equal(fixture.request.schema, "clockchain.agent-handshake-signing-request/v2");
  const calls = [];
  const signed = await signAcceptance(fixture, fixture.request, { sign: honestSigner(fixture, "responder", fixture.request, calls) });
  assert.equal(signed.bytesSha256, fixture.request.bytesSha256);
  assert.equal(signed.checkpoint.artifactType, "acceptance");
  assert.equal(calls.length, 2);

  let reached = 0;
  const sign = async () => { reached += 1; return {}; };
  const withoutEnvelope = Object.fromEntries(Object.entries(fixture.request).filter(([key]) => key !== "proposalEnvelope"));
  for (const request of [
    { ...withoutEnvelope, schema: "clockchain.agent-handshake-signing-request/v1" },
    { ...fixture.request, schema: "clockchain.agent-handshake-signing-request/v1" },
    { ...fixture.request, proposalEnvelope: null },
    withoutEnvelope,
    { ...fixture.request, proposalEnvelope: {} },
    { ...fixture.request, proposalEnvelope: fixture.proposalEnvelope.payload },
  ]) {
    await assert.rejects(() => signAcceptance(fixture, request, { sign }));
  }
  assert.equal(reached, 0);
});

test("acceptance verifies the proposal signature, digest, context and window before signing", async () => {
  const fixture = await buildAgentCliFixture("responder");
  const base = fixture.acceptanceEnvelope.payload;
  const proposal = fixture.proposalEnvelope.payload;
  const responder = fixture.parties.responder;
  const otherResponder = {
    sessionKeyAddress: THIRD.address.toLowerCase(),
    policyDigest: responder.policyDigest,
    erc8004: {
      ...responder.erc8004,
      agentId: "9454",
      reference: `${responder.erc8004.chainId}:${responder.erc8004.registryAddress}:9454`,
    },
  };
  // The local responder named as the initiator of a proposal it did not make.
  const swappedRoles = await signAgentHandshakeV2Proposal({
    proposal: { ...proposal, initiator: fixture.parties.responder, responder: fixture.parties.initiator },
    signMessage: (bytes) => RESPONDER.signMessage({ message: { raw: bytes } }),
  });
  const cases = {
    // Signature: the proposal bytes are unchanged but not signed by the initiator.
    signedByResponder: acceptanceRequest(fixture, { proposalEnvelope: await proposalSignedBy(RESPONDER, proposal) }),
    signedByThirdKey: acceptanceRequest(fixture, { proposalEnvelope: await proposalSignedBy(THIRD, proposal) }),
    signerAddressNotInitiator: acceptanceRequest(fixture, { proposalEnvelope: await proposalSignedBy(RESPONDER, proposal, RESPONDER.address.toLowerCase()) }),
    // Context: a validly signed proposal for another session, repository or terms.
    proposalSessionId: await reboundPair(fixture, { sessionId: "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee" }),
    proposalRepositorySha: await reboundPair(fixture, { repositorySha: "e".repeat(40) }),
    proposalReference: await reboundPair(fixture, { reference: "NS-1848" }),
    proposalStatementDigest: await reboundPair(fixture, { statementDigest: "f".repeat(64) }),
    proposalIdentityPolicy: await reboundPair(fixture, { identityPolicy: { ...proposal.identityPolicy, erc8004: "required_existing_or_fresh" } }),
    // Window: a proposal whose own window has lapsed.
    proposalExpired: await reboundPair(fixture, { issuedAtMs: "1786337000000", expiresAtMs: "1786337090000" }),
    // Digest and parties.
    proposalDigestMismatch: acceptanceRequest(fixture, { acceptance: { ...base, proposalDigest: "a".repeat(64) } }),
    proposalNamesAnotherResponder: await reboundPair(fixture, { responder: otherResponder }),
    localPartyIsProposalInitiator: acceptanceRequest(fixture, {
      acceptance: { ...base, proposalDigest: agentHandshakeV2ProposalDigest(swappedRoles) },
      proposalEnvelope: swappedRoles,
    }),
    // The five contradictions between an acceptance and its proposal.
    acceptanceRepositorySha: acceptanceRequest(fixture, { acceptance: { ...base, repositorySha: "e".repeat(40) } }),
    acceptanceReference: acceptanceRequest(fixture, { acceptance: { ...base, reference: "NS-1848" } }),
    acceptanceStatementDigest: acceptanceRequest(fixture, { acceptance: { ...base, statementDigest: "f".repeat(64) } }),
    acceptanceIdentityPolicy: acceptanceRequest(fixture, { acceptance: { ...base, identityPolicy: { ...base.identityPolicy, erc8004: "required_existing_or_fresh" } } }),
    acceptanceIssuedBeforeProposal: acceptanceRequest(fixture, { acceptance: { ...base, issuedAtMs: String(BigInt(proposal.issuedAtMs) - 1n) } }),
  };
  let reached = 0;
  const sign = async () => { reached += 1; return {}; };
  // Every case runs; a failure names each case that reached the signer.
  const reachedSigner = [];
  for (const [name, request] of Object.entries(cases)) {
    const before = reached;
    await assert.rejects(() => signAcceptance(fixture, request, { sign }), undefined, name);
    if (reached !== before) reachedSigner.push(name);
  }
  assert.deepEqual(reachedSigner, []);
  // The shared agreement window lapsing is the distinct window-expired error.
  const lapsed = await signAcceptance(fixture, fixture.request, { at: Number(proposal.expiresAtMs), sign }).then(() => null, (error) => error);
  assert.ok(isSigningWindowExpired(lapsed));
  assert.equal(reached, 0);
});

test("non-acceptance operations require proposalEnvelope null", async () => {
  const fixture = await buildAgentCliFixture("initiator");
  assert.equal(fixture.request.proposalEnvelope, null);
  const address = fixture.parties.initiator.sessionKeyAddress;
  let reached = 0;
  const sign = async () => { reached += 1; return {}; };
  const run = (request) => executeAgentSigningRequest({
    address,
    localPolicy: fixture.policy,
    now: () => fixture.nowMs,
    request,
    rootKeyRing: fixture.rootKeyRing,
    sign,
  });
  for (const request of [
    { ...fixture.request, proposalEnvelope: fixture.proposalEnvelope },
    { ...fixture.request, proposalEnvelope: {} },
    Object.fromEntries(Object.entries(fixture.request).filter(([key]) => key !== "proposalEnvelope")),
    evidenceRequest(fixture, { proposalEnvelope: fixture.proposalEnvelope }),
  ]) {
    await assert.rejects(() => run(request));
  }
  assert.equal(reached, 0);
  const evidence = evidenceRequest(fixture);
  const signed = await executeAgentSigningRequest({
    address,
    localPolicy: fixture.policy,
    now: () => fixture.nowMs,
    request: evidence,
    rootKeyRing: fixture.rootKeyRing,
    sign: async () => ({ address, bytesSha256: evidence.bytesSha256, signatureHex: "0x" + "1".repeat(130) }),
  });
  assert.equal(signed.bytesSha256, evidence.bytesSha256);
});

// --- H-REQ-07: the helper re-reads its clock after every signature. ---

const GENERIC_FAILURE = "Agent handshake operation failed safely.";
const PAYLOAD_EXPIRES_AT_MS = 1786337190000;

// A clock the signer advances: onArtifact runs inside the artifact signature,
// onCheckpoint inside the checkpoint signature.
function scriptedSigning(fixture, request, { onArtifact, onCheckpoint } = {}) {
  const address = fixture.parties[request.role].sessionKeyAddress;
  const clock = { value: fixture.nowMs };
  const calls = { artifact: 0, checkpoint: 0 };
  const sign = async (input) => {
    if (input.bytesHex) {
      calls.checkpoint += 1;
      onCheckpoint?.(clock);
      return { address, bytesSha256: sha256(Buffer.from(input.bytesHex.slice(2), "hex")), signatureHex: "0x" + "2".repeat(130) };
    }
    calls.artifact += 1;
    onArtifact?.(clock);
    return { address, bytesSha256: request.bytesSha256, signatureHex: "0x" + "1".repeat(130) };
  };
  const run = () => executeAgentSigningRequest({
    address,
    localPolicy: fixture.policy,
    now: () => clock.value,
    request,
    rootKeyRing: fixture.rootKeyRing,
    sign,
  }).then((value) => ({ value }), (error) => ({ error }));
  return { calls, clock, run };
}

function identityClaimRequest(fixture, overrides = {}) {
  const role = fixture.request.role;
  const bytes = canonicalBytes({
    schema: "clockchain.agent-handshake-identity-claim/v2",
    protocol: "clockchain.agent-handshake/v2",
    sessionId: fixture.request.sessionId,
    repositorySha: fixture.request.repositorySha,
    role,
    sessionKeyAddress: fixture.parties[role].sessionKeyAddress,
    policyDigest: fixture.request.policyDigest,
    statementDigest: fixture.policy.statementDigest,
    externalBusinessActionPerformed: false,
  });
  return {
    ...fixture.request,
    operation: "identity_claim",
    bytesGzipBase64Url: gzipSync(bytes).toString("base64url"),
    bytesSha256: sha256(bytes),
    ...overrides,
  };
}

test("artifact signature finishing after the window is discarded, checkpoint signer never called", async () => {
  for (const role of ["initiator", "responder"]) {
    const fixture = await buildAgentCliFixture(role);
    const control = await scriptedSigning(fixture, fixture.request, {
      onArtifact: (clock) => { clock.value = PAYLOAD_EXPIRES_AT_MS - 1; },
    }).run();
    assert.equal(control.error, undefined, `${role}: ${control.error?.message}`);
    assert.equal(control.value.checkpoint.issuedAtMs, String(PAYLOAD_EXPIRES_AT_MS - 1));
    const late = scriptedSigning(fixture, fixture.request, {
      onArtifact: (clock) => { clock.value = PAYLOAD_EXPIRES_AT_MS; },
    });
    const outcome = await late.run();
    assert.equal(outcome.value, undefined);
    assert.ok(isSigningWindowExpired(outcome.error), `${role}: ${outcome.error?.message}`);
    assert.deepEqual(late.calls, { artifact: 1, checkpoint: 0 });
  }
});

test("late checkpoint signature discarded", async () => {
  for (const role of ["initiator", "responder"]) {
    const fixture = await buildAgentCliFixture(role);
    const late = scriptedSigning(fixture, fixture.request, {
      onCheckpoint: (clock) => { clock.value = PAYLOAD_EXPIRES_AT_MS; },
    });
    const outcome = await late.run();
    assert.equal(outcome.value, undefined);
    assert.ok(isSigningWindowExpired(outcome.error), `${role}: ${outcome.error?.message}`);
    assert.deepEqual(late.calls, { artifact: 1, checkpoint: 1 });
    const lastMs = await scriptedSigning(fixture, fixture.request, {
      onCheckpoint: (clock) => { clock.value = PAYLOAD_EXPIRES_AT_MS - 1; },
    }).run();
    assert.equal(lastMs.error, undefined, `${role}: ${lastMs.error?.message}`);
    assert.equal(lastMs.value.checkpoint.signature.value, "0x" + "2".repeat(130));
  }
});

test("checkpoint issuedAtMs is the fresh read", async () => {
  const fixture = await buildAgentCliFixture("initiator");
  const signedAtMs = 1786337170123;
  const outcome = await scriptedSigning(fixture, fixture.request, {
    onArtifact: (clock) => { clock.value = signedAtMs; },
  }).run();
  assert.equal(outcome.error, undefined, outcome.error?.message);
  assert.notEqual(signedAtMs, fixture.nowMs);
  assert.equal(outcome.value.checkpoint.issuedAtMs, String(signedAtMs));
  assert.equal(
    outcome.value.checkpoint.expiresAtMs,
    String(Math.min(signedAtMs + Number(fixture.policy.maxValidForSeconds) * 1000, Number(SESSION_DEADLINE_MS))),
  );
});

test("rollback is a generic refusal, not window-expired", async () => {
  const fixture = await buildAgentCliFixture("initiator");
  const control = await scriptedSigning(fixture, fixture.request).run();
  assert.equal(control.error, undefined, control.error?.message);
  for (const [name, hooks, expectedCalls] of [
    ["artifact rollback", { onArtifact: (clock) => { clock.value = fixture.nowMs - 1; } }, { artifact: 1, checkpoint: 0 }],
    ["checkpoint rollback", { onCheckpoint: (clock) => { clock.value = fixture.nowMs - 1; } }, { artifact: 1, checkpoint: 1 }],
    ["non-integer read", { onArtifact: (clock) => { clock.value = fixture.nowMs + 0.5; } }, { artifact: 1, checkpoint: 0 }],
  ]) {
    const scripted = scriptedSigning(fixture, fixture.request, hooks);
    const outcome = await scripted.run();
    assert.equal(outcome.value, undefined, name);
    assert.equal(isSigningWindowExpired(outcome.error), false, name);
    assert.equal(outcome.error?.message, GENERIC_FAILURE, name);
    assert.deepEqual(scripted.calls, expectedCalls, name);
  }
});

test("evidence and identity_claim are bounded by the session deadline and host-key validity", async () => {
  const fixture = await buildAgentCliFixture("initiator");
  const deadlineMs = Number(SESSION_DEADLINE_MS);
  // A host key that expires before the session deadline.
  const shortKeyUntilMs = 1786337170000;
  const shortKey = createHostSessionKeyCertificate({
    certificate: {
      schema: "clockchain.host-session-key/v1",
      rootKid: fixture.root.keyId,
      sessionId: SESSION_ID,
      repositorySha: REPOSITORY_SHA,
      sessionPublicKey: fixture.host.publicKey,
      validFromMs: SESSION_OPENED_AT_MS,
      validUntilMs: String(shortKeyUntilMs),
    },
    root: { keyId: fixture.root.keyId, privateKeyPem: fixture.root.privateKeyPem },
  });
  const shortKeyDescriptor = createAgentHandshakeV2DescriptorEnvelope({
    ...fixture.descriptorEnvelope.descriptor,
    hostSessionKeyCertificateDigest: hostSessionKeyCertificateDigest(shortKey),
  }, { keyId: fixture.host.keyId, privateKeyPem: fixture.host.privateKeyPem });
  const shortKeyEvidenceBytes = canonicalBytes({
    ...fixture.evidence.initiator.result,
    sessionDigest: agentHandshakeV2DescriptorDigest(shortKeyDescriptor.descriptor),
  });
  const requests = {
    evidence: evidenceRequest(fixture),
    identityClaim: identityClaimRequest(fixture),
    evidenceShortKey: evidenceRequest(fixture, {
      hostSessionKeyCertificate: shortKey,
      descriptorEnvelope: shortKeyDescriptor,
      bytesGzipBase64Url: gzipSync(shortKeyEvidenceBytes).toString("base64url"),
      bytesSha256: sha256(shortKeyEvidenceBytes),
    }),
    identityClaimShortKey: identityClaimRequest(fixture, { hostSessionKeyCertificate: shortKey }),
  };
  const boundOf = (name) => (name.endsWith("ShortKey") ? shortKeyUntilMs : deadlineMs);
  const outcomes = {};
  for (const [name, request] of Object.entries(requests)) {
    const bound = boundOf(name);
    const before = await scriptedSigning(fixture, request, { onArtifact: (clock) => { clock.value = bound - 1; } }).run();
    const at = await scriptedSigning(fixture, request, { onArtifact: (clock) => { clock.value = bound; } }).run();
    outcomes[name] = {
      lastMs: before.error === undefined ? "signed" : before.error.message,
      atBound: at.error === undefined ? "signed" : isSigningWindowExpired(at.error) ? "window-expired" : at.error.message,
    };
  }
  assert.deepEqual(outcomes, Object.fromEntries(Object.keys(requests).map((name) => [name, { lastMs: "signed", atBound: "window-expired" }])));
});

// --- H-REQ-07: the helper reads its clock immediately before each signature. ---

// The clock returns reads[i] on its i-th read and repeats the last value after
// that. Read 0 validates the request; read 1 is taken immediately before the
// artifact signature; for proposal and acceptance, read 3 is taken immediately
// before the checkpoint signature.
function readScriptedSigning(fixture, request, reads) {
  const address = fixture.parties[request.role].sessionKeyAddress;
  const calls = { artifact: 0, checkpoint: 0 };
  let index = 0;
  const now = () => reads[Math.min(index++, reads.length - 1)];
  const sign = async (input) => {
    if (input.bytesHex) {
      calls.checkpoint += 1;
      return { address, bytesSha256: sha256(Buffer.from(input.bytesHex.slice(2), "hex")), signatureHex: "0x" + "2".repeat(130) };
    }
    calls.artifact += 1;
    return { address, bytesSha256: request.bytesSha256, signatureHex: "0x" + "1".repeat(130) };
  };
  const run = () => executeAgentSigningRequest({
    address,
    localPolicy: fixture.policy,
    now,
    request,
    rootKeyRing: fixture.rootKeyRing,
    sign,
  }).then((value) => ({ value }), (error) => ({ error }));
  return { calls, run };
}

function signingOutcome(outcome) {
  if (outcome.error === undefined) return "signed";
  return isSigningWindowExpired(outcome.error) ? "window-expired" : outcome.error.message;
}

test("a window that ends while the request is validated stops before the artifact signer is called", async () => {
  const initiator = await buildAgentCliFixture("initiator");
  const responder = await buildAgentCliFixture("responder");
  const deadlineMs = Number(SESSION_DEADLINE_MS);
  const cases = {
    proposal: { fixture: initiator, request: initiator.request, bound: PAYLOAD_EXPIRES_AT_MS },
    acceptance: { fixture: responder, request: responder.request, bound: PAYLOAD_EXPIRES_AT_MS },
    evidence: { fixture: initiator, request: evidenceRequest(initiator), bound: deadlineMs },
    identityClaim: { fixture: initiator, request: identityClaimRequest(initiator), bound: deadlineMs },
  };
  const outcomes = {};
  for (const [name, { fixture, request, bound }] of Object.entries(cases)) {
    const atBound = readScriptedSigning(fixture, request, [fixture.nowMs, bound]);
    const lastMs = readScriptedSigning(fixture, request, [fixture.nowMs, bound - 1]);
    outcomes[name] = {
      atBound: signingOutcome(await atBound.run()),
      atBoundCalls: atBound.calls,
      lastMs: signingOutcome(await lastMs.run()),
      lastMsArtifactCalls: lastMs.calls.artifact,
    };
  }
  assert.deepEqual(outcomes, Object.fromEntries(Object.keys(cases).map((name) => [name, {
    atBound: "window-expired",
    atBoundCalls: { artifact: 0, checkpoint: 0 },
    lastMs: "signed",
    lastMsArtifactCalls: 1,
  }])));
});

test("a window that ends after the artifact signature stops before the checkpoint signer is called", async () => {
  for (const role of ["initiator", "responder"]) {
    const fixture = await buildAgentCliFixture(role);
    const start = fixture.nowMs;
    const atBound = readScriptedSigning(fixture, fixture.request, [start, start, start, PAYLOAD_EXPIRES_AT_MS]);
    const atBoundOutcome = await atBound.run();
    assert.equal(signingOutcome(atBoundOutcome), "window-expired", role);
    assert.deepEqual(atBound.calls, { artifact: 1, checkpoint: 0 }, role);
    const lastMs = readScriptedSigning(fixture, fixture.request, [start, start, start, PAYLOAD_EXPIRES_AT_MS - 1]);
    const lastMsOutcome = await lastMs.run();
    assert.equal(signingOutcome(lastMsOutcome), "signed", role);
    assert.deepEqual(lastMs.calls, { artifact: 1, checkpoint: 1 }, role);
    assert.equal(lastMsOutcome.value.checkpoint.issuedAtMs, String(start), role);
  }
});
