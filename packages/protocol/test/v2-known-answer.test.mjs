import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import {
  agentHandshakeV2DescriptorDigest,
  agentHandshakeV2ProposalDigest,
  agentHandshakeV2ResultDigest,
  agentHandshakeV2StatementDigest,
  agentHandshakeV2TransitionDigest,
  canonicalBytes,
  digestHex,
  ed25519PublicKeyFingerprint,
  hostSessionKeyCertificateDigest,
  localPolicyDigest,
  verifyAgentHandshakeV2Acceptance,
  verifyAgentHandshakeV2DescriptorEnvelope,
  verifyAgentHandshakeV2Evidence,
  verifyAgentHandshakeV2Proposal,
  verifyAgentHandshakeV2Result,
  verifyHostSessionKeyCertificate,
} from "@clockchain/handshake-protocol";

const fixture = JSON.parse(
  await readFile(new URL("./fixtures/agent-handshake-v2-canonical.json", import.meta.url), "utf8"),
);
const provenance = JSON.parse(
  await readFile(new URL("./fixtures/v2-provenance.json", import.meta.url), "utf8"),
);

test("v2 protocol package preserves the historical canonical fixture bytes and digests", () => {
  assert.equal(fixture.schema, "clockchain.agent-handshake-v2-canonical-fixture/v1");
  assert.equal(fixture.handshakeSourceCommit, "c02da109081840262928f1a7e6d636d07e972f42");
  assert.deepEqual(provenance, {
    schema: "clockchain.handshake-protocol-v2-extraction-provenance/v1",
    approvedExtractionSourceCommit: "d2cdedb705cf6855657381a908e47f71df959145",
    historicalCanonicalFixtureCommit: fixture.handshakeSourceCommit,
    historicalCanonicalFixturePath: "packages/protocol/test/fixtures/agent-handshake-v2-canonical.json",
    historicalCanonicalFixtureOriginalPath: "test/fixtures/agent-handshake-v2-canonical.json",
    packageName: "@clockchain/handshake-protocol",
  });

  const { canonical, objects } = fixture;
  assert.equal(Buffer.from(canonicalBytes(objects.terms)).toString("hex"), canonical.terms.bytesHex);
  assert.equal(agentHandshakeV2StatementDigest(objects.terms), canonical.terms.digest);

  for (const role of ["initiator", "responder"]) {
    assert.equal(Buffer.from(canonicalBytes(objects.policies[role])).toString("hex"), canonical.policies[role].bytesHex);
    assert.equal(localPolicyDigest(objects.policies[role]), canonical.policies[role].digest);
    assert.equal(Buffer.from(canonicalBytes(objects.parties[role])).toString("hex"), canonical.parties[role].bytesHex);
    assert.equal(digestHex(objects.parties[role]), canonical.parties[role].digest);
    assert.equal(Buffer.from(canonicalBytes(objects.identityClaims[role])).toString("hex"), canonical.identityClaims[role].bytesHex);
    assert.equal(digestHex(objects.identityClaims[role]), canonical.identityClaims[role].digest);
  }

  assert.equal(Buffer.from(canonicalBytes(objects.proposalEnvelope.payload)).toString("hex"), canonical.proposal.bytesHex);
  assert.equal(agentHandshakeV2ProposalDigest(objects.proposalEnvelope), canonical.proposal.digest);
  assert.equal(Buffer.from(canonicalBytes(objects.acceptanceEnvelope.payload)).toString("hex"), canonical.acceptance.bytesHex);
  assert.equal(digestHex(objects.acceptanceEnvelope.payload), canonical.acceptance.digest);

  for (const role of ["initiator", "responder"]) {
    assert.equal(Buffer.from(canonicalBytes(objects.evidence[role].result)).toString("hex"), canonical.evidence[role].bytesHex);
    assert.equal(digestHex(objects.evidence[role].result), canonical.evidence[role].digest);
  }

  assert.equal(Buffer.from(canonicalBytes(objects.descriptorEnvelope.descriptor)).toString("hex"), canonical.descriptor.bytesHex);
  assert.equal(agentHandshakeV2DescriptorDigest(objects.descriptorEnvelope.descriptor), canonical.descriptor.digest);
  assert.equal(Buffer.from(canonicalBytes(objects.certificateEnvelope.result)).toString("hex"), canonical.certificate.bytesHex);
  assert.equal(digestHex(objects.certificateEnvelope.result), canonical.certificate.digest);
  assert.equal(agentHandshakeV2ResultDigest(objects.certificateEnvelope), "609fb08d7285a5e2799d9396210c09cd0354bdb3b90a3732820ac32c4168b9f8");
});

test("v2 protocol package verifies the historical proposal, acceptance, descriptor, result, and certificate", async () => {
  const { canonical, objects } = fixture;
  const expectedSessionId = objects.proposalEnvelope.payload.sessionId;
  const expectedRepositorySha = objects.proposalEnvelope.payload.repositorySha;
  const expectedHostSessionKeyCertificateDigest = hostSessionKeyCertificateDigest(
    objects.certificateEnvelope.hostSessionKeyCertificate,
  );
  const rootKeyRing = [{
    kid: objects.certificateEnvelope.hostSessionKeyCertificate.rootSignature.keyId,
    publicKey: objects.certificateEnvelope.hostSessionKeyCertificate.rootSignature.publicKey,
    fingerprint: ed25519PublicKeyFingerprint(
      objects.certificateEnvelope.hostSessionKeyCertificate.rootSignature.publicKey,
    ),
  }];

  assert.equal(expectedHostSessionKeyCertificateDigest, objects.certificateEnvelope.result.hostSessionKeyCertificateDigest);
  assert.equal(expectedHostSessionKeyCertificateDigest, "be3e5869e69ef4ab45a0d1d76c6eb16d66a8363459dcedbb93a5ad20ef6c45bb");

  await verifyAgentHandshakeV2Proposal({
    envelope: objects.proposalEnvelope,
    expectedRepositorySha,
    expectedSessionId,
    expectedTerms: objects.terms,
    nowMs: 1786337160000,
  });
  await verifyAgentHandshakeV2Acceptance({
    envelope: objects.acceptanceEnvelope,
    expectedRepositorySha,
    expectedSessionId,
    expectedTerms: objects.terms,
    nowMs: 1786337160000,
    proposalEnvelope: objects.proposalEnvelope,
  });
  verifyAgentHandshakeV2DescriptorEnvelope(objects.descriptorEnvelope, {
    expectedHostSessionKeyCertificateDigest,
    expectedPublicKey: objects.certificateEnvelope.hostSessionKeyCertificate.certificate.sessionPublicKey,
  });
  verifyHostSessionKeyCertificate(objects.certificateEnvelope.hostSessionKeyCertificate, {
    expectedRepositorySha,
    expectedSessionId,
    nowMs: 1786337160000,
    rootKeyRing,
    sessionDeadlineMs: 1786337600000,
  });

  const transitionDigests = objects.certificateEnvelope.result.anchors.map((anchor) => anchor.digest);
  assert.deepEqual(transitionDigests, [
    "91c1509f5b92ec94827c5165761984d27b86ecac414d91d82f4e2b0135f09fbf",
    "b1a809194611341812df8cbf345789f7bb6b07e60532b223873664dd5ae0d8f8",
    "f969ae2ca72384e4e0961950b5faab4bfeaa40f4218133e688f4d6ed97017d6d",
  ]);
  assert.equal(agentHandshakeV2TransitionDigest({
    expiresAtMs: objects.proposalEnvelope.payload.expiresAtMs,
    externalBusinessActionPerformed: false,
    initiator: objects.parties.initiator,
    kind: "PROPOSED",
    predecessor: null,
    protocol: "clockchain.agent-handshake/v2",
    reference: objects.terms.reference,
    responder: objects.parties.responder,
    schema: "clockchain.agent-handshake-transition/v2",
    sequence: "1",
    sessionDigest: canonical.descriptor.digest,
    statementDigest: canonical.terms.digest,
  }), transitionDigests[0]);
  for (const role of ["initiator", "responder"]) {
    await verifyAgentHandshakeV2Evidence({
      envelope: objects.evidence[role],
      expectedParty: objects.parties[role],
      expectedPolicyDigest: objects.parties[role].policyDigest,
      expectedReference: objects.terms.reference,
      expectedRepositorySha,
      expectedRole: role,
      expectedSessionDigest: canonical.descriptor.digest,
      expectedStatementDigest: canonical.terms.digest,
      expectedTransitionDigests: transitionDigests,
      identityPolicy: objects.terms.identityPolicy,
    });
  }

  for (const role of ["initiator", "responder"]) {
    const verified = verifyAgentHandshakeV2Result(objects.certificateEnvelope, {
      expectedParty: objects.parties[role],
      expectedPolicyDigest: objects.parties[role].policyDigest,
      expectedRepositorySha,
      expectedRole: role,
      expectedSessionId,
      nowMs: 1786337160000,
      rootKeyRing,
      sessionDeadlineMs: 1786337600000,
    });
    assert.equal(verified.certificateVerified, true);
    assert.equal(verified.role, role);
  }
});
