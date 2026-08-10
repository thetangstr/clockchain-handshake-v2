import assert from "node:assert/strict";
import test from "node:test";

import {
  createAgentHandshakeV2DescriptorEnvelope,
  verifyAgentHandshakeV2DescriptorEnvelope,
} from "../src/agent-handshake/v2/descriptor.mjs";
import { buildV2Fixture, ed25519 } from "./support/agent-handshake-v2-fixture.mjs";

test("only the certified per-session host key signs the exact v2 descriptor", async () => {
  const fixture = await buildV2Fixture();
  const verified = verifyAgentHandshakeV2DescriptorEnvelope(fixture.descriptorEnvelope, {
    expectedHostSessionKeyCertificateDigest: fixture.descriptorEnvelope.descriptor.hostSessionKeyCertificateDigest,
    expectedPublicKey: fixture.host.publicKey,
  });
  assert.equal(verified.descriptor.initiator.policyDigest, fixture.parties.initiator.policyDigest);
});

test("foreign host key, policy, identity mode, registry, or external-action mutations fail", async () => {
  const fixture = await buildV2Fixture();
  const foreign = ed25519("foreign-host");
  const foreignEnvelope = createAgentHandshakeV2DescriptorEnvelope({
    ...fixture.descriptorEnvelope.descriptor,
    operatorPublicKey: foreign.publicKey,
  }, { keyId: foreign.keyId, privateKeyPem: foreign.privateKeyPem });
  assert.throws(() => verifyAgentHandshakeV2DescriptorEnvelope(foreignEnvelope, {
    expectedHostSessionKeyCertificateDigest: fixture.descriptorEnvelope.descriptor.hostSessionKeyCertificateDigest,
    expectedPublicKey: fixture.host.publicKey,
  }));
  for (const descriptor of [
    { ...fixture.descriptorEnvelope.descriptor, externalBusinessActionPerformed: true },
    { ...fixture.descriptorEnvelope.descriptor, identityPolicy: { ...fixture.descriptorEnvelope.descriptor.identityPolicy, registryAddress: "0x" + "1".repeat(40) } },
  ]) {
    assert.throws(() => createAgentHandshakeV2DescriptorEnvelope(descriptor, {
      keyId: fixture.host.keyId,
      privateKeyPem: fixture.host.privateKeyPem,
    }));
  }
});
