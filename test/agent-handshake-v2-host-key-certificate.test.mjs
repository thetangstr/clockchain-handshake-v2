import assert from "node:assert/strict";
import test from "node:test";

import {
  createHostSessionKeyCertificate,
  ed25519PublicKeyFingerprint,
  verifyHostSessionKeyCertificate,
} from "../src/agent-handshake/v2/host-key-certificate.mjs";
import {
  NOW_MS, REPOSITORY_SHA, SESSION_DEADLINE_MS, SESSION_ID, buildV2Fixture, ed25519,
} from "./support/agent-handshake-v2-fixture.mjs";

test("root-signed session key is pinned to session, repository, key, and bounded validity", async () => {
  const fixture = await buildV2Fixture();
  const ring = [{
    kid: fixture.root.keyId,
    publicKey: fixture.hostSessionKeyCertificate.rootSignature.publicKey,
    fingerprint: ed25519PublicKeyFingerprint(fixture.hostSessionKeyCertificate.rootSignature.publicKey),
  }];
  const verified = verifyHostSessionKeyCertificate(fixture.hostSessionKeyCertificate, {
    expectedRepositorySha: REPOSITORY_SHA,
    expectedSessionId: SESSION_ID,
    nowMs: NOW_MS,
    rootKeyRing: ring,
    sessionDeadlineMs: Number(SESSION_DEADLINE_MS),
  });
  assert.equal(verified.certificate.sessionPublicKey, fixture.host.publicKey);
});

test("validly signed foreign, unknown, stale, early, expired, and overlong certificates fail", async () => {
  const fixture = await buildV2Fixture();
  const foreign = ed25519("foreign-root");
  const ring = [{
    kid: fixture.root.keyId,
    publicKey: fixture.hostSessionKeyCertificate.rootSignature.publicKey,
    fingerprint: ed25519PublicKeyFingerprint(fixture.hostSessionKeyCertificate.rootSignature.publicKey),
  }];
  const variants = [
    { root: foreign, certificate: { ...fixture.hostSessionKeyCertificate.certificate, rootKid: foreign.keyId } },
    { root: fixture.root, certificate: { ...fixture.hostSessionKeyCertificate.certificate, sessionId: "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee" } },
    { root: fixture.root, certificate: { ...fixture.hostSessionKeyCertificate.certificate, repositorySha: "e".repeat(40) } },
    { root: fixture.root, certificate: { ...fixture.hostSessionKeyCertificate.certificate, validFromMs: String(NOW_MS + 1) } },
    { root: fixture.root, certificate: { ...fixture.hostSessionKeyCertificate.certificate, validUntilMs: String(NOW_MS) } },
    { root: fixture.root, certificate: { ...fixture.hostSessionKeyCertificate.certificate, validUntilMs: String(Number(SESSION_DEADLINE_MS) + 1) } },
  ];
  for (const { root, certificate } of variants) {
    const envelope = createHostSessionKeyCertificate({
      certificate,
      root: { keyId: root.keyId, privateKeyPem: root.privateKeyPem },
    });
    assert.throws(() => verifyHostSessionKeyCertificate(envelope, {
      expectedRepositorySha: REPOSITORY_SHA,
      expectedSessionId: SESSION_ID,
      nowMs: NOW_MS,
      rootKeyRing: ring,
      sessionDeadlineMs: Number(SESSION_DEADLINE_MS),
    }));
  }
});
