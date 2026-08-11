import { createHash } from "node:crypto";
import { gzipSync } from "node:zlib";

import { canonicalBytes } from "../../src/core/canonical.mjs";
import { ed25519PublicKeyFingerprint } from "../../src/agent-handshake/v2/host-key-certificate.mjs";
import {
  NOW_MS,
  REPOSITORY_SHA,
  SESSION_DEADLINE_MS,
  SESSION_ID,
  TERMS,
  buildV2Fixture,
} from "./agent-handshake-v2-fixture.mjs";

export async function buildAgentCliFixture(role = "initiator") {
  const fixture = await buildV2Fixture();
  const payload = role === "initiator"
    ? fixture.proposalEnvelope.payload
    : fixture.acceptanceEnvelope.payload;
  const bytes = canonicalBytes(payload);
  const policy = fixture.policies[role];
  return {
    ...fixture,
    nowMs: NOW_MS,
    policy,
    request: {
      schema: "clockchain.agent-handshake-signing-request/v1",
      helperVersion: "2.1.2",
      operation: role === "initiator" ? "proposal" : "acceptance",
      role,
      sessionId: SESSION_ID,
      repositorySha: REPOSITORY_SHA,
      sessionDeadlineMs: SESSION_DEADLINE_MS,
      hostSessionKeyCertificate: fixture.hostSessionKeyCertificate,
      terms: TERMS,
      policyDigest: fixture.parties[role].policyDigest,
      bytesGzipBase64Url: gzipSync(bytes).toString("base64url"),
      bytesSha256: createHash("sha256").update(bytes).digest("hex"),
      externalBusinessActionPerformed: false,
    },
    rootKeyRing: [{
      kid: fixture.root.keyId,
      publicKey: fixture.hostSessionKeyCertificate.rootSignature.publicKey,
      fingerprint: ed25519PublicKeyFingerprint(
        fixture.hostSessionKeyCertificate.rootSignature.publicKey,
      ),
      notBeforeMs: String(NOW_MS - 60_000),
      notAfterMs: String(Number(SESSION_DEADLINE_MS) + 60_000),
    }],
  };
}
