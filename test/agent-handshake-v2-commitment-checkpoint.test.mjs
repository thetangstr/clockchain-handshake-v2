import assert from "node:assert/strict";
import test from "node:test";

import {
  commitmentCheckpointDigest,
  commitmentCheckpointSigningBytes,
  normalizeV2CommitmentCheckpoint,
} from "../src/agent-handshake/v2/commitment-checkpoint.mjs";

const SESSION_ID = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";
const SIGNER = "0x" + "1".repeat(40);
const SIGNATURE = { address: SIGNER, algorithm: "eip191", value: "0x" + "f".repeat(130) };

function proposalCheckpoint(overrides = {}) {
  return {
    schema: "clockchain.agent-handshake-commitment-checkpoint/v1",
    version: "1",
    protocol: "clockchain.agent-handshake/v2",
    sessionId: SESSION_ID,
    role: "initiator",
    artifactType: "proposal",
    artifactDigest: "a".repeat(64),
    sequence: "1",
    previousCheckpointDigest: null,
    issuedAtMs: "1789866096979",
    expiresAtMs: "1789866186979",
    signerAddress: SIGNER,
    signature: SIGNATURE,
    ...overrides,
  };
}

// Known-answer against the coordinator's own commitment-checkpoint
// implementation: identical bytes and digest for this exact checkpoint were
// produced by packages/mcp-server/src/agent-handshake/v2/commitment-checkpoint
// at the same input, which is what submitCheckpoint verifies against.
test("canonical signing bytes and digest match the coordinator implementation", () => {
  const checkpoint = proposalCheckpoint();
  assert.equal(
    commitmentCheckpointDigest(checkpoint),
    "85a11c8ec54b4ccda618cf4f858c5c5fb11e37829a3c17afb037096716cfed77",
  );
  assert.equal(
    commitmentCheckpointSigningBytes(checkpoint).toString("utf8"),
    '{"artifactDigest":"' + "a".repeat(64) + '","artifactType":"proposal","expiresAtMs":"1789866186979","issuedAtMs":"1789866096979","previousCheckpointDigest":null,"protocol":"clockchain.agent-handshake/v2","role":"initiator","schema":"clockchain.agent-handshake-commitment-checkpoint/v1","sequence":"1","sessionId":"' + SESSION_ID + '","signerAddress":"' + SIGNER + '","version":"1"}',
  );
});

test("signing bytes exclude the signature field only", () => {
  const checkpoint = proposalCheckpoint();
  const unsigned = commitmentCheckpointSigningBytes(checkpoint).toString("utf8");
  assert.ok(!unsigned.includes("signature"));
  // The digest covers the full checkpoint including the signature, so the two
  // encodings must differ.
  const full = commitmentCheckpointDigest(checkpoint);
  assert.notEqual(
    commitmentCheckpointDigest({ ...checkpoint, signature: { ...SIGNATURE, value: "0x" + "e".repeat(130) } }),
    full,
  );
});

test("proposal checkpoints require sequence 1 and no predecessor", () => {
  assert.throws(() => normalizeV2CommitmentCheckpoint(proposalCheckpoint({ sequence: "2" })));
  assert.throws(() => normalizeV2CommitmentCheckpoint(proposalCheckpoint({ previousCheckpointDigest: "b".repeat(64) })));
});

test("acceptance checkpoints require sequence >= 2 and a predecessor digest", () => {
  const base = proposalCheckpoint({ artifactType: "acceptance", role: "responder", sequence: "2", previousCheckpointDigest: "c".repeat(64) });
  assert.equal(normalizeV2CommitmentCheckpoint(base).artifactType, "acceptance");
  assert.throws(() => normalizeV2CommitmentCheckpoint({ ...base, sequence: "1" }));
  assert.throws(() => normalizeV2CommitmentCheckpoint({ ...base, previousCheckpointDigest: null }));
  assert.throws(() => normalizeV2CommitmentCheckpoint({ ...base, previousCheckpointDigest: "not-a-digest" }));
});

test("exact-key and field-shape mutations are rejected", () => {
  const base = proposalCheckpoint();
  for (const mutation of [
    { ...base, extra: true },
    (() => { const { version: _v, ...rest } = base; return rest; })(),
    { ...base, sessionId: "AAAAAAAA-BBBB-4CCC-8DDD-EEEEEEEEEEEE" },
    { ...base, issuedAtMs: base.expiresAtMs },
    { ...base, signerAddress: SIGNER.toUpperCase() },
    { ...base, signature: { ...SIGNATURE, algorithm: "eip712" } },
    { ...base, signature: { ...SIGNATURE, address: "0x" + "2".repeat(40) } },
    { ...base, signature: { ...SIGNATURE, value: SIGNATURE.value.slice(0, -1) + "F" } },
  ]) {
    assert.throws(() => normalizeV2CommitmentCheckpoint(mutation));
  }
});
