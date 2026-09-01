import assert from "node:assert/strict";
import { recoverMessageAddress } from "viem";
import test from "node:test";

import {
  commitmentCheckpointDigest,
  commitmentCheckpointSigningBytes,
  executeDirectAgentCheckpointRequest,
  validateDirectAgentCheckpointResult,
} from "../src/direct-agent-signer/checkpoint.mjs";
import { canonicalBytes, digestHex } from "../src/core/canonical.mjs";
import { buildAgentCliFixture } from "./support/agent-cli-fixture.mjs";
import { INITIATOR } from "./support/agent-handshake-v2-fixture.mjs";

const SCHEMA = "clockchain.direct-agent-signer-checkpoint-request/v1";
const RESULT_SCHEMA = "clockchain.direct-agent-signer-checkpoint-result/v1";
const VERSION = "1.1.0";

function requestFor(fixture, artifactType, previousCheckpoint = null) {
  const envelope = artifactType === "proposal"
    ? fixture.proposalEnvelope
    : fixture.acceptanceEnvelope;
  return {
    schema: SCHEMA,
    adapterVersion: VERSION,
    role: artifactType === "proposal" ? "initiator" : "responder",
    sessionId: fixture.request.sessionId,
    repositorySha: fixture.request.repositorySha,
    sessionDeadlineMs: fixture.request.sessionDeadlineMs,
    artifactType,
    artifactPayload: envelope.payload,
    artifactSignatureHex: envelope.signature.value,
    previousCheckpoint,
    issuedAtMs: "1786337160000",
    expiresAtMs: "1786337220000",
    externalBusinessActionPerformed: false,
  };
}

function resultShape(result) {
  return {
    schema: result.schema,
    adapterVersion: result.adapterVersion,
    role: result.role,
    sessionId: result.sessionId,
    artifactType: result.artifactType,
    checkpointDigest: result.checkpointDigest,
    signerAddress: result.signerAddress,
  };
}

test("creates a proposal checkpoint from the role wallet without requiring a final certificate", async () => {
  const fixture = await buildAgentCliFixture();
  const request = requestFor(fixture, "proposal");
  const address = fixture.parties.initiator.sessionKeyAddress;
  let calls = 0;

  const result = await executeDirectAgentCheckpointRequest({
    address,
    localPolicy: fixture.policies.initiator,
    nowMs: fixture.nowMs,
    registration: fixture.parties.initiator.erc8004,
    request,
    sign: async (input) => {
      calls += 1;
      assert.match(input.bytesHex, /^0x[0-9a-f]+$/);
      return {
        address,
        bytesSha256: input.expectedBytesSha256,
        signatureHex: "0x" + "3".repeat(130),
      };
    },
  });

  assert.deepEqual(resultShape(result), {
    schema: RESULT_SCHEMA,
    adapterVersion: VERSION,
    role: "initiator",
    sessionId: fixture.request.sessionId,
    artifactType: "proposal",
    checkpointDigest: commitmentCheckpointDigest(result.checkpoint),
    signerAddress: address,
  });
  assert.equal(result.checkpoint.schema, "clockchain.agent-handshake-commitment-checkpoint/v1");
  assert.equal(result.checkpoint.sequence, "1");
  assert.equal(result.checkpoint.previousCheckpointDigest, null);
  assert.equal(result.checkpoint.artifactDigest, digestHex({
    payload: request.artifactPayload,
    schema: "clockchain.agent-handshake-proposal-envelope/v2",
    signature: { address, algorithm: "eip191", value: request.artifactSignatureHex },
  }));
  assert.equal(result.checkpoint.signature.value, "0x" + "3".repeat(130));
  assert.equal(Object.hasOwn(result, "retainedV2Certificate"), false);
  assert.equal(calls, 1);
});

test("creates a proposal checkpoint from a raw registration recovery with an external identity reference", async () => {
  const fixture = await buildAgentCliFixture();
  const address = fixture.parties.initiator.sessionKeyAddress;
  const registered = fixture.parties.initiator.erc8004;
  const recovery = {
    schema: "clockchain.handshake-registration-recovery/v1",
    agentId: registered.agentId,
    address,
    displayName: "Direct participant",
    identityReference: "https://identity.example/direct-participant.json",
    registerTx: registered.registrationTx,
    registerBlock: registered.registrationBlock,
    metadataTx: null,
    metadataBlock: null,
  };

  const result = await executeDirectAgentCheckpointRequest({
    address,
    localPolicy: fixture.policies.initiator,
    nowMs: fixture.nowMs,
    registration: recovery,
    request: requestFor(fixture, "proposal"),
    sign: async (input) => ({
      address,
      bytesSha256: input.expectedBytesSha256,
      signatureHex: "0x" + "7".repeat(130),
    }),
  });

  assert.equal(result.checkpoint.role, "initiator");
  assert.equal(result.checkpoint.artifactType, "proposal");
});

test("creates an acceptance checkpoint chained to the proposal checkpoint", async () => {
  const fixture = await buildAgentCliFixture();
  const initiator = fixture.parties.initiator.sessionKeyAddress;
  const responder = fixture.parties.responder.sessionKeyAddress;
  const proposal = await executeDirectAgentCheckpointRequest({
    address: initiator,
    localPolicy: fixture.policies.initiator,
    nowMs: fixture.nowMs,
    registration: fixture.parties.initiator.erc8004,
    request: requestFor(fixture, "proposal"),
    sign: async (input) => ({
      address: initiator,
      bytesSha256: input.expectedBytesSha256,
      signatureHex: "0x" + "4".repeat(130),
    }),
  });

  const result = await executeDirectAgentCheckpointRequest({
    address: responder,
    localPolicy: fixture.policies.responder,
    nowMs: fixture.nowMs,
    registration: fixture.parties.responder.erc8004,
    request: requestFor(fixture, "acceptance", proposal.checkpoint),
    sign: async (input) => ({
      address: responder,
      bytesSha256: input.expectedBytesSha256,
      signatureHex: "0x" + "5".repeat(130),
    }),
  });

  assert.equal(result.checkpoint.sequence, "2");
  assert.equal(result.checkpoint.previousCheckpointDigest, commitmentCheckpointDigest(proposal.checkpoint));
});

test("real wallet signatures recover to the checkpoint signer over exact canonical bytes", async () => {
  const fixture = await buildAgentCliFixture();
  const address = fixture.parties.initiator.sessionKeyAddress;
  const result = await executeDirectAgentCheckpointRequest({
    address,
    localPolicy: fixture.policies.initiator,
    nowMs: fixture.nowMs,
    registration: fixture.parties.initiator.erc8004,
    request: requestFor(fixture, "proposal"),
    sign: async (input) => {
      const raw = `0x${Buffer.from(input.bytesHex.slice(2), "hex").toString("hex")}`;
      const signatureHex = await INITIATOR.signMessage({ message: { raw } });
      return { address, bytesSha256: input.expectedBytesSha256, signatureHex };
    },
  });

  assert.equal(
    await recoverMessageAddress({
      message: { raw: `0x${commitmentCheckpointSigningBytes(result.checkpoint).toString("hex")}` },
      signature: result.checkpoint.signature.value,
    }).then((value) => value.toLowerCase()),
    address,
  );
});

test("validates exact checkpoint result provenance for endpoint adapters", async () => {
  const fixture = await buildAgentCliFixture();
  const address = fixture.parties.initiator.sessionKeyAddress;
  const checkpoint = {
    schema: "clockchain.agent-handshake-commitment-checkpoint/v1",
    version: "1",
    protocol: "clockchain.agent-handshake/v2",
    sessionId: fixture.request.sessionId,
    role: "initiator",
    artifactType: "proposal",
    artifactDigest: "d".repeat(64),
    sequence: "1",
    previousCheckpointDigest: null,
    issuedAtMs: "1786337160000",
    expiresAtMs: "1786337220000",
    signerAddress: address,
    signature: { address, algorithm: "eip191", value: "0x" + "3".repeat(130) },
  };
  const result = {
    schema: RESULT_SCHEMA,
    adapterVersion: VERSION,
    role: "initiator",
    sessionId: fixture.request.sessionId,
    artifactType: "proposal",
    checkpoint,
    checkpointDigest: commitmentCheckpointDigest(checkpoint),
    signerAddress: address,
  };

  assert.deepEqual(validateDirectAgentCheckpointResult(result), result);
  for (const mutated of [
    { ...result, schema: "clockchain.direct-agent-signer-checkpoint-result/v2" },
    { ...result, adapterVersion: "1.0.0" },
    { ...result, artifactType: "acceptance" },
    { ...result, checkpointDigest: "e".repeat(64) },
    { ...result, extra: true },
    Object.fromEntries(Object.entries(result).filter(([key]) => key !== "adapterVersion")),
  ]) {
    assert.throws(() => validateDirectAgentCheckpointResult(mutated));
  }
});

test("rejects checkpoint request and binding mutations before signing", async () => {
  const fixture = await buildAgentCliFixture();
  const request = requestFor(fixture, "proposal");
  const address = fixture.parties.initiator.sessionKeyAddress;
  let calls = 0;
  const sign = async () => {
    calls += 1;
    return {};
  };
  const mutations = [
    { ...request, schema: "clockchain.direct-agent-signer-checkpoint-request/v2" },
    { ...request, adapterVersion: "1.0.0" },
    { ...request, role: "responder" },
    { ...request, sessionId: "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee" },
    { ...request, repositorySha: "e".repeat(40) },
    { ...request, sessionDeadlineMs: "1786337000000" },
    { ...request, artifactType: "acceptance" },
    { ...request, artifactPayload: { ...request.artifactPayload, sessionId: "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee" } },
    { ...request, artifactSignatureHex: "0x" + "1".repeat(130) },
    { ...request, previousCheckpoint: { schema: "clockchain.agent-handshake-commitment-checkpoint/v1" } },
    { ...request, issuedAtMs: "1786337220000" },
    { ...request, expiresAtMs: "1786337160000" },
    { ...request, externalBusinessActionPerformed: true },
    { ...request, extra: true },
  ];

  for (const mutated of mutations) {
    await assert.rejects(() => executeDirectAgentCheckpointRequest({
      address,
      localPolicy: fixture.policies.initiator,
      nowMs: fixture.nowMs,
      registration: fixture.parties.initiator.erc8004,
      request: mutated,
      sign,
    }));
  }

  await assert.rejects(() => executeDirectAgentCheckpointRequest({
    address: fixture.parties.responder.sessionKeyAddress,
    localPolicy: fixture.policies.initiator,
    nowMs: fixture.nowMs,
    registration: fixture.parties.initiator.erc8004,
    request,
    sign,
  }));
  assert.equal(calls, 0);
});
