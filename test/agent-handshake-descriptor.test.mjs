import assert from "node:assert/strict";
import test from "node:test";
import { generateKeyPairSync } from "node:crypto";

import {
  AGENT_HANDSHAKE_DESCRIPTOR_SCHEMA,
  AgentHandshakeDescriptorError,
  OperatorKeyMismatchError,
  agentDescriptorDigest,
  createAgentDescriptorEnvelope,
  rawAgentOperatorPublicKey,
  validateAgentDescriptor,
  verifyAgentDescriptorEnvelope,
} from "../src/agent-handshake/descriptor.mjs";

function operator(keyId) {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  return Object.freeze({
    keyId,
    privateKeyPem: privateKey.export({ format: "pem", type: "pkcs8" }),
    publicKeyPem: publicKey.export({ format: "pem", type: "spki" }),
  });
}

const HOST = operator("session-host-1");
const FOREIGN_HOST = operator("session-host-2");
const PUBLIC_KEY = rawAgentOperatorPublicKey(HOST.publicKeyPem);
const SESSION_ID = "11111111-2222-4333-8444-555555555555";

function descriptor(overrides = {}) {
  return {
    chainId: "11155111",
    expiresAtMs: "1786339800000",
    externalActionPerformed: false,
    initiator: {
      address: "0x00112233445566778899aabbccddeeff00112233",
      agentId: "9452",
    },
    operatorPublicKey: PUBLIC_KEY,
    protocol: "clockchain.agent-handshake/v1",
    reference: "NS-1847",
    registryAddress: "0x8004a818bfb912233c491871b3d84c89a494bd9e",
    repositorySha: "a".repeat(40),
    responder: {
      address: "0xffeeddccbbaa99887766554433221100ffeeddcc",
      agentId: "9453",
    },
    schema: AGENT_HANDSHAKE_DESCRIPTOR_SCHEMA,
    sessionId: SESSION_ID,
    statementDigest: "b".repeat(64),
    ...overrides,
  };
}

test("host signs the exact generic descriptor and pins its discovery key", () => {
  const envelope = createAgentDescriptorEnvelope(descriptor(), {
    keyId: HOST.keyId,
    privateKeyPem: HOST.privateKeyPem,
  });
  assert.deepEqual(Object.keys(envelope), ["descriptor", "operator"]);
  assert.deepEqual(Object.keys(envelope.descriptor), [
    "chainId",
    "expiresAtMs",
    "externalActionPerformed",
    "initiator",
    "operatorPublicKey",
    "protocol",
    "reference",
    "registryAddress",
    "repositorySha",
    "responder",
    "schema",
    "sessionId",
    "statementDigest",
  ]);
  assert.deepEqual(
    verifyAgentDescriptorEnvelope(envelope, { expectedPublicKey: PUBLIC_KEY }),
    envelope,
  );
  assert.match(agentDescriptorDigest(envelope.descriptor), /^[0-9a-f]{64}$/);
});

test("descriptor validation rejects extra, payment, identity, and invariant mutations", () => {
  const mutations = [
    { ...descriptor(), amount: "0" },
    descriptor({ externalActionPerformed: true }),
    descriptor({ statementDigest: "not-a-digest" }),
    descriptor({ sessionId: "not-a-session" }),
    descriptor({ expiresAtMs: "01786339800000" }),
    descriptor({ initiator: { ...descriptor().initiator, agentId: "09452" } }),
    descriptor({ responder: descriptor().initiator }),
    descriptor({ registryAddress: "0x00112233445566778899aabbccddeeff00112233" }),
  ];
  for (const value of mutations) {
    assert.throws(
      () => validateAgentDescriptor(value),
      (error) =>
        error instanceof AgentHandshakeDescriptorError &&
        error.code === "AGENT_HANDSHAKE_DESCRIPTOR_INVALID",
    );
  }
});

test("descriptor verification rejects a foreign host, wrong trust root, and tampering", () => {
  const envelope = createAgentDescriptorEnvelope(descriptor(), {
    keyId: HOST.keyId,
    privateKeyPem: HOST.privateKeyPem,
  });
  const foreignPublicKey = rawAgentOperatorPublicKey(FOREIGN_HOST.publicKeyPem);
  assert.throws(
    () => verifyAgentDescriptorEnvelope(envelope, { expectedPublicKey: foreignPublicKey }),
    (error) => error instanceof OperatorKeyMismatchError,
  );

  const foreignEnvelope = createAgentDescriptorEnvelope(
    descriptor({ operatorPublicKey: foreignPublicKey }),
    { keyId: FOREIGN_HOST.keyId, privateKeyPem: FOREIGN_HOST.privateKeyPem },
  );
  assert.throws(
    () => verifyAgentDescriptorEnvelope(foreignEnvelope, { expectedPublicKey: PUBLIC_KEY }),
    (error) => error instanceof OperatorKeyMismatchError,
  );

  const tampered = structuredClone(envelope);
  tampered.descriptor.reference = "NS-1848";
  assert.throws(
    () => verifyAgentDescriptorEnvelope(tampered, { expectedPublicKey: PUBLIC_KEY }),
    { code: "AGENT_HANDSHAKE_DESCRIPTOR_SIGNATURE" },
  );
});

test("generic descriptor bytes contain no payment vocabulary", () => {
  const envelope = createAgentDescriptorEnvelope(descriptor(), {
    keyId: HOST.keyId,
    privateKeyPem: HOST.privateKeyPem,
  });
  const text = JSON.stringify(envelope).toLowerCase();
  for (const word of [
    "amount",
    "currency",
    "invoice",
    "payer",
    "payee",
    "payment",
    "requestor",
  ]) {
    assert.equal(text.includes(word), false, word);
  }
});
