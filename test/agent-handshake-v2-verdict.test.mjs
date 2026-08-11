import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import { verifyAgentHandshakeV2Authorization } from "../src/agent-handshake/v2/verdict.mjs";
import { createAgentHandshakeV2DescriptorEnvelope } from "../src/agent-handshake/v2/descriptor.mjs";
import {
  NOW_MS, REPOSITORY_SHA, SESSION_ID, TERMS, buildV2Fixture,
} from "./support/agent-handshake-v2-fixture.mjs";

function input(fixture) {
  return {
    acceptanceEnvelope: fixture.acceptanceEnvelope,
    descriptorEnvelope: fixture.descriptorEnvelope,
    evidence: fixture.evidence,
    expectedHostSessionKeyCertificateDigest: fixture.descriptorEnvelope.descriptor.hostSessionKeyCertificateDigest,
    expectedPublicKey: fixture.host.publicKey,
    expectedRepositorySha: REPOSITORY_SHA,
    expectedSessionId: SESSION_ID,
    expectedTerms: TERMS,
    nowMs: NOW_MS,
    proposalEnvelope: fixture.proposalEnvelope,
    receipts: fixture.receipts,
    resolveRegistration: async (party) => ({
      owner: party.sessionKeyAddress,
      registrationBlock: party.erc8004.registrationBlock,
    }),
    transitions: fixture.transitions,
  };
}

test("checker emits one positive verdict only after every independent artifact verifies", async () => {
  const fixture = await buildV2Fixture();
  assert.equal(fixture.verdict.outcome, "VERIFIED");
  assert.equal(fixture.verdict.externalBusinessActionPerformed, false);
  const source = await readFile(new URL("../src/agent-handshake/v2/verdict.mjs", import.meta.url), "utf8");
  assert.equal((source.match(/outcome:\s*"VERIFIED"/g) ?? []).length, 1);
});

test("wrong fresh-registration ownership, chronology, receipt, or duplicate identity fails", async () => {
  const fixture = await buildV2Fixture();
  await assert.rejects(() => verifyAgentHandshakeV2Authorization({
    ...input(fixture),
    resolveRegistration: async () => ({ owner: "0x" + "9".repeat(40), registrationBlock: "7000" }),
  }));
  await assert.rejects(() => verifyAgentHandshakeV2Authorization({
    ...input(fixture),
    resolveRegistration: async (party) => ({
      owner: party.sessionKeyAddress,
      registrationBlock: "6999",
    }),
  }));
  await assert.rejects(() => verifyAgentHandshakeV2Authorization({
    ...input(fixture),
    receipts: [{ ...fixture.receipts[0], digest: "f".repeat(64) }, ...fixture.receipts.slice(1)],
  }));
  const wrongPolicyDescriptor = createAgentHandshakeV2DescriptorEnvelope({
    ...fixture.descriptorEnvelope.descriptor,
    initiator: { ...fixture.parties.initiator, policyDigest: "f".repeat(64) },
  }, { keyId: fixture.host.keyId, privateKeyPem: fixture.host.privateKeyPem });
  await assert.rejects(() => verifyAgentHandshakeV2Authorization({
    ...input(fixture),
    descriptorEnvelope: wrongPolicyDescriptor,
  }));
});

test("checker uses the accepted ledger time instead of its later wall clock", async () => {
  const fixture = await buildV2Fixture();
  const proposalIssuedAtMs = Number(fixture.proposalEnvelope.payload.issuedAtMs);
  const acceptanceIssuedAtMs = Number(fixture.acceptanceEnvelope.payload.issuedAtMs);
  const expiresAtMs = Number(fixture.proposalEnvelope.payload.expiresAtMs);
  const receipts = fixture.receipts.map((receipt, index) => ({
    ...receipt,
    blockTimeRaw: new Date([
      proposalIssuedAtMs + 30_000,
      acceptanceIssuedAtMs + 5_000,
      expiresAtMs + 20_000,
    ][index]).toISOString(),
  }));

  await assert.doesNotReject(() => verifyAgentHandshakeV2Authorization({
    ...input(fixture),
    nowMs: expiresAtMs + 60_000,
    receipts,
  }));

  await assert.rejects(() => verifyAgentHandshakeV2Authorization({
    ...input(fixture),
    nowMs: expiresAtMs + 60_000,
    receipts: receipts.map((receipt, index) => index === 1
      ? { ...receipt, blockTimeRaw: new Date(expiresAtMs).toISOString() }
      : receipt),
  }));
});
