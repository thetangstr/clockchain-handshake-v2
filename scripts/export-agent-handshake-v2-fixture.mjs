#!/usr/bin/env node
import { canonicalBytes, digestHex } from "../src/core/canonical.mjs";
import { agentHandshakeV2StatementDigest } from "../src/agent-handshake/v2/terms.mjs";
import { buildV2Fixture, REPOSITORY_SHA, SESSION_ID, TERMS } from "../test/support/agent-handshake-v2-fixture.mjs";

function canonical(value) {
  const bytes = canonicalBytes(value);
  return Object.freeze({ bytesHex: bytes.toString("hex"), digest: digestHex(value) });
}

export async function exportAgentHandshakeV2Fixture(sourceCommit) {
  if (!/^[0-9a-f]{40}$/.test(sourceCommit)) throw new Error("invalid source commit");
  const fixture = await buildV2Fixture();
  const identityClaims = Object.fromEntries(["initiator", "responder"].map((role) => [role, {
    schema: "clockchain.agent-handshake-identity-claim/v2",
    protocol: "clockchain.agent-handshake/v2",
    sessionId: SESSION_ID,
    repositorySha: REPOSITORY_SHA,
    role,
    sessionKeyAddress: fixture.parties[role].sessionKeyAddress,
    policyDigest: fixture.parties[role].policyDigest,
    statementDigest: agentHandshakeV2StatementDigest(TERMS),
    externalBusinessActionPerformed: false,
  }]));
  const objects = {
    terms: TERMS,
    policies: fixture.policies,
    parties: fixture.parties,
    identityClaims,
    proposalEnvelope: fixture.proposalEnvelope,
    acceptanceEnvelope: fixture.acceptanceEnvelope,
    evidence: fixture.evidence,
    descriptorEnvelope: fixture.descriptorEnvelope,
    certificateEnvelope: fixture.resultEnvelope,
  };
  const canonicalRecords = {
    terms: canonical(objects.terms),
    policies: Object.fromEntries(Object.entries(objects.policies).map(([key, value]) => [key, canonical(value)])),
    parties: Object.fromEntries(Object.entries(objects.parties).map(([key, value]) => [key, canonical(value)])),
    identityClaims: Object.fromEntries(Object.entries(objects.identityClaims).map(([key, value]) => [key, canonical(value)])),
    proposal: canonical(objects.proposalEnvelope.payload),
    acceptance: canonical(objects.acceptanceEnvelope.payload),
    evidence: Object.fromEntries(Object.entries(objects.evidence).map(([key, value]) => [key, canonical(value.result)])),
    descriptor: canonical(objects.descriptorEnvelope.descriptor),
    certificate: canonical(objects.certificateEnvelope.result),
  };
  return {
    schema: "clockchain.agent-handshake-v2-canonical-fixture/v1",
    handshakeSourceCommit: sourceCommit,
    objects,
    canonical: canonicalRecords,
  };
}

if (import.meta.url === new URL(`file://${process.argv[1]}`).href) {
  const value = await exportAgentHandshakeV2Fixture(process.argv[2]);
  process.stdout.write(JSON.stringify(value, null, 2) + "\n");
}
