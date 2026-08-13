import assert from "node:assert/strict";
import test from "node:test";

import {
  createAgentHandshakeV2Monitor,
} from "../src/monitor/agent-snapshot-v2-producer.mjs";
import { validateAgentHandshakeV2Snapshot } from "../src/monitor/agent-snapshot-v2.mjs";
import { agentHandshakeV2StatementDigest } from "../src/agent-handshake/v2/terms.mjs";
import {
  buildV2Fixture,
  REPOSITORY_SHA,
  SESSION_DEADLINE_MS,
  SESSION_ID,
  SESSION_OPENED_AT_MS,
  SESSION_OPENED_BLOCK,
  TERMS,
} from "./support/agent-handshake-v2-fixture.mjs";

test("the live producer publishes only the artifact just observed", async () => {
  const fixture = await buildV2Fixture();
  const session = {
    hostSessionKeyCertificate: fixture.hostSessionKeyCertificate,
    invitationExpiresAtMs: Number(SESSION_OPENED_AT_MS) + 5 * 60_000,
    protocol: "clockchain.agent-handshake/v2",
    repositorySha: REPOSITORY_SHA,
    sessionDeadlineMs: Number(SESSION_DEADLINE_MS),
    sessionId: SESSION_ID,
    sessionOpenedAtMs: Number(SESSION_OPENED_AT_MS),
    sessionOpenedBlock: SESSION_OPENED_BLOCK,
    terms: TERMS,
  };
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
  const published = [];
  let now = 1786337000000;
  const monitor = createAgentHandshakeV2Monitor({
    now: () => ++now,
    publish: async (snapshot) => published.push(structuredClone(snapshot)),
    session,
  });
  await monitor.start();
  assert.equal(published.at(-1).policies.initiator, null);
  assert.deepEqual(published.at(-1).invitation, {
    createdAtMs: null,
    responderClaimedAtMs: null,
  });
  await monitor.invitationCreated(Number(SESSION_OPENED_AT_MS) + 1);
  assert.deepEqual(published.at(-1).invitation, {
    createdAtMs: Number(SESSION_OPENED_AT_MS) + 1,
    responderClaimedAtMs: null,
  });
  await monitor.invitationClaimed(Number(SESSION_OPENED_AT_MS) + 2);
  assert.equal(published.at(-1).invitation.responderClaimedAtMs, Number(SESSION_OPENED_AT_MS) + 2);
  await monitor.identityClaimed("initiator", identityClaims.initiator);
  assert.equal(published.at(-1).policies.initiator.digest, identityClaims.initiator.policyDigest);
  assert.equal(published.at(-1).parties.initiator, null);
  await monitor.identityClaimed("responder", identityClaims.responder);
  assert.equal(published.at(-1).invitation.responderClaimedAtMs, Number(SESSION_OPENED_AT_MS) + 2);
  await monitor.partiesReady(fixture.parties);
  assert.equal(published.at(-1).parties.initiator.erc8004.agentId, "9452");
  await monitor.proposalSigned(fixture.proposalEnvelope);
  assert.ok(published.at(-1).statements.proposalDigest);
  assert.equal(published.at(-1).statements.acceptanceDigest, null);
  await monitor.acceptanceSigned(fixture.acceptanceEnvelope);
  await monitor.anchorsRecorded({ receipts: fixture.receipts });
  await monitor.evidenceReceived("initiator", fixture.evidence.initiator);
  await monitor.evidenceReceived("responder", fixture.evidence.responder);
  await monitor.checkerStage("VERIFYING");
  await monitor.certificateIssued(fixture.resultEnvelope);
  assert.equal(published.at(-1).checker.stage, "VERIFIED");
  assert.equal(published.at(-1).certificate.outcome, "VERIFIED");
  assert.equal(published.at(-1).externalBusinessActionPerformed, false);
  for (const snapshot of published) assert.equal(validateAgentHandshakeV2Snapshot(snapshot), true);
});

test("a checker failure is visible without fabricating a certificate", async () => {
  const fixture = await buildV2Fixture();
  const published = [];
  const monitor = createAgentHandshakeV2Monitor({
    now: () => 1786337000001,
    publish: async (snapshot) => published.push(snapshot),
    session: {
      hostSessionKeyCertificate: fixture.hostSessionKeyCertificate,
      invitationExpiresAtMs: 1786337300000,
      protocol: "clockchain.agent-handshake/v2",
      repositorySha: REPOSITORY_SHA,
      sessionDeadlineMs: Number(SESSION_DEADLINE_MS),
      sessionId: SESSION_ID,
      sessionOpenedAtMs: Number(SESSION_OPENED_AT_MS),
      sessionOpenedBlock: SESSION_OPENED_BLOCK,
      terms: TERMS,
    },
  });
  await monitor.failed("AGENT_HANDSHAKE_V2_VERDICT_INVALID");
  assert.equal(published.at(-1).checker.stage, "FAILED");
  assert.deepEqual(published.at(-1).failure, { reasonCode: "AGENT_HANDSHAKE_V2_VERDICT_INVALID" });
  assert.equal(published.at(-1).certificate, null);
});
