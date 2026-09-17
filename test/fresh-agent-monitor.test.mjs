import assert from "node:assert/strict";
import { test } from "node:test";

import {
  certifiedRunRecorded,
  certifiedV2Result,
  certifiedV2Snapshot,
  monitorEvidenceMatches,
  monitorSession,
  sessionMonitorEndpoints,
} from "../src/testing/fresh-agent-monitor.mjs";
import { agentHandshakeV2ResultDigest } from "../src/agent-handshake/v2/result.mjs";
import { digestHex } from "../src/core/canonical.mjs";

const SESSION = "11111111-1111-4111-8111-111111111111";
const OTHER_SESSION = "22222222-2222-4222-8222-222222222222";
const ENDPOINT = "http://relay.test:8080/v1/sessions/{sessionId}/snapshot";
const REGISTRY = "0x8004a818bfb912233c491871b3d84c89a494bd9e";
const CERT_DIGEST = "5".repeat(64);

function registration(agentId, fill, block) {
  return {
    agentId,
    chainId: "eip155:11155111",
    registryAddress: REGISTRY,
    reference: `eip155:11155111:${REGISTRY}:${agentId}`,
    registrationTx: "0x" + fill.repeat(64),
    registrationBlock: block,
  };
}

function receipt(kind, index) {
  return {
    blockHeight: String(7010 + index),
    blockTimeRaw: `2026-08-09T17:0${index}:00.000Z`,
    digest: String(index + 1).repeat(64),
    explorerUrl: `https://clockchain.network/ledger/33333333-4444-4555-8666-77777777777${index}`,
    kind,
    ledgerId: `33333333-4444-4555-8666-77777777777${index}`,
  };
}

function certifiedSnapshot(overrides = {}) {
  return {
    schema: "clockchain.agent-handshake-snapshot/v2",
    protocol: "clockchain.agent-handshake/v2",
    sessionId: SESSION,
    repositorySha: "d".repeat(40),
    hostTrust: {
      rootKid: "root-2026-08",
      rootFingerprint: "a".repeat(64),
      sessionPublicKey: "A".repeat(43) + "=",
      sessionKeyCertificateDigest: "b".repeat(64),
    },
    timing: {
      createdAtMs: 1786337000000,
      invitationExpiresAtMs: 1786337120000,
      sessionDeadlineMs: 1786337600000,
      agreementValidForSeconds: "90",
    },
    invitation: { createdAtMs: 1786337001000, responderClaimedAtMs: 1786337002000 },
    terms: {
      reference: "NS-1847",
      statement: "Northstar and Harbor authorize these agents to communicate.",
      identityPolicy: { erc8004: "required_fresh", chainId: "eip155:11155111", registryAddress: REGISTRY },
    },
    policies: {
      initiator: { digest: "c".repeat(64), committedAtMs: 1786337003000 },
      responder: { digest: "d".repeat(64), committedAtMs: 1786337004000 },
    },
    parties: {
      initiator: { sessionKeyAddress: "0x" + "1".repeat(40), erc8004: registration("9452", "e", "7000") },
      responder: { sessionKeyAddress: "0x" + "2".repeat(40), erc8004: registration("9453", "f", "7001") },
    },
    statements: { proposalDigest: "1".repeat(64), acceptanceDigest: "2".repeat(64) },
    receipts: {
      proposal: receipt("proposal", 0),
      acceptance: receipt("acceptance", 1),
      acknowledgment: receipt("acknowledgment", 2),
    },
    evidence: {
      initiator: { digest: "3".repeat(64), receivedAtMs: 1786337180000 },
      responder: { digest: "4".repeat(64), receivedAtMs: 1786337180001 },
    },
    checker: { stage: "VERIFIED", lastSeenMs: 1786337181000 },
    certificate: { digest: CERT_DIGEST, issuedAtMs: 1786337182000, outcome: "VERIFIED" },
    freshness: {
      initiator: { lastSeenMs: 1786337180000 },
      responder: { lastSeenMs: 1786337180001 },
      host: { lastSeenMs: 1786337181000 },
      checker: { lastSeenMs: 1786337181000 },
    },
    failure: null,
    externalBusinessActionPerformed: false,
    ...overrides,
  };
}

function certifiedRun(overrides = {}) {
  return {
    anchors: { proposal: "7010", acceptance: "7011", acknowledgment: "7012" },
    outcome: "VERIFIED",
    reasonCode: null,
    sessionId: SESSION,
    stage: "CERTIFIED",
    startedAtMs: 1786337000000,
    ...overrides,
  };
}

function certifiedRuns(overrides = {}) {
  return { ok: true, paymentMoved: false, runs: [certifiedRun()], ...overrides };
}

function resultAnchor(kind, index) {
  const { blockHeight, blockTimeRaw, digest, ledgerId } = receipt(kind, index);
  return { blockHeight, blockTimeRaw, digest, kind, ledgerId };
}

function resultEnvelope(overrides = {}) {
  return {
    hostSessionKeyCertificate: { certificateDigest: "6".repeat(64) },
    result: {
      anchors: [resultAnchor("proposal", 0), resultAnchor("acceptance", 1), resultAnchor("acknowledgment", 2)],
      externalBusinessActionPerformed: false,
      hostSessionKeyCertificateDigest: "7".repeat(64),
      identityPolicy: { erc8004: "required_fresh", chainId: "eip155:11155111", registryAddress: REGISTRY },
      issuedAtMs: "1786337182000",
      outcome: "VERIFIED",
      parties: {
        initiator: {
          sessionKeyAddress: "0x" + "1".repeat(40),
          policyDigest: "c".repeat(64),
          erc8004: registration("9452", "e", "7000"),
        },
        responder: {
          sessionKeyAddress: "0x" + "2".repeat(40),
          policyDigest: "d".repeat(64),
          erc8004: registration("9453", "f", "7001"),
        },
      },
      policyDigests: { initiator: "c".repeat(64), responder: "d".repeat(64) },
      reference: "NS-1847",
      schema: "clockchain.agent-handshake-result/v2",
      sessionDigest: "8".repeat(64),
      sessionId: SESSION,
      statementDigest: "9".repeat(64),
      subjectRun: "stakeholder",
    },
    signer: {
      algorithm: "ed25519",
      keyId: "session-key-1",
      publicKey: "A".repeat(43) + "=",
      signature: "B".repeat(86) + "==",
    },
    ...overrides,
  };
}

// The snapshot's certificate.digest covers the full signed envelope; the
// monitor's certificateDigest covers envelope.result only — the same domain
// as the trusted terminal proof.
function snapshotBoundTo(envelope) {
  return certifiedSnapshot({
    certificate: { digest: agentHandshakeV2ResultDigest(envelope), issuedAtMs: 1786337182000, outcome: "VERIFIED" },
  });
}

function fetchFor({ snapshot, runs = certifiedRuns(), result = resultEnvelope() } = {}) {
  const calls = [];
  const impl = async (url) => {
    calls.push(url);
    if (url.endsWith("/snapshot")) return { ok: true, json: async () => snapshot ?? snapshotBoundTo(result) };
    if (url.endsWith("/result")) return { ok: true, json: async () => result };
    if (url.endsWith("/runs")) return { ok: true, json: async () => runs };
    throw new Error(`unexpected url ${url}`);
  };
  return { calls, impl };
}

test("sessionMonitorEndpoints derives snapshot, result, and runs urls from the template", () => {
  const endpoints = sessionMonitorEndpoints(ENDPOINT);
  assert.equal(endpoints.snapshotFor(SESSION), `http://relay.test:8080/v1/sessions/${SESSION}/snapshot`);
  assert.equal(endpoints.resultFor(SESSION), `http://relay.test:8080/v1/sessions/${SESSION}/result`);
  assert.equal(endpoints.runs, "http://relay.test:8080/v1/runs");
});

test("sessionMonitorEndpoints returns null without the session token", () => {
  assert.equal(sessionMonitorEndpoints("https://example.test/api/handshake/monitor"), null);
  assert.equal(sessionMonitorEndpoints("not a url"), null);
});

test("sessionMonitorEndpoints rejects malformed templates", () => {
  assert.throws(() => sessionMonitorEndpoints("http://relay.test/v1/{sessionId}/snapshot"), /invalid/);
  assert.throws(() => sessionMonitorEndpoints("http://relay.test/v1/sessions/{sessionId}"), /invalid/);
  assert.throws(() => sessionMonitorEndpoints("http://relay.test/v1/sessions/{sessionId}/snapshot?x={sessionId}"), /invalid/);
});

test("certifiedV2Snapshot accepts the exact certified contract and parses strictly", () => {
  const snapshot = certifiedV2Snapshot(certifiedSnapshot(), SESSION);
  assert.equal(snapshot.sessionId, SESSION);
  assert.equal(snapshot.certificate.digest, CERT_DIGEST);
});

test("certifiedV2Snapshot rejects every divergence from the certified contract", () => {
  const base = certifiedSnapshot();
  const cases = [
    { sessionId: OTHER_SESSION },
    { schema: "clockchain.agent-handshake-snapshot/v1" },
    { checker: { stage: "VERIFYING", lastSeenMs: 1786337181000 } },
    { checker: { stage: "FAILED", lastSeenMs: 1786337181000 } },
    { certificate: null },
    { certificate: { digest: CERT_DIGEST, issuedAtMs: 1786337182000, outcome: "REJECTED" } },
    { certificate: { digest: "not-a-digest", issuedAtMs: 1786337182000, outcome: "VERIFIED" } },
    { failure: { reasonCode: "EXPIRED" } },
    { externalBusinessActionPerformed: true },
    { receipts: { proposal: null, acceptance: receipt("acceptance", 1), acknowledgment: receipt("acknowledgment", 2) } },
    { receipts: { proposal: receipt("proposal", 0), acceptance: receipt("acceptance", 1), acknowledgment: null } },
  ];
  for (const overrides of cases) {
    assert.equal(certifiedV2Snapshot({ ...base, ...overrides }, SESSION), null, JSON.stringify(Object.keys(overrides)));
  }
});

test("certifiedV2Snapshot rejects extra and malformed fields", () => {
  const base = certifiedSnapshot();
  assert.equal(certifiedV2Snapshot({ ...base, extra: true }, SESSION), null);
  assert.equal(certifiedV2Snapshot({ ...base, roleAccess: "secret" }, SESSION), null);
  assert.equal(certifiedV2Snapshot({ ...base, certificate: { ...base.certificate, extra: 1 } }, SESSION), null);
  assert.equal(certifiedV2Snapshot(null, SESSION), null);
  assert.equal(certifiedV2Snapshot([], SESSION), null);
  assert.equal(certifiedV2Snapshot("x", SESSION), null);
});

test("certifiedRunRecorded requires a strict matching CERTIFIED/VERIFIED record", () => {
  const snapshot = certifiedV2Snapshot(certifiedSnapshot(), SESSION);
  assert.equal(certifiedRunRecorded(certifiedRuns(), snapshot), true);
});

test("certifiedRunRecorded rejects forged, mismatched, and malformed run bodies", () => {
  const snapshot = certifiedV2Snapshot(certifiedSnapshot(), SESSION);
  const bodies = [
    { ok: false, paymentMoved: false, runs: [certifiedRun()] },
    { ok: true, paymentMoved: true, runs: [certifiedRun()] },
    { ok: true, paymentMoved: false, runs: [] },
    { ok: true, paymentMoved: false, runs: [certifiedRun({ sessionId: OTHER_SESSION })] },
    { ok: true, paymentMoved: false, runs: [certifiedRun({ stage: "VERIFYING" })] },
    { ok: true, paymentMoved: false, runs: [certifiedRun({ outcome: "REJECTED" })] },
    { ok: true, paymentMoved: false, runs: [certifiedRun({ reasonCode: "FAILED" })] },
    { ok: true, paymentMoved: false, runs: [certifiedRun({ anchors: { proposal: "7010", acceptance: "7011", acknowledgment: "9999" } })] },
    { ok: true, paymentMoved: false, runs: [certifiedRun({ anchors: { proposal: "7010", acceptance: "7011" } })] },
    { ok: true, paymentMoved: false, runs: [certifiedRun({ anchors: { proposal: "7010", acceptance: "7011", acknowledgment: "7012", extra: "1" } })] },
    { ok: true, paymentMoved: false, runs: [{ ...certifiedRun(), extra: 1 }] },
    { ok: true, paymentMoved: false, runs: [{ stage: "CERTIFIED", outcome: "VERIFIED", sessionId: SESSION }] },
    { ok: true, paymentMoved: false, runs: [certifiedRun({ startedAtMs: -1 })] },
    { ok: true, paymentMoved: false, runs: [certifiedRun({ startedAtMs: 1.5 })] },
    null,
    [],
    { ok: true, paymentMoved: false },
    { ok: true, paymentMoved: false, runs: "yes" },
  ];
  for (const body of bodies) {
    assert.equal(certifiedRunRecorded(body, snapshot), false, JSON.stringify(body)?.slice(0, 120));
  }
});

test("monitorEvidenceMatches accepts the exact bound session, digest, and terminal chronology", () => {
  const result = { chronology: ["WAITING", "VERIFYING", "CERTIFIED"], sessionId: SESSION, certificateDigest: CERT_DIGEST };
  assert.equal(monitorEvidenceMatches(result, { sessionId: SESSION, certificateDigest: CERT_DIGEST }), true);
});

test("monitorEvidenceMatches rejects forged digest, wrong session, missing digest, and non-terminal chronology", () => {
  const bound = { sessionId: SESSION, certificateDigest: CERT_DIGEST };
  const cases = [
    { chronology: ["CERTIFIED"], sessionId: SESSION, certificateDigest: "f".repeat(64) },
    { chronology: ["CERTIFIED"], sessionId: OTHER_SESSION, certificateDigest: CERT_DIGEST },
    { chronology: ["CERTIFIED"], sessionId: SESSION },
    { chronology: ["CERTIFIED"], sessionId: SESSION, certificateDigest: null },
    { chronology: ["CERTIFIED"], sessionId: SESSION, certificateDigest: "not-a-digest" },
    { chronology: ["WAITING"], sessionId: SESSION, certificateDigest: CERT_DIGEST },
    { chronology: ["CERTIFIED", "VERIFYING"], sessionId: SESSION, certificateDigest: CERT_DIGEST },
    { chronology: [], sessionId: SESSION, certificateDigest: CERT_DIGEST },
    { sessionId: SESSION, certificateDigest: CERT_DIGEST },
    null,
    "x",
  ];
  for (const monitorResult of cases) {
    assert.equal(monitorEvidenceMatches(monitorResult, bound), false, JSON.stringify(monitorResult));
  }
  assert.equal(monitorEvidenceMatches({ chronology: ["CERTIFIED"], sessionId: SESSION, certificateDigest: CERT_DIGEST }, { sessionId: SESSION, certificateDigest: "e".repeat(64) }), false);
});

test("certifiedV2Result accepts the envelope bound to the certified snapshot", () => {
  const envelope = resultEnvelope();
  const snapshot = certifiedV2Snapshot(snapshotBoundTo(envelope), SESSION);
  const result = certifiedV2Result(envelope, snapshot, SESSION);
  assert.equal(result.sessionId, SESSION);
  assert.notEqual(agentHandshakeV2ResultDigest(envelope), digestHex(result));
  assert.equal(digestHex(result), digestHex(envelope.result));
});

test("certifiedV2Result rejects forged results, mismatches, and malformed envelopes", () => {
  const envelope = resultEnvelope();
  const snapshot = certifiedV2Snapshot(snapshotBoundTo(envelope), SESSION);
  const tampered = (mutate) => {
    const copy = JSON.parse(JSON.stringify(envelope));
    mutate(copy);
    return copy;
  };
  const cases = [
    // forged result: tampered outcome
    tampered((e) => { e.result.outcome = "FAILED"; }),
    // forged result: tampered statement digest
    tampered((e) => { e.result.statementDigest = "f".repeat(64); }),
    // forged result: tampered responder address
    tampered((e) => { e.result.parties.responder.sessionKeyAddress = "0x" + "9".repeat(40); }),
    // envelope-snapshot digest mismatch: valid envelope, snapshot bound to another
    resultEnvelope({ signer: { algorithm: "ed25519", keyId: "session-key-2", publicKey: "C".repeat(43) + "=", signature: "D".repeat(86) + "==" } }),
    // result-session mismatch
    tampered((e) => { e.result.sessionId = OTHER_SESSION; }),
    // anchor mismatch: blockHeight diverges from the snapshot receipt
    tampered((e) => { e.result.anchors[0].blockHeight = "9999"; }),
    // anchor mismatch: digest diverges from the snapshot receipt
    tampered((e) => { e.result.anchors[1].digest = "f".repeat(64); }),
    // external action performed
    tampered((e) => { e.result.externalBusinessActionPerformed = true; }),
    // malformed envelope: extra top-level key
    tampered((e) => { e.extra = true; }),
    // malformed envelope: missing signer
    tampered((e) => { delete e.signer; }),
    // malformed result: missing anchors
    tampered((e) => { delete e.result.anchors; }),
    null,
    "x",
    {},
  ];
  for (const candidate of cases) {
    assert.equal(certifiedV2Result(candidate, snapshot, SESSION), null, JSON.stringify(candidate)?.slice(0, 120));
  }
});

test("monitorSession returns CERTIFIED chronology bound to the result-object digest", async () => {
  const envelope = resultEnvelope();
  const { calls, impl } = fetchFor({ result: envelope });
  const monitorResult = await monitorSession({
    endpoint: ENDPOINT,
    sessionId: SESSION,
    fetchImpl: impl,
    sleep: async () => {},
  });
  assert.equal(monitorResult.sessionId, SESSION);
  assert.equal(monitorResult.certificateDigest, digestHex(envelope.result));
  assert.notEqual(monitorResult.certificateDigest, agentHandshakeV2ResultDigest(envelope));
  assert.deepEqual([...monitorResult.chronology], ["CERTIFIED"]);
  assert.equal(calls[0], `http://relay.test:8080/v1/sessions/${SESSION}/snapshot`);
  assert.deepEqual(new Set(calls), new Set([
    `http://relay.test:8080/v1/sessions/${SESSION}/snapshot`,
    `http://relay.test:8080/v1/sessions/${SESSION}/result`,
    "http://relay.test:8080/v1/runs",
  ]));
});

test("monitorSession rejects a forged or unbound result envelope", async () => {
  const envelopes = [
    // forged result: outcome downgraded
    resultEnvelope({ result: { ...resultEnvelope().result, outcome: "FAILED" } }),
    // result-session mismatch
    resultEnvelope({ result: { ...resultEnvelope().result, sessionId: OTHER_SESSION } }),
    // anchor mismatch
    resultEnvelope({ result: { ...resultEnvelope().result, anchors: [resultAnchor("proposal", 9), resultAnchor("acceptance", 1), resultAnchor("acknowledgment", 2)] } }),
    // malformed envelope
    { hello: "world" },
  ];
  for (const result of envelopes) {
    const { impl } = fetchFor({ result });
    await assert.rejects(
      monitorSession({ endpoint: ENDPOINT, sessionId: SESSION, fetchImpl: impl, sleep: async () => {}, timeoutMs: 5, intervalMs: 0 }),
      /invalid/,
    );
  }
  // envelope-snapshot digest mismatch: snapshot bound to a different envelope
  const other = resultEnvelope({ result: { ...resultEnvelope().result, reference: "OTHER" } });
  const { impl } = fetchFor({ snapshot: snapshotBoundTo(other) });
  await assert.rejects(
    monitorSession({ endpoint: ENDPOINT, sessionId: SESSION, fetchImpl: impl, sleep: async () => {}, timeoutMs: 5, intervalMs: 0 }),
    /invalid/,
  );
});

test("monitorSession polls until the session certifies", async () => {
  let pending = true;
  const envelope = resultEnvelope();
  const impl = async (url) => {
    if (url.endsWith("/snapshot")) {
      const snapshot = snapshotBoundTo(envelope);
      if (pending) {
        snapshot.certificate = null;
        snapshot.checker = { stage: "VERIFYING", lastSeenMs: 1786337181000 };
      }
      return { ok: true, json: async () => snapshot };
    }
    if (url.endsWith("/result")) return { ok: true, json: async () => envelope };
    return { ok: true, json: async () => certifiedRuns() };
  };
  const result = await monitorSession({
    endpoint: ENDPOINT,
    sessionId: SESSION,
    fetchImpl: impl,
    sleep: async () => { pending = false; },
  });
  assert.equal(result.sessionId, SESSION);
});

test("monitorSession does not accept a different certified session", async () => {
  const snapshot = snapshotBoundTo(resultEnvelope());
  snapshot.sessionId = OTHER_SESSION;
  const { impl } = fetchFor({ snapshot });
  await assert.rejects(
    monitorSession({ endpoint: ENDPOINT, sessionId: SESSION, fetchImpl: impl, sleep: async () => {}, timeoutMs: 5, intervalMs: 0 }),
    /invalid/,
  );
});

test("monitorSession rejects when no matching run record certifies", async () => {
  for (const runs of [
    { ok: true, paymentMoved: false, runs: [] },
    { ok: true, paymentMoved: false, runs: [certifiedRun({ stage: "VERIFYING", outcome: null })] },
    { ok: true, paymentMoved: false, runs: [certifiedRun({ anchors: { proposal: "1", acceptance: "2", acknowledgment: "3" } })] },
    { ok: true, paymentMoved: true, runs: [certifiedRun()] },
  ]) {
    const { impl } = fetchFor({ runs });
    await assert.rejects(
      monitorSession({ endpoint: ENDPOINT, sessionId: SESSION, fetchImpl: impl, sleep: async () => {}, timeoutMs: 5, intervalMs: 0 }),
      /invalid/,
    );
  }
});

test("monitorSession rejects a non-template endpoint", async () => {
  await assert.rejects(
    monitorSession({ endpoint: "https://example.test/monitor", sessionId: SESSION }),
    /invalid/,
  );
});

test("monitorSession keeps polling past transient fetch failures", async () => {
  let fail = true;
  const envelope = resultEnvelope();
  const impl = async (url) => {
    if (fail) throw new Error("connection reset");
    if (url.endsWith("/snapshot")) return { ok: true, json: async () => snapshotBoundTo(envelope) };
    if (url.endsWith("/result")) return { ok: true, json: async () => envelope };
    return { ok: true, json: async () => certifiedRuns() };
  };
  const result = await monitorSession({
    endpoint: ENDPOINT,
    sessionId: SESSION,
    fetchImpl: impl,
    sleep: async () => { fail = false; },
  });
  assert.equal(result.sessionId, SESSION);
});
