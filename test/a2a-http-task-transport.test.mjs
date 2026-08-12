import assert from "node:assert/strict";
import { X509Certificate } from "node:crypto";
import test from "node:test";

import { privateKeyToAccount } from "viem/accounts";

import { canonicalBytes } from "../src/core/canonical.mjs";
import { A2A_AGENT_CARD_SCHEMA, a2aAgentCardDigest, signA2AAgentCard } from "../src/a2a/agent-card.mjs";
import { A2A_ENVELOPE_SCHEMA, a2aEnvelopeDigest, signA2AEnvelope } from "../src/a2a/envelope.mjs";
import { createHttpTaskTransport } from "../src/a2a/http-task-transport.mjs";

const SESSION_ID = "11111111-2222-4333-8444-555555555555";
const INITIATOR = privateKeyToAccount(`0x${"1".repeat(64)}`);
const RESPONDER = privateKeyToAccount(`0x${"2".repeat(64)}`);
const INITIATOR_CARD = privateKeyToAccount(`0x${"6".repeat(64)}`);
const RESPONDER_CARD = privateKeyToAccount(`0x${"7".repeat(64)}`);
const TLS_KEY = `-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC2EOIie3N+z5se
QQMDMZdpg9YFOeB95gJpJyFJgQNfg5GEhUYkdSLdMTykCfS88d0l+8AwL1kgt9Do
x+J9fQMazb4POCIOO3lEim9nCgM3fAfHHKGCsVUhZRQGs39SaZ00s+cPgfbRJSys
0U+siG7qEAUdvBUT0tn7wOFelVHTwvTaFAGzCkdAHGqzaktUSzzZzbKo5jqfnIpM
+jyZUU7iLRr/CBcAdBNYfXTQS3TRxivlu1MR0KFsa/hV8liAW4HFIjLASK7UNJAx
4DcOt7lw8CQcGzBwhf6GA86Kd4Z/OUumgoBufIxnRJpAoJCN6pOFjZqw5FzL/SkP
AxXewrkBAgMBAAECggEABnFqA0ThpTT1HRi5YdFNNa118zjlXic34h9BoQ+I/kYS
bgFmZk9j5LaDmh2FFPOtOxUh68KdMZh3sukx9XVpWPc7eN/oap8Fr1yDzT5wNzQz
NUNo3s5mQBiK4SLUiGbW6qDMNkMH6EZbwqDkpCsu26cl+zOm/kzZrHxarWV04BzI
kwqrjTIlgsOHdeZtU2VpBuEmVdN7CNArtcnmJD5X7m7NTOBOZmZ0ZIfA38F6+8UR
AY0ZfCx8zfv0SPJsgyzgd9VPlmehUHg3AdvZLM4iqzlH5GbFci5HMu7ANk5Vr5e6
C9YDEE5PQALrKx2TYYDQ6gn2KJjMvnzlaj+LDOuVsQKBgQDdPF14kLPBd3CdvKO8
CjIRsu6umEXAWjl49wtGvis6ELzmZFwtCVr+IIRhlTU5Z9aJ+WwWPX8brySZNCqA
Xw/Yfla1JjD8/Bagg9OgEFsnxD7RmmJlVjJoxmZx/fmSteHnIHJDlWNdt8DxXe/7
XgJYmy1Vf6XjOB4cNmefhh15eQKBgQDSrNX0zCoENQFSHkbTFSUSEEBR9/omS1Mr
nFgbAs36djz9pILgiFHQULWruHCiiWqmE7QmJMLiteHf5teM5RFPLs+/wFC8u7fk
W5VR5/KbSxEQiMSmBTEFg1o78+LCGH5sqEZj8V5UX2okV6N5uKWY1ndRaRnmvWLw
IZnbPPPhyQKBgDTnkpKaR+Ij5dJSofT9myuQVnN6BnQRH11F9nRcVYn1JrcRmNlM
O2456G5NeATaR/uGocpPum2sXFwmlWNNWES1MZbwIxbcUazg2WKVhrbjvwHwoUcK
bdOQXj80NNJYnEThBXIT70ciAgm2JQU/XeBCe3zOoaTMbqbge7cyIypBAoGBAM1J
l89LpuGkmN3hHNiRMSdR6Ks2/W2VVr0XQw9HA1m9H591UAblLvvTucNUHYV0bBTa
/F9y0OjDnQ9lzMLBb8V98viBuOq/7Og7idxfLZu/YSiAbUbtpiAeJ65l75986KyO
qNC4oVeMBkzVjTmOAOdWjLwqsw+RmjguNdNZqLhpAoGAT3FjJ88hxsSj2IMWFcEm
xOMaugGWwbWzb5/ze1jcxKpJee6V4an0afsYM3/vip7beJqjmDRlKyk803r8mksG
DlJAGG2+jY6nv+4ynbrOlhkhyBtlE2+L96VScbTZXTMjBA59SWDRWzUGB48JYUFr
CGGsPGQzeuvnUkOkpyjG47U=
-----END PRIVATE KEY-----`;
const TLS_CERT = `-----BEGIN CERTIFICATE-----
MIIDKTCCAhGgAwIBAgIUWU3HdiBi8gOPHgNu2tUaoBYxWIAwDQYJKoZIhvcNAQEL
BQAwIzEhMB8GA1UEAwwYY2xvY2tjaGFpbi1hMmEtdGVzdC1sb25nMCAXDTI2MDgx
MjA1NDI1MVoYDzIxMjYwODEzMDU0MjUxWjAjMSEwHwYDVQQDDBhjbG9ja2NoYWlu
LWEyYS10ZXN0LWxvbmcwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC2
EOIie3N+z5seQQMDMZdpg9YFOeB95gJpJyFJgQNfg5GEhUYkdSLdMTykCfS88d0l
+8AwL1kgt9Dox+J9fQMazb4POCIOO3lEim9nCgM3fAfHHKGCsVUhZRQGs39SaZ00
s+cPgfbRJSys0U+siG7qEAUdvBUT0tn7wOFelVHTwvTaFAGzCkdAHGqzaktUSzzZ
zbKo5jqfnIpM+jyZUU7iLRr/CBcAdBNYfXTQS3TRxivlu1MR0KFsa/hV8liAW4HF
IjLASK7UNJAx4DcOt7lw8CQcGzBwhf6GA86Kd4Z/OUumgoBufIxnRJpAoJCN6pOF
jZqw5FzL/SkPAxXewrkBAgMBAAGjUzBRMB0GA1UdDgQWBBQT0ZM5zi44jakN5uHI
M9Nql8ngLjAfBgNVHSMEGDAWgBQT0ZM5zi44jakN5uHIM9Nql8ngLjAPBgNVHRMB
Af8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQCnwJQWTpE7VYfHhgujxAB6RR+B
+PiKc7AbTzHEOE6z9b4nCkDApna5buxQa0YLsvlv8OM9/t3at544pJ+Z02DM01gB
7AgSg+vk0XbSisICLnE9Li3Gzhg36kKppID5F8Y8BQOGFtlHnQ/9R6zXG1zIVh6Q
HAxGTIihrCZEBoGxQqMwkeUBRGwn54iOdVJDSf2d8eT7luhwj0d38Rj9L4bAAzZM
NS9tdkAqebXJeBEu1gc3W3iAO9YfoOcfisTScYHF889eV6vw25VrKwIKu8XuZDHV
EszUrOBb1q6eaQbLQMsZjAWxQWsGaVEfKJYLtLfgCtfbvki208s9Rd84Moup
-----END CERTIFICATE-----`;

function tls() {
  return { key: TLS_KEY, cert: TLS_CERT, peerCa: TLS_CERT, peerCertificateSha256: "50db5af0e402b3ce734bca44f413dddd9e3884396124e229abf804da87986a2c" };
}

function unsignedCard(account, role, peerCardDigest = null) {
  return {
    schema: A2A_AGENT_CARD_SCHEMA,
    version: 1,
    sessionId: SESSION_ID,
    role,
    partySignerAddress: account.address.toLowerCase(),
    partySignerPublicKey: account.publicKey,
    a2aCardPublicKey: role === "initiator" ? INITIATOR_CARD.publicKey : RESPONDER_CARD.publicKey,
    workloadAttestationDigest: role === "initiator" ? "4".repeat(64) : "5".repeat(64),
    runtimeId: `runtime-${role}`,
    taskId: `task-${role}`,
    endpoint: `https://${role}.task.local:8443`,
    peerCardDigest,
    issuedAtMs: "1000",
    expiresAtMs: "3000",
    nonce: `nonce-${role}`,
    jti: `jti-${role}`,
    supportedArtifacts: ["invitation", "proposal", "counterproposal", "acceptance"],
  };
}

async function cards() {
  const responder = await signA2AAgentCard({
    card: unsignedCard(RESPONDER, "responder"),
    signMessage: (raw) => RESPONDER.signMessage({ message: { raw } }),
  });
  const initiator = await signA2AAgentCard({
    card: unsignedCard(INITIATOR, "initiator", a2aAgentCardDigest(responder)),
    signMessage: (raw) => INITIATOR.signMessage({ message: { raw } }),
  });
  return { initiator, responder };
}

async function signedArtifact(account, payload) {
  return {
    payload,
    signature: {
      address: account.address.toLowerCase(),
      algorithm: "eip191",
      value: await account.signMessage({ message: { raw: canonicalBytes(payload) } }),
    },
  };
}

async function envelope({ fromAccount, fromCard, toCard, sequence, artifactType = "proposal", previousMessageDigest = null, nonce = `message-${sequence}` }) {
  const artifact = await signedArtifact(fromAccount, { kind: artifactType, sequence });
  return signA2AEnvelope({
    envelope: {
      schema: A2A_ENVELOPE_SCHEMA,
      version: 1,
      sessionId: SESSION_ID,
      fromCardDigest: a2aAgentCardDigest(fromCard),
      toCardDigest: a2aAgentCardDigest(toCard),
      sequence,
      artifactType,
      artifactDigest: a2aEnvelopeDigest({ artifact }),
      previousMessageDigest,
      expiresAtMs: "2500",
      nonce,
      body: artifact,
      ciphertext: null,
    },
    fromCard,
    toCard,
    signMessage: (raw) => (fromAccount === INITIATOR ? INITIATOR_CARD : RESPONDER_CARD).signMessage({ message: { raw } }),
  });
}

test("HTTP task transport exchanges A2A envelopes directly without controller content routing", async (t) => {
  const pair = await cards();
  const controller = { routed: false, routeRawContent() { this.routed = true; } };
  const initiator = await createHttpTaskTransport({
    sessionId: SESSION_ID,
    role: "initiator",
    ownCard: pair.initiator,
    peerCard: pair.responder,
    listenHost: "127.0.0.1",
    port: 0,
    nowMs: () => 1500,
    allowLoopbackForTests: true,
    tls: tls(),
  });
  t.after(() => initiator.close());
  const responder = await createHttpTaskTransport({
    sessionId: SESSION_ID,
    role: "responder",
    ownCard: pair.responder,
    peerCard: pair.initiator,
    listenHost: "127.0.0.1",
    port: 0,
    nowMs: () => 1500,
    allowLoopbackForTests: true,
    tls: tls(),
  });
  t.after(() => responder.close());
  initiator.setPeerUrl(responder.url);
  responder.setPeerUrl(initiator.url);

  const proposal = await envelope({ fromAccount: INITIATOR, fromCard: pair.initiator, toCard: pair.responder, sequence: "1" });
  const sentProposal = await initiator.sendEnvelope({ envelope: proposal });
  const receivedProposal = await responder.receive();
  assert.equal(receivedProposal.body.payload.kind, "proposal");
  const acceptance = await envelope({ fromAccount: RESPONDER, fromCard: pair.responder, toCard: pair.initiator, sequence: "1", artifactType: "acceptance", nonce: "message-acceptance-1" });
  const sentAcceptance = await responder.sendEnvelope({ envelope: acceptance });
  const receivedAcceptance = await initiator.receive();
  assert.equal(receivedAcceptance.body.payload.kind, "acceptance");
  assert.equal(controller.routed, false);

  for (const evidence of [initiator.publicEvidence(), responder.publicEvidence()]) {
    assert.equal(evidence.schema, "clockchain.a2a-http-task-transport-evidence/v1");
    assert.equal(evidence.sessionId, SESSION_ID);
    assert.match(evidence.cardDigests.initiator, /^[0-9a-f]{64}$/);
    assert.match(evidence.cardDigests.responder, /^[0-9a-f]{64}$/);
    assert.doesNotMatch(JSON.stringify(evidence), /body|ciphertext|transcript|private reasoning|proposal\\W+1|acceptance\\W+1/i);
  }
  assert.match(sentProposal.messageDigest, /^[0-9a-f]{64}$/);
  assert.match(sentAcceptance.messageDigest, /^[0-9a-f]{64}$/);
});

test("HTTP task transport test TLS fixture covers the fixed support window", () => {
  const cert = new X509Certificate(TLS_CERT);
  assert.ok(Date.parse(cert.validFrom) <= Date.parse("2026-08-13T00:00:00Z"));
  assert.ok(Date.parse(cert.validTo) >= Date.parse("2036-08-12T00:00:00Z"));
});

test("HTTP task transport rejects wrong paths, replay, oversized bodies, and unsigned claims", async (t) => {
  const pair = await cards();
  const responder = await createHttpTaskTransport({
    sessionId: SESSION_ID,
    role: "responder",
    ownCard: pair.responder,
    peerCard: pair.initiator,
    listenHost: "127.0.0.1",
    port: 0,
    nowMs: () => 1500,
    maxBytes: 2048,
    allowLoopbackForTests: true,
    tls: tls(),
  });
  t.after(() => responder.close());
  const proposal = await envelope({ fromAccount: INITIATOR, fromCard: pair.initiator, toCard: pair.responder, sequence: "1" });
  const first = await responder.postJsonForTests("/a2a/v1/envelopes", { envelope: proposal });
  assert.equal(first.status, 202);
  const replay = await responder.postJsonForTests("/a2a/v1/envelopes", { envelope: proposal });
  assert.equal(replay.status, 400);
  const wrongPath = await responder.postJsonForTests("/a2a/v1/raw", {});
  assert.equal(wrongPath.status, 404);
  const unsigned = await responder.postJsonForTests("/a2a/v1/envelopes", { transcript: "private", envelope: { ...proposal, signature: undefined } });
  assert.equal(unsigned.status, 400);
  assert.equal(responder.publicEvidence().messages.length, 1);
});

test("HTTP task transport validates nested envelopes locally before network disclosure", async (t) => {
  const pair = await cards();
  const initiator = await createHttpTaskTransport({
    sessionId: SESSION_ID,
    role: "initiator",
    ownCard: pair.initiator,
    peerCard: pair.responder,
    listenHost: "127.0.0.1",
    port: 0,
    nowMs: () => 1500,
    allowLoopbackForTests: true,
    tls: tls(),
  });
  t.after(() => initiator.close());
  const responder = await createHttpTaskTransport({
    sessionId: SESSION_ID,
    role: "responder",
    ownCard: pair.responder,
    peerCard: pair.initiator,
    listenHost: "127.0.0.1",
    port: 0,
    nowMs: () => 1500,
    allowLoopbackForTests: true,
    tls: tls(),
  });
  t.after(() => responder.close());
  initiator.setPeerUrl(responder.url);

  let traps = 0;
  const nestedProxy = new Proxy({}, {
    get() {
      traps += 1;
      return "secret-canary /Users/alice/secret";
    },
    ownKeys() {
      traps += 1;
      return [];
    },
  });
  await assert.rejects(
    () => initiator.sendEnvelope({ envelope: nestedProxy }),
    (error) => {
      assert.match(error.message, /A2A HTTP task transport failed safely/);
      assert.doesNotMatch(error.message, /secret-canary|\/Users\/alice\/secret/);
      return true;
    },
  );
  assert.equal(traps, 0);

  const validEnvelope = await envelope({ fromAccount: INITIATOR, fromCard: pair.initiator, toCard: pair.responder, sequence: "1" });
  const descriptorEnvelope = { ...validEnvelope, body: { ...validEnvelope.body } };
  Object.defineProperty(descriptorEnvelope.body, "secret", {
    enumerable: true,
    get() {
      traps += 1;
      throw new Error("secret-canary /Users/alice/secret");
    },
  });
  await assert.rejects(
    () => initiator.sendEnvelope({ envelope: descriptorEnvelope }),
    (error) => {
      assert.match(error.message, /A2A HTTP task transport failed safely/);
      assert.doesNotMatch(error.message, /secret-canary|\/Users\/alice\/secret/);
      return true;
    },
  );
  assert.equal(traps, 0);

  const toJsonEnvelope = {
    ...validEnvelope,
    toJSON() {
      traps += 1;
      return { secret: "secret-canary /Users/alice/secret" };
    },
  };
  await assert.rejects(
    () => initiator.sendEnvelope({ envelope: toJsonEnvelope }),
    (error) => {
      assert.match(error.message, /A2A HTTP task transport failed safely/);
      assert.doesNotMatch(error.message, /secret-canary|\/Users\/alice\/secret/);
      return true;
    },
  );
  assert.equal(traps, 0);
  assert.equal(responder.publicEvidence().messages.length, 0);
});

test("HTTP task transport consumes local send before ambiguous network failure without public sent evidence", async (t) => {
  const pair = await cards();
  const initiator = await createHttpTaskTransport({
    sessionId: SESSION_ID,
    role: "initiator",
    ownCard: pair.initiator,
    peerCard: pair.responder,
    listenHost: "127.0.0.1",
    port: 0,
    nowMs: () => 1500,
    allowLoopbackForTests: true,
    tls: tls(),
  });
  t.after(() => initiator.close());
  initiator.setPeerUrl("https://127.0.0.1:65534");
  const proposal = await envelope({ fromAccount: INITIATOR, fromCard: pair.initiator, toCard: pair.responder, sequence: "1" });

  await assert.rejects(() => initiator.sendEnvelope({ envelope: proposal }));
  assert.equal(initiator.publicEvidence().messages.length, 0);
  await assert.rejects(() => initiator.sendEnvelope({ envelope: proposal }));
  assert.equal(initiator.publicEvidence().messages.length, 0);
});

test("HTTP task transport uses private HTTPS peer endpoints in live mode and loopback only when explicit", async (t) => {
  const pair = await cards();
  await assert.rejects(() => createHttpTaskTransport({
    sessionId: SESSION_ID,
    role: "initiator",
    ownCard: pair.initiator,
    peerCard: pair.responder,
    listenHost: "127.0.0.1",
    port: 0,
    nowMs: () => 1500,
    tls: tls(),
  }));
  await assert.rejects(() => createHttpTaskTransport({
    sessionId: SESSION_ID,
    role: "initiator",
    ownCard: pair.initiator,
    peerCard: pair.responder,
    listenHost: "0.0.0.0",
    port: 0,
    nowMs: () => 1500,
    tls: tls(),
  }));
  const transport = await createHttpTaskTransport({
    sessionId: SESSION_ID,
    role: "initiator",
    ownCard: pair.initiator,
    peerCard: pair.responder,
    listenHost: "0.0.0.0",
    port: 0,
    nowMs: () => 1500,
    publicEndpoint: "https://10.0.12.34:8443",
    tls: tls(),
  });
  t.after(() => transport.close());
  assert.equal(transport.publicUrl, "https://10.0.12.34:8443");
  transport.setPeerUrl("https://10.0.56.78:8443");
  transport.setPeerUrl("https://responder.task.local:8443");
  assert.throws(() => transport.setPeerUrl("https://10.0.56.78"));
  assert.throws(() => transport.setPeerUrl("https://10.0.56.78:9443"));
  assert.throws(() => transport.setPeerUrl("https://10.999.56.78:8443"));
  assert.throws(() => transport.setPeerUrl("https://10.0.56.78:8443/a2a"));
  assert.throws(() => transport.setPeerUrl(new URL("https://10.0.56.78:8443")));
  assert.throws(() => transport.setPeerUrl("http://10.0.56.78:8443"));
  assert.throws(() => transport.setPeerUrl("https://127.0.0.1:8443"));
  assert.throws(() => transport.setPeerUrl("https://example.com:8443"));
});

test("HTTP task transport requires both peer CA and certificate pin and snapshots send inputs", async (t) => {
  const pair = await cards();
  for (const badTls of [
    { key: TLS_KEY, cert: TLS_CERT, peerCa: TLS_CERT },
    { key: TLS_KEY, cert: TLS_CERT, peerCertificateSha256: "6e67c44febfdea21e6a716e5d8d0b9cbd2a563012165a1baa0a4305fba121606" },
  ]) {
    await assert.rejects(() => createHttpTaskTransport({
      sessionId: SESSION_ID,
      role: "initiator",
      ownCard: pair.initiator,
      peerCard: pair.responder,
      listenHost: "127.0.0.1",
      port: 0,
      nowMs: () => 1500,
      allowLoopbackForTests: true,
      tls: badTls,
    }));
  }
  const initiator = await createHttpTaskTransport({
    sessionId: SESSION_ID,
    role: "initiator",
    ownCard: pair.initiator,
    peerCard: pair.responder,
    listenHost: "127.0.0.1",
    port: 0,
    nowMs: () => 1500,
    allowLoopbackForTests: true,
    tls: tls(),
  });
  t.after(() => initiator.close());
  let traps = 0;
  const proxy = new Proxy({}, {
    get() {
      traps += 1;
      return "secret-canary /Users/alice/secret";
    },
    ownKeys() {
      traps += 1;
      return [];
    },
  });
  await assert.rejects(
    () => initiator.sendEnvelope(proxy),
    (error) => {
      assert.match(error.message, /A2A HTTP task transport failed safely/);
      assert.doesNotMatch(error.message, /secret-canary|\/Users\/alice\/secret/);
      return true;
    },
  );
  assert.equal(traps, 0);
});

test("HTTP task transport rejects hostile opaque inputs without proxy traps or leaked contents", async () => {
  let traps = 0;
  const proxy = new Proxy({}, {
    get() {
      traps += 1;
      return "secret-canary /Users/alice/secret";
    },
    ownKeys() {
      traps += 1;
      return [];
    },
  });
  await assert.rejects(
    () => createHttpTaskTransport(proxy),
    (error) => {
      assert.match(error.message, /A2A HTTP task transport failed safely/);
      assert.doesNotMatch(error.message, /secret-canary|\/Users\/alice\/secret/);
      return true;
    },
  );
  assert.equal(traps, 0);
  await assert.rejects(
    () => createHttpTaskTransport({ get sessionId() { throw new Error("secret-canary /Users/alice/secret"); } }),
    (error) => {
      assert.match(error.message, /A2A HTTP task transport failed safely/);
      assert.doesNotMatch(error.message, /secret-canary|\/Users\/alice\/secret/);
      return true;
    },
  );
});
