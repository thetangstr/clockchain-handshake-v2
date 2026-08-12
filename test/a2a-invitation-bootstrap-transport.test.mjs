import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, sign, X509Certificate } from "node:crypto";
import https from "node:https";
import test from "node:test";

import { privateKeyToAccount } from "viem/accounts";

import { A2A_AGENT_CARD_SCHEMA, a2aAgentCardDigest, signA2AAgentCard } from "../src/a2a/agent-card.mjs";
import { a2aCanonicalBytes } from "../src/a2a/auth.mjs";
import { createA2ACardBootstrap } from "../src/a2a/card-bootstrap.mjs";
import { createInvitationBootstrapTransport } from "../src/a2a/invitation-bootstrap-transport.mjs";

const RUN_ID = "run-6c0-task1";
const SESSION_ID = "11111111-2222-4333-8444-555555555555";
const OTHER_SESSION_ID = "22222222-3333-4444-8555-666666666666";
const INVITATION = "cc_invitation_live_secret_value_roleAccess_123";
const NOW = 1786337000000;
const INITIATOR_PARTY = privateKeyToAccount(`0x${"1".repeat(64)}`);
const RESPONDER_PARTY = privateKeyToAccount(`0x${"2".repeat(64)}`);
const INITIATOR_CARD_KEY = privateKeyToAccount(`0x${"6".repeat(64)}`);
const RESPONDER_CARD_KEY = privateKeyToAccount(`0x${"7".repeat(64)}`);
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
const TLS_KEY_2 = `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIPhqzVCZvyNp5GyDyMMN2QbAX5mUzOjcBq89IKhof4vuoAoGCCqGSM49
AwEHoUQDQgAEJdlb2J0I/YMTXiSP/exOZinJr53CKSxyBbdukXXJqXXvhUUi794+
Cz5UNdffmk0WCXA2pliXBSBeRVugfoh7JQ==
-----END EC PRIVATE KEY-----`;
const TLS_CERT_2 = `-----BEGIN CERTIFICATE-----
MIIBqzCCAVGgAwIBAgIUbm3B1Wyw4uRMsPXHpeMuqedMIZgwCgYIKoZIzj0EAwIw
KjEoMCYGA1UEAwwfY2xvY2tjaGFpbi1hMmEtYm9vdHN0cmFwLXRlc3QtMjAgFw0y
NjA4MTIwNzMwMTFaGA8yMTI2MDcxOTA3MzAxMVowKjEoMCYGA1UEAwwfY2xvY2tj
aGFpbi1hMmEtYm9vdHN0cmFwLXRlc3QtMjBZMBMGByqGSM49AgEGCCqGSM49AwEH
A0IABCXZW9idCP2DE14kj/3sTmYpya+dwikscgW3bpF1yal174VFIu/ePgs+VDXX
35pNFglwNqZYlwUgXkVboH6IeyWjUzBRMB0GA1UdDgQWBBToetMFwTMB8z01VM6w
NezE6jtwGjAfBgNVHSMEGDAWgBToetMFwTMB8z01VM6wNezE6jtwGjAPBgNVHRMB
Af8EBTADAQH/MAoGCCqGSM49BAMCA0gAMEUCIBzYluLLsW4Yd7WxkSHo+SSWVRmr
IKlnH7f0nOriql5HAiEAsujZrEDN5Gk8H1VOWz56SeEL6lbACzVQqd20zh43MUI=
-----END CERTIFICATE-----`;

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

function tls({ peerPin = sha256(new X509Certificate(TLS_CERT).raw) } = {}) {
  return {
    certificate: TLS_CERT,
    privateKey: TLS_KEY,
    ownCertificateSha256: sha256(new X509Certificate(TLS_CERT).raw),
    peerCertificateSha256: peerPin,
  };
}

function tls2({ peerPin = sha256(new X509Certificate(TLS_CERT).raw) } = {}) {
  return {
    certificate: TLS_CERT_2,
    privateKey: TLS_KEY_2,
    ownCertificateSha256: sha256(new X509Certificate(TLS_CERT_2).raw),
    peerCertificateSha256: peerPin,
  };
}

function signer() {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  return {
    publicKey: publicKey.export({ type: "spki", format: "pem" }),
    signCanonicalBytes(bytes) {
      return sign(null, bytes, privateKey).toString("base64");
    },
  };
}

function runtime(role) {
  return {
    runtimeId: `runtime-${role}`,
    workloadAttestationDigest: role === "initiator" ? "4".repeat(64) : "5".repeat(64),
  };
}

async function pair(overrides = {}) {
  const initiatorSigner = signer();
  const responderSigner = signer();
  const responder = await createInvitationBootstrapTransport({
    allowLoopbackForTests: true,
    bootstrapSigner: responderSigner,
    initialSessionId: null,
    listenHost: "127.0.0.1",
    localRuntime: runtime("responder"),
    nowMs: () => NOW,
    peerBootstrapPublicKey: initiatorSigner.publicKey,
    peerRole: "initiator",
    peerRuntime: runtime("initiator"),
    port: 0,
    role: "responder",
    runId: RUN_ID,
    tls: tls(),
    ...overrides.responder,
  });
  const initiator = await createInvitationBootstrapTransport({
    allowLoopbackForTests: true,
    bootstrapSigner: initiatorSigner,
    initialSessionId: null,
    listenHost: "127.0.0.1",
    localRuntime: runtime("initiator"),
    nowMs: () => NOW,
    peerBootstrapPublicKey: responderSigner.publicKey,
    peerRole: "responder",
    peerRuntime: runtime("responder"),
    peerUrl: responder.publicUrl,
    port: 0,
    role: "initiator",
    runId: RUN_ID,
    tls: tls(),
    ...overrides.initiator,
  });
  responder.setPeerUrl(initiator.publicUrl);
  return { initiator, responder, initiatorSigner, responderSigner };
}

function partyBinding(role) {
  const account = role === "initiator" ? INITIATOR_PARTY : RESPONDER_PARTY;
  return {
    partySignerAddress: account.address.toLowerCase(),
    runtimeId: `runtime-${role}`,
    workloadAttestationDigest: role === "initiator" ? "4".repeat(64) : "5".repeat(64),
    taskId: `task-${role}`,
    endpoint: `https://${role}.task.local:8443`,
  };
}

async function partyCard(role, peerCardDigest = null) {
  const account = role === "initiator" ? INITIATOR_PARTY : RESPONDER_PARTY;
  const cardAccount = role === "initiator" ? INITIATOR_CARD_KEY : RESPONDER_CARD_KEY;
  const binding = partyBinding(role);
  return signA2AAgentCard({
    card: {
      schema: A2A_AGENT_CARD_SCHEMA,
      version: 1,
      sessionId: SESSION_ID,
      role,
      partySignerAddress: binding.partySignerAddress,
      partySignerPublicKey: account.publicKey,
      a2aCardPublicKey: cardAccount.publicKey,
      workloadAttestationDigest: binding.workloadAttestationDigest,
      runtimeId: binding.runtimeId,
      taskId: binding.taskId,
      endpoint: binding.endpoint,
      peerCardDigest,
      issuedAtMs: String(NOW - 1_000),
      expiresAtMs: String(NOW + 60_000),
      nonce: `nonce-network-${role}`,
      jti: `jti-network-${role}`,
      supportedArtifacts: ["invitation", "proposal", "counterproposal", "acceptance"],
    },
    signMessage: (raw) => account.signMessage({ message: { raw } }),
  });
}

function signedRequest({
  body = INVITATION,
  initiatorSigner,
  responder,
  responderSigner,
  overrides = {},
  signatureInputOverrides = {},
}) {
  const unsigned = {
    schema: "clockchain.invitation-bootstrap-envelope/v1",
    version: 1,
    artifactKind: "invitation",
    method: "POST",
    path: "/a2a/v1/bootstrap/invitations",
    runId: RUN_ID,
    sessionId: SESSION_ID,
    senderRole: "initiator",
    receiverRole: "responder",
    senderRuntimeId: "runtime-initiator",
    receiverRuntimeId: "runtime-responder",
    senderWorkloadAttestationDigest: "4".repeat(64),
    receiverWorkloadAttestationDigest: "5".repeat(64),
    senderBootstrapPublicKey: initiatorSigner.publicKey,
    receiverBootstrapPublicKey: responderSigner.publicKey,
    receiverPublicEndpoint: responder.publicUrl,
    receiverCertificateSha256: tls().ownCertificateSha256,
    bodySha256: sha256(body),
    bodyLength: Buffer.byteLength(body),
    issuedAtMs: String(NOW),
    expiresAtMs: String(NOW + 10_000),
    nonce: `nonce-${sha256(`${body}:nonce`)}`,
    jti: `jti-${sha256(`${body}:jti`)}`,
    ...overrides,
  };
  const signatureInput = { ...unsigned, ...signatureInputOverrides };
  return {
    body,
    envelope: {
      ...unsigned,
      signature: {
        algorithm: "ed25519",
        value: initiatorSigner.signCanonicalBytes(a2aCanonicalBytes(signatureInput)),
      },
    },
  };
}

test("invitation bootstrap sends one opaque invitation directly and exposes digest-only evidence", async (t) => {
  const controller = { routed: false, routeRawInvitation() { this.routed = true; } };
  const { initiator, responder } = await pair();
  t.after(() => initiator.close());
  t.after(() => responder.close());

  const sent = await initiator.sendInvitation({ invitation: INVITATION, sessionId: SESSION_ID, expiresAtMs: NOW + 10_000 });
  assert.deepEqual(sent, { invitationDigest: sha256(INVITATION), acknowledged: true });
  const taken = responder.takeInvitation();
  assert.deepEqual(taken, { invitation: INVITATION, invitationDigest: sha256(INVITATION), sessionId: SESSION_ID });
  assert.equal(controller.routed, false);

  for (const evidence of [initiator.publicEvidence(), responder.publicEvidence()]) {
    assert.equal(evidence.schema, "clockchain.invitation-bootstrap-transport-evidence/v1");
    assert.equal(evidence.runId, RUN_ID);
    assert.match(evidence.localCertificateSha256, /^[0-9a-f]{64}$/);
    assert.match(evidence.peerCertificateSha256, /^[0-9a-f]{64}$/);
    assert.equal(evidence.invitations.length, 1);
    assert.equal(evidence.invitations[0].invitationDigest, sha256(INVITATION));
    assert.doesNotMatch(JSON.stringify(evidence), /roleAccess|invitation_live_secret|private reasoning|\/Users\/alice/i);
  }
  assert.throws(() => responder.takeInvitation(), /Invitation bootstrap transport failed safely/);
});

test("the same pinned HTTPS listeners carry the responder-first signed card bootstrap", async (t) => {
  const { initiator: initiatorTransport, responder: responderTransport } = await pair();
  t.after(() => initiatorTransport.close());
  t.after(() => responderTransport.close());
  const initiatorUrl = initiatorTransport.publicUrl;
  const responderUrl = responderTransport.publicUrl;
  await initiatorTransport.sendInvitation({ invitation: INVITATION, sessionId: SESSION_ID, expiresAtMs: NOW + 10_000 });
  responderTransport.takeInvitation();

  const initiator = createA2ACardBootstrap({
    role: "initiator",
    sessionId: SESSION_ID,
    nowMs: () => NOW,
    ownBinding: partyBinding("initiator"),
    peerBinding: partyBinding("responder"),
    transport: initiatorTransport,
  });
  const responder = createA2ACardBootstrap({
    role: "responder",
    sessionId: SESSION_ID,
    nowMs: () => NOW,
    ownBinding: partyBinding("responder"),
    peerBinding: partyBinding("initiator"),
    transport: responderTransport,
  });
  const responderCard = await partyCard("responder");
  await responder.publishResponderCard({ card: responderCard, expiresAtMs: NOW + 10_000 });
  initiator.takeResponderCard();
  const initiatorCard = await partyCard("initiator", a2aAgentCardDigest(responderCard));
  await initiator.publishInitiatorCard({ card: initiatorCard, expiresAtMs: NOW + 10_000 });
  responder.takeInitiatorCard();
  await initiator.verifiedPair();
  await responder.verifiedPair();
  assert.equal(initiatorTransport.publicUrl, initiatorUrl);
  assert.equal(responderTransport.publicUrl, responderUrl);
});

test("invitation bootstrap rejects replay, second invitations, and session rebinding", async (t) => {
  const { initiator, responder, initiatorSigner, responderSigner } = await pair();
  t.after(() => initiator.close());
  t.after(() => responder.close());

  await initiator.sendInvitation({ invitation: INVITATION, sessionId: SESSION_ID, expiresAtMs: NOW + 10_000 });
  assert.equal(responder.takeInvitation().sessionId, SESSION_ID);
  await assert.rejects(
    () => initiator.sendInvitation({ invitation: "second-secret", sessionId: SESSION_ID, expiresAtMs: NOW + 10_000 }),
    /Invitation bootstrap transport failed safely/,
  );
  await assert.rejects(
    () => initiator.sendInvitation({ invitation: "rebind-secret", sessionId: OTHER_SESSION_ID, expiresAtMs: NOW + 10_000 }),
    /Invitation bootstrap transport failed safely/,
  );
  const secondDirect = signedRequest({
    body: "second-direct-secret",
    initiatorSigner,
    responder,
    responderSigner,
  });
  const directResponse = await postJson(responder.publicUrl, secondDirect, tls());
  assert.equal(directResponse.status, 400);
  assert.equal(responder.publicEvidence().invitations.length, 1);
});

test("invitation bootstrap atomically accepts only one concurrent valid request", async (t) => {
  const { initiator, responder, initiatorSigner, responderSigner } = await pair();
  t.after(() => initiator.close());
  t.after(() => responder.close());
  const first = signedRequest({ body: "concurrent-first-secret", initiatorSigner, responder, responderSigner });
  const second = signedRequest({ body: "concurrent-second-secret", initiatorSigner, responder, responderSigner });
  const delayed = await startDelayedPost(responder.publicUrl, first, tls());
  await new Promise((resolve) => setTimeout(resolve, 20));
  const secondResponse = await postJson(responder.publicUrl, second, tls());
  const firstResponse = await delayed.finish();
  const responses = [firstResponse, secondResponse];
  assert.deepEqual(responses.map(({ status }) => status).sort(), [202, 400]);
  const taken = responder.takeInvitation();
  assert.ok([sha256(first.body), sha256(second.body)].includes(taken.invitationDigest));
  assert.equal(responder.publicEvidence().invitations.length, 1);
});

test("invitation bootstrap requires private endpoints, UUID sessions, peer certificate pin, and bounded body/time", async (t) => {
  await assert.rejects(
    () => createInvitationBootstrapTransport({
      allowLoopbackForTests: false,
      bootstrapSigner: signer(),
      initialSessionId: null,
      localRuntime: runtime("initiator"),
      peerBootstrapPublicKey: signer().publicKey,
      peerRole: "responder",
      peerRuntime: runtime("responder"),
      publicEndpoint: "https://127.0.0.1:8443",
      role: "initiator",
      runId: RUN_ID,
      tls: tls(),
    }),
    /Invitation bootstrap transport failed safely/,
  );
  await assert.rejects(
    () => createInvitationBootstrapTransport({
      allowLoopbackForTests: true,
      bootstrapSigner: signer(),
      initialSessionId: "not-a-uuid",
      localRuntime: runtime("initiator"),
      peerBootstrapPublicKey: signer().publicKey,
      peerRole: "responder",
      peerRuntime: runtime("responder"),
      role: "initiator",
      runId: RUN_ID,
      tls: tls(),
    }),
    /Invitation bootstrap transport failed safely/,
  );
  const { initiator, responder } = await pair({
    initiator: { tls: tls({ peerPin: "0".repeat(64) }) },
  });
  t.after(() => initiator.close());
  t.after(() => responder.close());
  await assert.rejects(
    () => initiator.sendInvitation({ invitation: INVITATION, sessionId: SESSION_ID, expiresAtMs: NOW + 10_000 }),
    /Invitation bootstrap transport failed safely/,
  );

  const fresh = await pair({ initiator: { maxBytes: 1024 } });
  t.after(() => fresh.initiator.close());
  t.after(() => fresh.responder.close());
  await assert.rejects(
    () => fresh.initiator.sendInvitation({ invitation: "x".repeat(2048), sessionId: SESSION_ID, expiresAtMs: NOW + 10_000 }),
    /Invitation bootstrap transport failed safely/,
  );
  await assert.rejects(
    () => fresh.initiator.sendInvitation({ invitation: INVITATION, sessionId: SESSION_ID, expiresAtMs: NOW - 1 }),
    /Invitation bootstrap transport failed safely/,
  );
  await assert.rejects(
    () => fresh.initiator.sendInvitation({ invitation: INVITATION, sessionId: "not-a-uuid", expiresAtMs: NOW + 10_000 }),
    /Invitation bootstrap transport failed safely/,
  );
  await assert.rejects(
    () => fresh.initiator.sendInvitation({ invitation: INVITATION, sessionId: SESSION_ID, expiresAtMs: NOW + 180_001 }),
    /Invitation bootstrap transport failed safely/,
  );
});

test("invitation bootstrap works with distinct per-party TLS certificates via pin-only verification", async (t) => {
  const responderTls = tls2({ peerPin: tls().ownCertificateSha256 });
  const initiatorTls = tls({ peerPin: responderTls.ownCertificateSha256 });
  const { initiator, responder } = await pair({
    responder: { tls: responderTls },
    initiator: { tls: initiatorTls },
  });
  t.after(() => initiator.close());
  t.after(() => responder.close());

  await initiator.sendInvitation({ invitation: INVITATION, sessionId: SESSION_ID, expiresAtMs: NOW + 10_000 });
  assert.equal(responder.takeInvitation().invitationDigest, sha256(INVITATION));
});

test("invitation bootstrap authenticates sender key and exact runtime bindings", async (t) => {
  const { initiator, responder, responderSigner } = await pair();
  t.after(() => initiator.close());
  t.after(() => responder.close());
  const rogue = await createInvitationBootstrapTransport({
    allowLoopbackForTests: true,
    bootstrapSigner: signer(),
    initialSessionId: null,
    listenHost: "127.0.0.1",
    localRuntime: runtime("initiator"),
    nowMs: () => NOW,
    peerBootstrapPublicKey: responderSigner.publicKey,
    peerRole: "responder",
    peerRuntime: runtime("responder"),
    peerUrl: responder.publicUrl,
    port: 0,
    role: "initiator",
    runId: RUN_ID,
    tls: tls(),
  });
  t.after(() => rogue.close());
  await assert.rejects(
    () => rogue.sendInvitation({ invitation: INVITATION, sessionId: SESSION_ID, expiresAtMs: NOW + 10_000 }),
    /Invitation bootstrap transport failed safely/,
  );
  assert.equal(responder.publicEvidence().invitations.length, 0);
});

test("invitation bootstrap requires distinct Ed25519 bootstrap identities", async () => {
  const valid = signer();
  const { publicKey: rsaPublicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const rsaPem = rsaPublicKey.export({ type: "spki", format: "pem" });
  for (const overrides of [
    { bootstrapSigner: { publicKey: rsaPem, signCanonicalBytes: valid.signCanonicalBytes } },
    { peerBootstrapPublicKey: rsaPem },
    { peerBootstrapPublicKey: valid.publicKey, bootstrapSigner: valid },
  ]) {
    let created = null;
    let rejected = false;
    try {
      created = await createInvitationBootstrapTransport({
        allowLoopbackForTests: true,
        bootstrapSigner: signer(),
        initialSessionId: null,
        listenHost: "127.0.0.1",
        localRuntime: runtime("initiator"),
        peerBootstrapPublicKey: signer().publicKey,
        peerRole: "responder",
        peerRuntime: runtime("responder"),
        port: 0,
        role: "initiator",
        runId: RUN_ID,
        tls: tls(),
        ...overrides,
      });
    } catch (error) {
      rejected = /Invitation bootstrap transport failed safely/.test(error.message);
    } finally {
      await created?.close();
    }
    assert.equal(rejected, true);
  }
});

test("invitation bootstrap stores no outbound evidence on ambiguous network failure", async (t) => {
  const pin = tls().ownCertificateSha256;
  const server = https.createServer({ key: TLS_KEY, cert: TLS_CERT }, (req, res) => {
    req.resume();
    res.destroy();
  });
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  t.after(() => server.close());
  const address = server.address();
  const localSigner = signer();
  const transport = await createInvitationBootstrapTransport({
    allowLoopbackForTests: true,
    bootstrapSigner: localSigner,
    initialSessionId: null,
    listenHost: "127.0.0.1",
    localRuntime: runtime("initiator"),
    nowMs: () => NOW,
    peerBootstrapPublicKey: signer().publicKey,
    peerRole: "responder",
    peerRuntime: runtime("responder"),
    peerUrl: `https://127.0.0.1:${address.port}`,
    port: 0,
    role: "initiator",
    runId: RUN_ID,
    tls: tls({ peerPin: pin }),
  });
  t.after(() => transport.close());
  await assert.rejects(
    () => transport.sendInvitation({ invitation: INVITATION, sessionId: SESSION_ID, expiresAtMs: NOW + 10_000 }),
    /Invitation bootstrap transport failed safely/,
  );
  assert.equal(transport.publicEvidence().invitations.length, 0);
});

test("invitation bootstrap rejects swapped bindings and malformed signed requests before storing private data", async (t) => {
  const mutations = [
    { method: "GET" },
    { path: "/a2a/v1/raw" },
    { issuedAtMs: String(NOW + 20_000), expiresAtMs: String(NOW + 10_000) },
    { runId: "other-run" },
    { senderRole: "responder" },
    { receiverRole: "initiator" },
    { senderRuntimeId: "runtime-other" },
    { receiverRuntimeId: "runtime-other" },
    { senderWorkloadAttestationDigest: "8".repeat(64) },
    { receiverWorkloadAttestationDigest: "9".repeat(64) },
    { senderBootstrapPublicKey: signer().publicKey },
    { receiverBootstrapPublicKey: signer().publicKey },
    { receiverPublicEndpoint: "https://responder.task.local:8443" },
    { receiverCertificateSha256: "0".repeat(64) },
    { bodySha256: sha256("different") },
    { bodyLength: 1 },
  ];
  for (const mutation of mutations) {
    const { initiator, responder, initiatorSigner, responderSigner } = await pair();
    t.after(() => initiator.close());
    t.after(() => responder.close());
    const response = await postJson(responder.publicUrl, signedRequest({
      body: `tampered-secret-${Object.keys(mutation)[0]}`,
      initiatorSigner,
      responder,
      responderSigner,
      overrides: mutation,
    }), tls());
    assert.equal(response.status, 400);
  }

  const bound = await pair({ responder: { initialSessionId: SESSION_ID } });
  t.after(() => bound.initiator.close());
  t.after(() => bound.responder.close());
  assert.equal((await postJson(bound.responder.publicUrl, signedRequest({
    body: "wrong-session-secret",
    initiatorSigner: bound.initiatorSigner,
    responder: bound.responder,
    responderSigner: bound.responderSigner,
    overrides: { sessionId: OTHER_SESSION_ID },
  }), tls())).status, 400);

  const { initiator, responder, initiatorSigner, responderSigner } = await pair();
  t.after(() => initiator.close());
  t.after(() => responder.close());
  const extra = signedRequest({ body: "extra-secret", initiatorSigner, responder, responderSigner });
  extra.envelope.extra = true;
  assert.equal((await postJson(responder.publicUrl, extra, tls())).status, 400);
  const missing = signedRequest({ body: "missing-secret", initiatorSigner, responder, responderSigner });
  delete missing.envelope.receiverRuntimeId;
  assert.equal((await postJson(responder.publicUrl, missing, tls())).status, 400);
  assert.equal((await postJson(responder.publicUrl, signedRequest({
    body: "wrong-content-type-secret",
    initiatorSigner,
    responder,
    responderSigner,
  }), tls(), { contentType: "text/plain" })).status, 404);
  assert.equal(responder.publicEvidence().invitations.length, 0);
});

async function postJson(url, payload, tlsConfig, { contentType = "application/json" } = {}) {
  const parsed = new URL(`${url}/a2a/v1/bootstrap/invitations`);
  const body = JSON.stringify(payload);
  return new Promise((resolve, reject) => {
    let peerFingerprint = null;
    const request = https.request({
      agent: false,
      hostname: parsed.hostname,
      port: parsed.port,
      path: parsed.pathname,
      method: "POST",
      headers: { "content-type": contentType, "content-length": Buffer.byteLength(body) },
      ca: tlsConfig.certificate,
      rejectUnauthorized: true,
      checkServerIdentity: () => undefined,
    }, (response) => {
      let responseBody = "";
      response.on("data", (chunk) => { responseBody += Buffer.from(chunk).toString("utf8"); });
      response.on("end", () => resolve({ status: response.statusCode, body: responseBody, peerFingerprint }));
    });
    request.on("socket", (socket) => {
      socket.on("secureConnect", () => {
        peerFingerprint = sha256(socket.getPeerCertificate().raw);
        request.end(body);
      });
    });
    request.on("error", reject);
  });
}

async function startDelayedPost(url, payload, tlsConfig) {
  const parsed = new URL(`${url}/a2a/v1/bootstrap/invitations`);
  const body = JSON.stringify(payload);
  let request;
  let resolveResponse;
  let rejectResponse;
  const responsePromise = new Promise((resolve, reject) => {
    resolveResponse = resolve;
    rejectResponse = reject;
  });
  await new Promise((resolve, reject) => {
    request = https.request({
      agent: false,
      hostname: parsed.hostname,
      port: parsed.port,
      path: parsed.pathname,
      method: "POST",
      headers: { "content-type": "application/json", "content-length": Buffer.byteLength(body) },
      ca: tlsConfig.certificate,
      rejectUnauthorized: true,
      checkServerIdentity: () => undefined,
    }, (response) => {
      let responseBody = "";
      response.on("data", (chunk) => { responseBody += Buffer.from(chunk).toString("utf8"); });
      response.on("end", () => resolveResponse({ status: response.statusCode, body: responseBody }));
    });
    request.on("socket", (socket) => {
      socket.on("secureConnect", () => {
        const midpoint = Math.floor(body.length / 2);
        request.write(body.slice(0, midpoint));
        resolve();
      });
    });
    request.on("error", (error) => {
      rejectResponse(error);
      reject(error);
    });
  });
  return {
    async finish() {
      const midpoint = Math.floor(body.length / 2);
      request.end(body.slice(midpoint));
      return responsePromise;
    },
  };
}
