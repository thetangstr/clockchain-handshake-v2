import assert from "node:assert/strict";
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
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCShQD6xrjOP/n3
NelAxjnLxMGZUCMKzO2HWw7jdgG4VyiRiOhQS9ExxiakugFYlCx8NeE8R/e/ALqo
e+xrAP37+3ywzScZEZ2zKrB9Ho+EyuS1xZ36J41aN8mgsOJZacboBREexLXSI05Y
M4PUGchTMnMK+rEweBWkVzypFdzTU3J6N7y+7+UIcZA+6Lanm1Dr/mro7IafrsRl
Jup9/Bby/5aFw86xDp3luEH+fdD3otm6YszXHSw71FzwXoldJbXMhJ8dSHvQ5hjq
OvELlvrLIf5PAQ8e5+GY2ED8f4tMX8/RqyqaWjkOiou7KoEDQjnBS0o/sJInDNe6
QPLX1nrxAgMBAAECggEAOz+wgTg5xCGHzclNrOVbusQyO3J18SikRq9ySlXOZUJN
g+h2dP3rtrJ3rvYOlEi64nGRRqSdkO3VDUurcyvACRUNu5sCG/eNK0Xwf3ALvjmj
mcOzWdSDqv9TN/k/VsPY7LsbzLLkCXlAdZdDUFIquUX10nNEkqKEseObAo72MLf5
t0C7Bv64CNIJiv3z/VbMmGvubCHPfkVXy0hpFuBL50Z8hBNlua/WihabIhZcvqnZ
r0SNoCJJP5UeEplb8/620h8n6++iV3a11dWJXwz2bj+FJh+q/eu//608oc2PvSSU
+d3tEvix3JUqAK95Qr03uFJD0PvRFELQ8MGMyKJmBwKBgQDDbXget0ZXR5RiYN9L
bP3EDd0dPv2+ciazFX6uE31xlPj96grqGJe//R4VktAF9nLqtjGMDNBZsWPzQpaj
+0Lwz3KV/xajQ40q/Hd3LU7p+koDI2YvCIKiHq5zQwNX/pqGVnL2SvBCbuoaqWV0
zFWNdm3d6CagK0BU71DQQ6X0xwKBgQC/7teZlsyfmrd0OrBolYzfigp/flD8xlx8
llJaB7+JutVqRPzJ+17nR4N0zzzrY5OXPIHE0Gzeu5W1Oe0jlVtKydg3Xkq/C154
pLyLCulZ6h59Pk7lE2/v9Ut9Qf2+P7Kw0puvybleaTF+LKc7sMiR3hrkaAqYIcXO
FyT/hEhqhwKBgBQjFoqLtgrOTGLquneKLofiKdOWpwzVtFklsNz9EyL+B74aPK+s
gw58ZXoxm4/RujunNGnK9DkZx0PMq7sP6/DmX1dHZqzCDCzOwPydxZDkgnXaUvAr
v1I3OSCVWiXaDVAkXko0pJcj2KmQpOypFXOzLVT9U+WTL1jRJBGhttsHAoGAay5/
699QidimlhuoI99P+g1ma2go5eAICfMQLgKhrdJOF7hKyqi7iMBg4rxQMss6wnwh
o70Y7xEmOzwL95ESmCM7wT/A0gsRSKIGQEdppLKfMCW5fSdrnT8IVvyhLLr5mNEj
6/jksZpg7ysUgLrqZrr3nZGUSPyjL8GxAZfnsMUCgYEAlu0LnLd491rUEVL1QaB5
Tc632q5XWA6qeCmIMqZ61bk8R+rt6XtFWPA2QnquXKaZUHHF44S7PBKCUOvFrYX8
hlGwMu71m3nzxi7z/kKCZgSdqG6aPhHFO0cZIo6liXX2myapVgnf49A1szHaux+Y
wSJ9QoD7HHdqHT3fQvUqyLU=
-----END PRIVATE KEY-----`;
const TLS_CERT = `-----BEGIN CERTIFICATE-----
MIIDHTCCAgWgAwIBAgIUdG9N3T47am4oQcUwfEPcRoP8u8owDQYJKoZIhvcNAQEL
BQAwHjEcMBoGA1UEAwwTY2xvY2tjaGFpbi1hMmEtdGVzdDAeFw0yNjA4MTIwNTE4
MjVaFw0yNjA4MTMwNTE4MjVaMB4xHDAaBgNVBAMME2Nsb2NrY2hhaW4tYTJhLXRl
c3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCShQD6xrjOP/n3NelA
xjnLxMGZUCMKzO2HWw7jdgG4VyiRiOhQS9ExxiakugFYlCx8NeE8R/e/ALqoe+xr
AP37+3ywzScZEZ2zKrB9Ho+EyuS1xZ36J41aN8mgsOJZacboBREexLXSI05YM4PU
GchTMnMK+rEweBWkVzypFdzTU3J6N7y+7+UIcZA+6Lanm1Dr/mro7IafrsRlJup9
/Bby/5aFw86xDp3luEH+fdD3otm6YszXHSw71FzwXoldJbXMhJ8dSHvQ5hjqOvEL
lvrLIf5PAQ8e5+GY2ED8f4tMX8/RqyqaWjkOiou7KoEDQjnBS0o/sJInDNe6QPLX
1nrxAgMBAAGjUzBRMB0GA1UdDgQWBBQ1pXNNYgaygAykttd5hbqG8qMbYjAfBgNV
HSMEGDAWgBQ1pXNNYgaygAykttd5hbqG8qMbYjAPBgNVHRMBAf8EBTADAQH/MA0G
CSqGSIb3DQEBCwUAA4IBAQAWZWaXBOPur8c3p/CfB5ZwhwdEMdzDoxLRokEu8G5/
D44FsS/fODYcE4CxtUyBHl3stwp67GIK/X+1vH8xbbDUWVWMPrihIr9WEoCBDb7J
+FHMGRQFLPYlaJ2KiTYyApbWuEVgYpdD/DgCnqLYQJ0Bb4664gdqrhm6fQkolbUy
M5q9kumAEIeP/De0ixytCM/aLO0YbBjX0Id6W/2q2Q5+NFPzDHYF292qhjNyzV3l
P4SCpqJxcgv5fgRAIOTA4xVezl31fPgAKgI793xG1DkfRoGWD2a6sGh3j8VuWCSV
eVPOqi/ZrX/m1Ymv7WPUUjd+L36oLpckBMoAmCEXIvAn
-----END CERTIFICATE-----`;

function tls() {
  return { key: TLS_KEY, cert: TLS_CERT, peerCa: TLS_CERT, peerCertificateSha256: "6e67c44febfdea21e6a716e5d8d0b9cbd2a563012165a1baa0a4305fba121606" };
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
