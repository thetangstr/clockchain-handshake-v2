// The closing certificate. RESULT_SCHEMA existed in constants.mjs with no
// emitter, and the requestor never received the verdict at all -- these tests
// pin the emitter that closes both gaps.
//
// The properties that matter: the certificate carries the verifier's words
// verbatim; any single-character tamper kills the signature; and a certificate
// signed by a key other than the session's operator key is refused even though
// its own signature checks out -- a valid-looking document about a session the
// signer had no authority over is the realistic forgery, not a broken one.
import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import test from "node:test";

import {
  ResultError,
  buildSignedResult,
  validateResultEnvelope,
  verifyResultEnvelope,
} from "../src/core/result.mjs";
import { RESULT_SCHEMA } from "../src/core/constants.mjs";

function operatorKey() {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  return {
    privateKeyPem: privateKey.export({ format: "pem", type: "pkcs8" }),
    publicKeyRaw: publicKey
      .export({ format: "der", type: "spki" })
      .subarray(-32)
      .toString("base64"),
  };
}

const VERDICT = Object.freeze({
  outcome: "AUTHORIZED",
  paymentMoved: false,
  transitions: [
    { blockHeight: "2732166", blockTimeRaw: "2026-08-04T01:15:57.916Z", digest: "a".repeat(64), kind: "proposal", ledgerId: "11111111-1111-4111-8111-111111111111" },
    { blockHeight: "2732187", blockTimeRaw: "2026-08-04T01:16:19.233Z", digest: "b".repeat(64), kind: "acceptance", ledgerId: "22222222-2222-4222-8222-222222222222" },
    { blockHeight: "2732209", blockTimeRaw: "2026-08-04T01:16:41.735Z", digest: "c".repeat(64), kind: "acknowledgment", ledgerId: "33333333-3333-4333-8333-333333333333" },
  ],
});

const PARTIES = Object.freeze({
  payer: { address: "0x" + "1".repeat(40), agentId: "9400", reference: "eip155:11155111:0x8004a818bfb912233c491871b3d84c89a494bd9e:9400" },
  payee: { address: "0x" + "2".repeat(40), agentId: "9401", reference: "eip155:11155111:0x8004a818bfb912233c491871b3d84c89a494bd9e:9401" },
});

function build(overrides = {}) {
  const key = overrides.key ?? operatorKey();
  return {
    key,
    envelope: buildSignedResult({
      issuedAtMs: "1785802329000",
      keyId: "handshake-host",
      parties: PARTIES,
      privateKeyPem: key.privateKeyPem,
      sessionDigest: "d".repeat(64),
      sessionId: "00000000-0000-4000-8000-000000000000",
      verdict: overrides.verdict ?? VERDICT,
    }),
  };
}

test("build -> validate -> verify roundtrip, and the words are the verifier's verbatim", () => {
  const { key, envelope } = build();
  assert.equal(validateResultEnvelope(envelope), true);
  const result = verifyResultEnvelope(envelope, { expectedPublicKey: key.publicKeyRaw });
  assert.equal(result.outcome, "AUTHORIZED");
  assert.equal(result.paymentMoved, false);
  assert.equal(result.schema, RESULT_SCHEMA);
  assert.deepEqual(
    result.anchors.map((a) => a.blockHeight),
    ["2732166", "2732187", "2732209"],
  );
  assert.equal(result.parties.payee.agentId, "9401");
});

test("any tamper after signing is caught", () => {
  const { key, envelope } = build();
  const cases = [
    (e) => ({ ...e, result: { ...e.result, outcome: "REFUSED" } }),
    (e) => ({ ...e, result: { ...e.result, issuedAtMs: "1785802329001" } }),
    (e) => ({
      ...e,
      result: {
        ...e.result,
        anchors: [
          { ...e.result.anchors[0], blockHeight: "2732167" },
          e.result.anchors[1],
          e.result.anchors[2],
        ],
      },
    }),
    (e) => ({
      ...e,
      result: {
        ...e.result,
        parties: { ...e.result.parties, payee: { ...e.result.parties.payee, agentId: "9999" } },
      },
    }),
  ];
  for (const mutate of cases) {
    assert.throws(
      () => verifyResultEnvelope(mutate(envelope), { expectedPublicKey: key.publicKeyRaw }),
      ResultError,
    );
  }
});

test("a certificate from the wrong key is refused even though its signature is internally valid", () => {
  const sessionKey = operatorKey();
  const strangerKey = operatorKey();
  const { envelope } = build({ key: strangerKey });
  // Internally consistent…
  assert.equal(
    verifyResultEnvelope(envelope).outcome,
    "AUTHORIZED",
    "the stranger's signature over its own document does verify",
  );
  // …but not from the key this session's descriptor named.
  assert.throws(
    () => verifyResultEnvelope(envelope, { expectedPublicKey: sessionKey.publicKeyRaw }),
    /not the session's operator key/,
  );
});

test("paymentMoved can never be true in a certificate", () => {
  const { key, envelope } = build();
  const flipped = { ...envelope, result: { ...envelope.result, paymentMoved: true } };
  assert.throws(() => validateResultEnvelope(flipped), /paymentMoved must be false/);
  assert.throws(() => verifyResultEnvelope(flipped, { expectedPublicKey: key.publicKeyRaw }), ResultError);
});

test("anchors must be the three kinds, in protocol order, at increasing heights", () => {
  const swapped = {
    ...VERDICT,
    transitions: [VERDICT.transitions[1], VERDICT.transitions[0], VERDICT.transitions[2]],
  };
  assert.throws(() => build({ verdict: swapped }), /in order/);

  const regressed = {
    ...VERDICT,
    transitions: [
      VERDICT.transitions[0],
      { ...VERDICT.transitions[1], blockHeight: "2732100" },
      VERDICT.transitions[2],
    ],
  };
  assert.throws(() => build({ verdict: regressed }), /strictly increasing/);

  const missing = { ...VERDICT, transitions: VERDICT.transitions.slice(0, 2) };
  assert.throws(() => build({ verdict: missing }), /exactly three/);
});

test("the outcome word is carried, not chosen: a refusing verdict certifies as refusing", () => {
  // The certificate must be as willing to say a run failed as that it passed --
  // an emitter that only fires on AUTHORIZED would be a press release.
  const refused = { ...VERDICT, outcome: "EXPIRED" };
  const { key, envelope } = build({ verdict: refused });
  const result = verifyResultEnvelope(envelope, { expectedPublicKey: key.publicKeyRaw });
  assert.equal(result.outcome, "EXPIRED");
});
