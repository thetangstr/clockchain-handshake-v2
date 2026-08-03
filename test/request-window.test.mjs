// The request window must never be tighter than the mandate window it sits
// inside.
//
// This is a regression test for a live failure. buildRequest stamped
// createdAtMs as issuedAtMs + 1000, so the payment request declared itself
// created one second in the future relative to the mandate. The verifier
// requires the proposal anchor to land at or after requestCreatedAtMs, and that
// anchor is timestamped by Clockchain while these fields are timestamped
// locally -- so the run only passed if the chain happened to write the proposal
// block more than a second after the mandate was signed.
//
// Across eight real runs the margin between the proposal's block time and
// requestCreatedAtMs was 202ms, 399ms, 401ms, 443ms, 731ms, 1291ms, 2902ms --
// and once -255ms, which failed closed as EXPIRED in front of a demo. Every run
// was within a second of failing. The offset bought nothing: the mandate window
// already bounds the anchor, and payment-request.mjs requires only
// createdAtMs >= issuedAtMs.
import assert from "node:assert/strict";
import test from "node:test";

import { buildMandate, buildRequest } from "../src/roles/session.mjs";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";

async function artifacts() {
  const payerAccount = privateKeyToAccount(generatePrivateKey());
  const requestorAccount = privateKeyToAccount(generatePrivateKey());
  const mandate = await buildMandate({
    payerAccount,
    payerAgentId: "1",
    repositorySha: "0".repeat(40),
    requestorAddress: requestorAccount.address,
    requestorAgentId: "2",
  });
  const requestEnvelope = await buildRequest({ ...mandate, requestorAccount });
  return { mandate, requestEnvelope };
}

test("the payment request is never stamped later than the mandate that authorises it", async () => {
  const { mandate, requestEnvelope } = await artifacts();
  const createdAtMs = BigInt(requestEnvelope.request.createdAtMs);
  const issuedAtMs = BigInt(mandate.issuedAtMs);

  assert.ok(
    createdAtMs >= issuedAtMs,
    "a request created before its mandate is rejected outright",
  );
  assert.equal(
    createdAtMs,
    issuedAtMs,
    "any offset past the mandate makes the request window tighter than the mandate " +
      "window, and the proposal anchor has to satisfy both",
  );
});

test("the request expires with its mandate, not before it", async () => {
  const { mandate, requestEnvelope } = await artifacts();
  assert.equal(
    BigInt(requestEnvelope.request.expiresAtMs),
    BigInt(mandate.expiresAtMs),
    "an earlier request expiry would reintroduce the same asymmetry at the far end",
  );
});
