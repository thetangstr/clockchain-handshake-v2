import assert from "node:assert/strict";
import { test } from "node:test";

import { buildMandate } from "../src/roles/session.mjs";

const PAYER_ACCOUNT = Object.freeze({
  address: `0x${"1".repeat(40)}`,
  signMessage: async () => `0x${"2".repeat(130)}`,
});
const REQUESTOR_ADDRESS = `0x${"3".repeat(40)}`;
const REPOSITORY_SHA = "0".repeat(40);
const FORTY_FIVE_MINUTES_MS = 45 * 60_000;

function mandateOptions(overrides = {}) {
  return {
    payerAccount: PAYER_ACCOUNT,
    payerAgentId: "101",
    repositorySha: REPOSITORY_SHA,
    requestorAddress: REQUESTOR_ADDRESS,
    requestorAgentId: "202",
    ...overrides,
  };
}

test("buildMandate signs an injected issuedAtMs into the mandate window", async () => {
  const issuedAtMs = 1_785_294_000_123;
  const result = await buildMandate(mandateOptions({ issuedAtMs }));

  assert.equal(result.issuedAtMs, issuedAtMs);
  assert.equal(result.expiresAtMs, issuedAtMs + FORTY_FIVE_MINUTES_MS);
  assert.equal(result.mandateEnvelope.mandate.issuedAtMs, String(issuedAtMs));
  assert.equal(
    result.mandateEnvelope.mandate.expiresAtMs,
    String(issuedAtMs + FORTY_FIVE_MINUTES_MS),
  );
});

test("buildMandate without issuedAtMs preserves the Date.now timestamp bytes", async (t) => {
  const issuedAtMs = 1_785_294_000_000;
  t.mock.method(Date, "now", () => issuedAtMs);

  const result = await buildMandate(mandateOptions());
  const timestampFixture = JSON.stringify({
    expiresAtMs: result.expiresAtMs,
    issuedAtMs: result.issuedAtMs,
    mandateExpiresAtMs: result.mandateEnvelope.mandate.expiresAtMs,
    mandateIssuedAtMs: result.mandateEnvelope.mandate.issuedAtMs,
  });

  assert.equal(
    timestampFixture,
    "{\"expiresAtMs\":1785296700000,\"issuedAtMs\":1785294000000,\"mandateExpiresAtMs\":\"1785296700000\",\"mandateIssuedAtMs\":\"1785294000000\"}",
  );
});
