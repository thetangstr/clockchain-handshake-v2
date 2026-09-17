import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import test from "node:test";

import {
  isCanonicalUsdPaymentAmount,
  normalizeCanonicalUsdPaymentAmount,
} from "../src/core/payment-amount.mjs";

const execFileAsync = promisify(execFile);
const ROOT = new URL("..", import.meta.url);

test("canonical USD payment amount accepts only positive safe integer cents profile", () => {
  for (const value of ["1", String(Number.MAX_SAFE_INTEGER)]) {
    const normalized = normalizeCanonicalUsdPaymentAmount(
      { currency: "USD", value },
      () => {
        throw new Error("invalid");
      },
    );
    assert.equal(normalized.currency, "USD");
    assert.equal(normalized.value, value);
    assert.equal(isCanonicalUsdPaymentAmount({ currency: "USD", value }), true);
  }

  for (const amount of [
    { currency: "USD", value: "0" },
    { currency: "USD", value: "01" },
    { currency: "USD", value: "1.0" },
    { currency: "USD", value: "1e3" },
    { currency: "USD", value: " 1" },
    { currency: "USD", value: "1 " },
    { currency: "EUR", value: "1" },
    { currency: "usd", value: "1" },
    { currency: "USD", value: "9007199254740992" },
    { currency: "USD", value: "9999999999999999" },
  ]) {
    assert.equal(isCanonicalUsdPaymentAmount(amount), false, JSON.stringify(amount));
  }
});

test("canonical USD payment amount rejects hostile and non-exact shapes without throwing from predicate", () => {
  const accessor = { currency: "USD" };
  Object.defineProperty(accessor, "value", {
    enumerable: true,
    get() {
      throw new Error("read");
    },
  });

  for (const amount of [
    null,
    [],
    { currency: "USD" },
    { value: "1" },
    { currency: "USD", moved: false, value: "1" },
    new Proxy({ currency: "USD", value: "1" }, {}),
    accessor,
  ]) {
    assert.equal(isCanonicalUsdPaymentAmount(amount), false);
  }
});

test("local demo rejects invalid payment amount before live setup progress or funding path", async () => {
  await assert.rejects(
    execFileAsync(process.execPath, ["scripts/run-local-demo.mjs", "--stub", "--amount", "0"], {
      cwd: ROOT,
      timeout: 10_000,
    }),
    (error) => {
      assert.equal(error.code, 1);
      assert.match(error.stdout, /Stopped: Payment amount must be USD/);
      assert.doesNotMatch(error.stdout, /Starting a payment-authorization handshake/);
      assert.doesNotMatch(error.stdout, /Operator treasury is available/);
      assert.doesNotMatch(error.stdout, /fresh payer identity/);
      assert.match(error.stderr, /"reason":"INVALID_PAYMENT_AMOUNT"/);
      return true;
    },
  );
});
