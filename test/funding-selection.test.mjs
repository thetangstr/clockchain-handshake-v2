import assert from "node:assert/strict";
import test from "node:test";

import { selectFundingRecord } from "../src/roles/funding-selection.mjs";

const ownAddress = "0x1111111111111111111111111111111111111111";
const otherAddress = "0x2222222222222222222222222222222222222222";

function funding(seq, funded, body = {}) {
  return {
    body: { funded, paymentMoved: false, ...body },
    kind: "funding_record",
    role: "host",
    seq: String(seq),
  };
}

test("requestor skips payer-tagged other funding and accepts later own funding", () => {
  const result = selectFundingRecord(
    [
      funding(1, otherAddress, { role: "payer" }),
      funding(2, ownAddress, { role: "requestor" }),
    ],
    { address: ownAddress, role: "requestor" },
  );

  assert.equal(result.status, "proceed");
  assert.equal(result.message.seq, "2");
});

test("requestor stops on untagged funding for another address", () => {
  const result = selectFundingRecord(
    [funding(1, otherAddress)],
    { address: ownAddress, role: "requestor" },
  );

  assert.equal(result.status, "already-bound");
  assert.equal(result.message.seq, "1");
});

test("requestor stops on requestor-tagged funding for another address", () => {
  const result = selectFundingRecord(
    [funding(1, otherAddress, { role: "requestor" })],
    { address: ownAddress, role: "requestor" },
  );

  assert.equal(result.status, "already-bound");
  assert.equal(result.message.seq, "1");
});

test("own-address funding proceeds even if the funding record names a different seat", () => {
  const result = selectFundingRecord(
    [funding(1, ownAddress, { role: "payer" })],
    { address: ownAddress, role: "requestor" },
  );

  assert.equal(result.status, "proceed");
  assert.equal(result.message.seq, "1");
});
