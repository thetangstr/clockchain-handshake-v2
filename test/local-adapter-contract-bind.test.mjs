import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import { contractCanonicalDigest, contractCanonicalJson } from "../src/local-adapter/contract-bind.mjs";

// --- piece 1: canonical JSON parity with the agent-contract server ----------
//
// test/fixtures/agent-contract-canonical-digest-vectors.json is a verbatim
// copy of clockchain-developer-tools packages/mcp-server
// test/fixtures/agent-contract-canonical-digest-vectors.json — the vectors the
// contract server's own canonical.ts is held to. The adapter's port must
// produce the same bytes and digests for every one of them.

const CANONICAL_VECTORS = JSON.parse(readFileSync(
  new URL("./fixtures/agent-contract-canonical-digest-vectors.json", import.meta.url),
  "utf8",
));

test("contract canonical JSON matches the server's committed digest vectors", () => {
  assert.equal(CANONICAL_VECTORS.schema, "agent-contract.canonical-digest-vectors/v1");
  assert.ok(CANONICAL_VECTORS.vectors.length >= 10);
  for (const vector of CANONICAL_VECTORS.vectors) {
    assert.equal(contractCanonicalJson(vector.input), vector.canonical);
    assert.equal(contractCanonicalDigest(vector.input), vector.digest);
  }
});

test("contract canonical JSON drops undefined members and refuses unrepresentable values", () => {
  assert.equal(contractCanonicalJson({ b: 1, skip: undefined, a: 2 }), "{\"a\":2,\"b\":1}");
  assert.throws(() => contractCanonicalJson([undefined]));
  assert.throws(() => contractCanonicalJson(Number.NaN));
  assert.throws(() => contractCanonicalJson(1n));
});
