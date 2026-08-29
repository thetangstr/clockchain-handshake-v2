import assert from "node:assert/strict";
import test from "node:test";

import {
  canonicalJsonBytes,
  canonicalJsonString,
  handshakeV3Digest,
  sha256Digest,
} from "@clockchain/handshake-protocol/v3/canonical";

test("RFC8785 canonicalization sorts keys and emits minimal supported JSON", () => {
  assert.equal(canonicalJsonString({ b: [3, true, null], a: "text" }), "{\"a\":\"text\",\"b\":[3,true,null]}");
  assert.equal(Buffer.from(canonicalJsonBytes({ z: "last", "é": "accent", a: 1 })).toString("utf8"), "{\"a\":1,\"z\":\"last\",\"é\":\"accent\"}");
  assert.equal(handshakeV3Digest({ b: 2, a: 1 }), "sha256:43258cff783fe7036d8a43033f830adfc60ec037382473548ac742b888292777");
});

test("RFC8785 canonicalization uses JSON-compatible Unicode escaping", () => {
  assert.equal(canonicalJsonString({ line: "\n", quote: "\"", slash: "\\" }), "{\"line\":\"\\n\",\"quote\":\"\\\"\",\"slash\":\"\\\\\"}");
});

test("RFC8785 canonicalization rejects unsupported or dangerous values", () => {
  assert.throws(() => canonicalJsonString({ n: NaN }), { code: "SCHEMA_INVALID" });
  assert.throws(() => canonicalJsonString({ n: Infinity }), { code: "SCHEMA_INVALID" });
  assert.throws(() => canonicalJsonString({ big: 1n }), { code: "SCHEMA_INVALID" });
  assert.throws(() => canonicalJsonString({ f() {} }), { code: "SCHEMA_INVALID" });
  assert.throws(() => canonicalJsonString({ bad: "\uD800" }), { code: "SCHEMA_INVALID" });
  const cyclic = {};
  cyclic.self = cyclic;
  assert.throws(() => canonicalJsonString(cyclic), { code: "SCHEMA_INVALID" });
});

test("RFC8785 official-style numeric, unicode, and ordering vectors are deterministic", () => {
  assert.equal(canonicalJsonString({ numbers: [333333333.3333333, 1e-27, -0] }), "{\"numbers\":[333333333.3333333,1e-27,0]}");
  assert.equal(canonicalJsonString({ "\u20ac": "Euro", "\r": "Carriage Return", "\ufb33": "Hebrew Letter Dalet With Dagesh" }), "{\"\\r\":\"Carriage Return\",\"€\":\"Euro\",\"דּ\":\"Hebrew Letter Dalet With Dagesh\"}");
});

test("sha256 digest helper accepts bytes and canonical JSON values", () => {
  assert.equal(sha256Digest(Buffer.from("hello")), "sha256:2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824");
  assert.equal(handshakeV3Digest({ hello: "world" }), "sha256:93a23971a914e5eacbf0a8d25154cda309c3c1c72fbb9914d47c60f3cb681588");
});
