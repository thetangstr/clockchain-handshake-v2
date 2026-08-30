import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import test from "node:test";

import {
  HANDSHAKE_V3_CONTRACT_PROVENANCE,
  HANDSHAKE_V3_PROTOCOL_VERSION,
  HANDSHAKE_V3_SCHEMA_VERSION,
  validateHandshakeV3Fixture,
  validateHandshakeV3ResponseEnvelope,
  validateHandshakeV3SignedAction,
  validateHandshakeV3SigningRequest,
  validateHandshakeV3ToolInput,
  validateHandshakeV3ToolResult,
} from "@clockchain/handshake-protocol/v3";

const fixtures = JSON.parse(
  await readFile(new URL("../fixtures/standalone-handshake-v3-contract-fixtures.json", import.meta.url), "utf8"),
);
const provenance = JSON.parse(
  await readFile(new URL("../fixtures/v3-provenance.json", import.meta.url), "utf8"),
);
const schemaBytes = await readFile(
  new URL("../schemas/standalone-handshake-v3-contract.schema.json", import.meta.url),
);
const fixtureBytes = await readFile(
  new URL("../fixtures/standalone-handshake-v3-contract-fixtures.json", import.meta.url),
);

function sha256Hex(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

test("v3 protocol package records approved schema and fixture provenance", () => {
  assert.equal(HANDSHAKE_V3_PROTOCOL_VERSION, "3.0");
  assert.equal(HANDSHAKE_V3_SCHEMA_VERSION, "3.0.0-draft.2");
  assert.deepEqual(provenance, HANDSHAKE_V3_CONTRACT_PROVENANCE);
  assert.equal(provenance.approvedProtocolSourceCommit, "d2cdedb705cf6855657381a908e47f71df959145");
  assert.equal(provenance.contractSchemaSha256, "579f2e07475fbf1e0209df9f082218837b766aab507430e514962971625d2991");
  assert.equal(provenance.contractFixturesSha256, "9a71c8efa6d4cce6f8f2d20ff6dc9ef7255874c8c81c26bb9393cc884aa5af79");
  assert.equal(sha256Hex(schemaBytes), provenance.contractSchemaSha256);
  assert.equal(sha256Hex(fixtureBytes), provenance.contractFixturesSha256);
});

test("v3 contract known-good fixtures are executable against strict validators", () => {
  for (const fixture of fixtures.knownGood) {
    assert.equal(validateHandshakeV3Fixture(fixture).valid, true, fixture.id);
    if (fixture.schemaRef === "#/$defs/signingRequest") {
      assert.equal(validateHandshakeV3SigningRequest(fixture.value).signingRequestId, fixture.value.signingRequestId);
    }
    if (fixture.schemaRef === "#/responseEnvelope") {
      assert.equal(validateHandshakeV3ResponseEnvelope(fixture.value).requestId, fixture.value.requestId);
    }
    if (fixture.tool) {
      assert.equal(validateHandshakeV3ToolInput(fixture.tool, fixture.input).tool, fixture.tool);
    }
  }
});

test("v3 contract known-bad fixtures fail closed with stable error codes", () => {
  for (const fixture of fixtures.knownBad) {
    if (fixture.schemaRef === "#/$defs/signedAction") {
      assert.throws(
        () => validateHandshakeV3SignedAction(fixture.value),
        { code: fixture.expectedError },
        fixture.id,
      );
      continue;
    }
    if (fixture.schemaRef === "#/responseEnvelope") {
      assert.throws(
        () => validateHandshakeV3ResponseEnvelope(fixture.value),
        { code: fixture.expectedError },
        fixture.id,
      );
      continue;
    }
    if (fixture.resultTool) {
      assert.throws(
        () => validateHandshakeV3ToolResult(fixture.resultTool, fixture.value),
        { code: fixture.expectedError },
        fixture.id,
      );
      continue;
    }
    if (fixture.tool) {
      assert.throws(
        () => validateHandshakeV3ToolInput(fixture.tool, fixture.input, { tokenScopes: fixture.tokenScopes }),
        { code: fixture.expectedError },
        fixture.id,
      );
    }
  }
});
