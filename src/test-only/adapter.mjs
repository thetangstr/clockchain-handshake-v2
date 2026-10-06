// Test-only adapter variant (Track B B3-2, TB/LLD.md §17.4). NEVER SHIP.
//
// Runs the release adapter code (createLocalAdapterServer) over a test-only
// build directory written by scripts/test-only/build-test-only.mjs:
//
//   <buildDir>/pin.json                       test pin (test root, test manifest digest)
//   <buildDir>/manifest.json                  canonical manifest of the test helper
//   <buildDir>/clockchain-agent-handshake.cjs the test-only helper (marker + test ring)
//   <buildDir>/test-only-build.json           the never-ship build record
//
// The endpoint is the loopback endpoint recorded at build time; no option or
// environment variable can redirect it. The server's own never-ship gate
// (never-ship-gate.mjs) re-checks the pin, the helper marker and the endpoint.

import { readFileSync } from "node:fs";
import { isAbsolute, join, resolve } from "node:path";

import { createLocalAdapterServer, startLocalAdapterStdio } from "../local-adapter/server.mjs";
import {
  NEVER_SHIP_REFUSALS,
  NeverShipRefusal,
  TEST_ONLY_BUILD_SCHEMA,
  TEST_ONLY_BUILD_TAG,
  assertLoopbackTestEndpoint,
  assertTestOnlyPin,
} from "../local-adapter/never-ship-gate.mjs";

export const TEST_ONLY_BUILD_RECORD = "test-only-build.json";

const RECORD_KEYS = Object.freeze([
  "schema", "buildTag", "neverShip", "shipAllowed", "component", "adapterVersion", "helperVersion",
  "sourceCommit", "sourceDirty", "endpoint", "hostRoots", "manifestDigest", "helperSha256", "builtAt", "notes",
]);
const DIGEST = /^[0-9a-f]{64}$/;

function refuse(code) {
  throw new NeverShipRefusal(code);
}

/** Strictly validates a parsed test-only build record. */
export function validateTestOnlyBuildRecord(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) refuse(NEVER_SHIP_REFUSALS.record);
  const keys = Object.keys(value);
  if (keys.length !== RECORD_KEYS.length || keys.some((key) => !RECORD_KEYS.includes(key))) {
    refuse(NEVER_SHIP_REFUSALS.record);
  }
  if (
    value.schema !== TEST_ONLY_BUILD_SCHEMA || value.buildTag !== TEST_ONLY_BUILD_TAG ||
    value.neverShip !== true || value.shipAllowed !== false ||
    !DIGEST.test(value.manifestDigest) || !DIGEST.test(value.helperSha256) ||
    !Array.isArray(value.hostRoots) || value.hostRoots.length < 1
  ) refuse(NEVER_SHIP_REFUSALS.record);
  assertLoopbackTestEndpoint(value.endpoint);
  assertTestOnlyPin({ hostRoots: value.hostRoots, manifestDigest: value.manifestDigest });
  return Object.freeze({ ...value, hostRoots: Object.freeze(value.hostRoots.map((root) => Object.freeze({ ...root }))) });
}

export function loadTestOnlyBuildRecord(buildDir) {
  if (typeof buildDir !== "string" || !isAbsolute(buildDir)) refuse(NEVER_SHIP_REFUSALS.record);
  let parsed;
  try { parsed = JSON.parse(readFileSync(join(resolve(buildDir), TEST_ONLY_BUILD_RECORD), "utf8")); } catch {
    refuse(NEVER_SHIP_REFUSALS.record);
  }
  return validateTestOnlyBuildRecord(parsed);
}

/**
 * createLocalAdapterServer over a test-only build directory. `endpoint` and
 * `assetDir` are not accepted as options: both come from the build.
 */
export function createTestOnlyLocalAdapterServer({ buildDir, ...options } = {}) {
  for (const key of ["endpoint", "assetDir", "assets", "pin", "pinPath", "manifestPath", "helperPath", "testOnlyBuild"]) {
    if (Object.hasOwn(options, key)) refuse(NEVER_SHIP_REFUSALS.record);
  }
  const record = loadTestOnlyBuildRecord(buildDir);
  let pin;
  try { pin = JSON.parse(readFileSync(join(resolve(buildDir), "pin.json"), "utf8")); } catch {
    refuse(NEVER_SHIP_REFUSALS.record);
  }
  assertTestOnlyPin(pin);
  if (pin.manifestDigest !== record.manifestDigest) refuse(NEVER_SHIP_REFUSALS.record);
  return createLocalAdapterServer({
    ...options,
    assetDir: resolve(buildDir),
    endpoint: record.endpoint,
    testOnlyBuild: record,
  });
}

export function startTestOnlyLocalAdapterStdio({ buildDir, ...options } = {}) {
  for (const key of ["endpoint", "assetDir", "assets", "pin", "pinPath", "manifestPath", "helperPath", "testOnlyBuild"]) {
    if (Object.hasOwn(options, key)) refuse(NEVER_SHIP_REFUSALS.record);
  }
  const record = loadTestOnlyBuildRecord(buildDir);
  return startLocalAdapterStdio({
    ...options,
    assetDir: resolve(buildDir),
    endpoint: record.endpoint,
    testOnlyBuild: record,
  });
}
