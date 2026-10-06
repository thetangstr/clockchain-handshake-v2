// Never-ship gate (Track B B3-2, TB/LLD.md §17.4).
//
// A test-only adapter 2.2.0 + helper 2.1.8 variant exists for offline loopback
// experiments: the helper's root ring is a Track B TEST host root and the
// adapter's endpoint is a loopback port. It must never run against the
// production host root or a production endpoint, and a production adapter must
// never run the test-only helper.
//
// This module is the small production-side half of that rule: it is imported
// by server.mjs, so it ships in the release adapter bundle. It holds no test
// keys — only the production pins it refuses and the marker that every
// test-only helper bundle carries. The builder and the test-only entry points
// live in src/test-only/ and are never part of a release bundle
// (scripts/check-invariants.sh §8, auditAgentHandshakeBundle).

// Every test-only helper bundle starts with this banner and carries the
// constant below, so its digest-verified bytes identify it. A helper without
// the marker is a release helper.
export const TEST_ONLY_HELPER_MARKER = "clockchain-test-only-never-ship-build/v1";
export const TEST_ONLY_BUILD_TAG = "test-only";
export const TEST_ONLY_BUILD_SCHEMA = "track-b.test-only-build/v1";

// The production host root (agent-cli/trust-roots.mjs EMBEDDED_HOST_ROOT_KEY_RING
// and release/agent-handshake/pin.json hostRoots; a test pins the equality).
export const PRODUCTION_HOST_ROOT_KIDS = Object.freeze(["root-2026-08"]);
export const PRODUCTION_HOST_ROOT_FINGERPRINTS = Object.freeze([
  "da2771c36bf2298525d2bbd8351b6122bb67115e9979624e8bb56537bcf71ed8",
]);
export const PRODUCTION_HOST_ROOT_PUBLIC_KEYS = Object.freeze([
  "mjsBe8vyv46uEu0Fa+oH5kCOlJRbZ8nbfIrBSp4aV8Q=",
]);
// The production helper release manifest (release/agent-handshake/pin.json).
export const PRODUCTION_MANIFEST_DIGESTS = Object.freeze([
  "956c8d94d4e7dbbaad5247e8de3f958ad75ec81831193c31c995e3787bf33bf7",
]);

// Track B loopback test block (track-b/config/tb.profile.json ports.block).
export const TEST_ONLY_PORT_RANGE = Object.freeze([19400, 19499]);
export const TEST_ONLY_LOOPBACK_HOST = "127.0.0.1";

export const NEVER_SHIP_REFUSALS = Object.freeze({
  productionRoot: "TEST_ONLY_PRODUCTION_ROOT",
  productionPin: "TEST_ONLY_PRODUCTION_PIN",
  endpoint: "TEST_ONLY_NON_LOOPBACK_ENDPOINT",
  record: "TEST_ONLY_BUILD_RECORD_INVALID",
  helper: "TEST_ONLY_HELPER_MISMATCH",
  ring: "TEST_ONLY_RING_INVALID",
  output: "TEST_ONLY_OUTPUT_REFUSED",
});

export class NeverShipRefusal extends Error {
  constructor(code) {
    super(`Never-ship test-only build refused: ${code}`);
    this.name = "NeverShipRefusal";
    this.code = code;
  }
}

function refuse(code) {
  throw new NeverShipRefusal(code);
}

/** True for https://127.0.0.1:<19400-19499>/... with no credentials. */
export function isLoopbackTestEndpoint(value) {
  if (typeof value !== "string") return false;
  let url;
  try { url = new URL(value); } catch { return false; }
  if (url.protocol !== "https:" || url.hostname !== TEST_ONLY_LOOPBACK_HOST) return false;
  if (url.username !== "" || url.password !== "" || url.port === "") return false;
  const port = Number(url.port);
  return Number.isSafeInteger(port) && port >= TEST_ONLY_PORT_RANGE[0] && port <= TEST_ONLY_PORT_RANGE[1];
}

export function assertLoopbackTestEndpoint(value) {
  if (!isLoopbackTestEndpoint(value)) refuse(NEVER_SHIP_REFUSALS.endpoint);
  return value;
}

/** Is this root (by kid, fingerprint or public key) the production host root? */
export function isProductionHostRoot(root) {
  if (root === null || typeof root !== "object") return false;
  return PRODUCTION_HOST_ROOT_KIDS.includes(root.kid) ||
    PRODUCTION_HOST_ROOT_FINGERPRINTS.includes(root.fingerprint) ||
    PRODUCTION_HOST_ROOT_PUBLIC_KEYS.includes(root.publicKey);
}

/** A test-only pin: no production root, not the production manifest. */
export function assertTestOnlyPin(pin) {
  if (pin === null || typeof pin !== "object" || !Array.isArray(pin.hostRoots) || pin.hostRoots.length < 1) {
    refuse(NEVER_SHIP_REFUSALS.record);
  }
  if (pin.hostRoots.some(isProductionHostRoot)) refuse(NEVER_SHIP_REFUSALS.productionRoot);
  if (PRODUCTION_MANIFEST_DIGESTS.includes(pin.manifestDigest)) refuse(NEVER_SHIP_REFUSALS.productionPin);
  return pin;
}

export function isTestOnlyHelperBytes(helperBytes) {
  return Buffer.isBuffer(helperBytes) && helperBytes.includes(Buffer.from(TEST_ONLY_HELPER_MARKER, "utf8"));
}

/**
 * The server-side gate, run by createLocalAdapterServer once its assets are
 * verified. Returns true for a test-only configuration, false for a release
 * one, and throws NeverShipRefusal for any mix of the two:
 *  - a test-only helper without a test-only build record (e.g. the release
 *    entry pointed at a test build directory) is refused;
 *  - a test-only build record with a release helper is refused;
 *  - a test-only configuration must pin a non-production root and manifest and
 *    talk to a loopback test endpoint.
 */
export function gateNeverShip({ helperBytes, pin, endpoint, testOnlyBuild }) {
  const helperIsTestOnly = isTestOnlyHelperBytes(helperBytes);
  if (testOnlyBuild === undefined) {
    if (helperIsTestOnly) refuse(NEVER_SHIP_REFUSALS.helper);
    return false;
  }
  if (
    testOnlyBuild === null || typeof testOnlyBuild !== "object" ||
    testOnlyBuild.schema !== TEST_ONLY_BUILD_SCHEMA ||
    testOnlyBuild.buildTag !== TEST_ONLY_BUILD_TAG ||
    testOnlyBuild.neverShip !== true ||
    testOnlyBuild.manifestDigest !== pin?.manifestDigest
  ) refuse(NEVER_SHIP_REFUSALS.record);
  if (!helperIsTestOnly) refuse(NEVER_SHIP_REFUSALS.helper);
  assertTestOnlyPin(pin);
  assertLoopbackTestEndpoint(endpoint);
  if (testOnlyBuild.endpoint !== endpoint) refuse(NEVER_SHIP_REFUSALS.endpoint);
  return true;
}
