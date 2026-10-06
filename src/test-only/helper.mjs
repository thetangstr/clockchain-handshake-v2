// Test-only helper 2.1.8 variant (Track B B3-2, TB/LLD.md §17.4). NEVER SHIP.
//
// The release helper verifies host session key certificates against the
// embedded production ring (agent-cli/trust-roots.mjs). This variant swaps in
// a Track B TEST host root ring baked at build time
// (scripts/test-only/build-test-only.mjs) and refuses to start at all when that
// ring names the production root — so a certificate minted under the
// production root can never verify here, and the variant cannot be pointed at
// production by configuration.

import { createAgentCliOperations } from "../agent-cli/operations.mjs";
import { runAgentHandshakeCli } from "../agent-cli/main.mjs";
import { isSigningWindowExpired, SIGNING_WINDOW_EXPIRED_MESSAGE } from "../agent-cli/signing-request.mjs";
import { ed25519PublicKeyFingerprint } from "../agent-handshake/v2/host-key-certificate.mjs";
import { AGENT_HANDSHAKE_HELPER_VERSION } from "../agent-handshake/v2/constants.mjs";
import {
  NEVER_SHIP_REFUSALS,
  NeverShipRefusal,
  TEST_ONLY_BUILD_TAG,
  TEST_ONLY_HELPER_MARKER,
  isProductionHostRoot,
} from "../local-adapter/never-ship-gate.mjs";

const KID = /^[a-z0-9][a-z0-9-]{0,63}$/;
const DIGEST = /^[0-9a-f]{64}$/;
const DECIMAL = /^(?:0|[1-9][0-9]*)$/;

/**
 * Validates a test-only root ring: 1–2 well-formed entries, none of them the
 * production root (by kid, fingerprint, or the fingerprint recomputed from its
 * public key). Validity windows are checked later, per operation, by the
 * release code path (validateHostRootKeyRing).
 */
export function assertTestOnlyRootKeyRing(ring) {
  if (!Array.isArray(ring) || ring.length < 1 || ring.length > 2) {
    throw new NeverShipRefusal(NEVER_SHIP_REFUSALS.ring);
  }
  for (const root of ring) {
    if (root === null || typeof root !== "object" || Array.isArray(root)) {
      throw new NeverShipRefusal(NEVER_SHIP_REFUSALS.ring);
    }
    if (isProductionHostRoot(root)) throw new NeverShipRefusal(NEVER_SHIP_REFUSALS.productionRoot);
    let recomputed;
    try { recomputed = ed25519PublicKeyFingerprint(root.publicKey); } catch {
      throw new NeverShipRefusal(NEVER_SHIP_REFUSALS.ring);
    }
    if (isProductionHostRoot({ fingerprint: recomputed })) {
      throw new NeverShipRefusal(NEVER_SHIP_REFUSALS.productionRoot);
    }
    if (
      !KID.test(root.kid) || !DIGEST.test(root.fingerprint) || root.fingerprint !== recomputed ||
      !DECIMAL.test(root.notBeforeMs) || !DECIMAL.test(root.notAfterMs)
    ) throw new NeverShipRefusal(NEVER_SHIP_REFUSALS.ring);
  }
  return Object.freeze(ring.map((root) => Object.freeze({ ...root })));
}

/** createAgentCliOperations bound to a validated test-only ring. */
export function createTestOnlyAgentCliOperations({ rootKeyRing, ...options } = {}) {
  const ring = assertTestOnlyRootKeyRing(rootKeyRing);
  return createAgentCliOperations({ ...options, rootKeyRing: ring });
}

export function testOnlyHelperInfo(rootKeyRing) {
  const ring = assertTestOnlyRootKeyRing(rootKeyRing);
  return Object.freeze({
    schema: "clockchain.agent-handshake-cli-test-only-info/v1",
    marker: TEST_ONLY_HELPER_MARKER,
    buildTag: TEST_ONLY_BUILD_TAG,
    neverShip: true,
    version: AGENT_HANDSHAKE_HELPER_VERSION,
    hostRoots: ring.map((root) => ({ kid: root.kid, fingerprint: root.fingerprint })),
  });
}

/**
 * The test-only CLI. `--test-only-info` reports the build tag and ring; every
 * other argv is the release CLI, under the test ring. The ring is checked
 * before anything else, so a production ring never reaches an operation.
 */
export async function runTestOnlyAgentHandshakeCli(argv, { rootKeyRing, ...options } = {}) {
  const ring = assertTestOnlyRootKeyRing(rootKeyRing);
  if (argv.length === 1 && argv[0] === "--test-only-info") return testOnlyHelperInfo(ring);
  return runAgentHandshakeCli(argv, {
    operations: createTestOnlyAgentCliOperations({ ...options, rootKeyRing: ring }),
  });
}

/**
 * Process entry for the bundled test-only helper: same stdout/stderr/exit
 * contract as bin/clockchain-agent-handshake.mjs, plus exit 87 with the
 * never-ship code when the baked ring is refused.
 */
export function runTestOnlyHelperMain({ rootKeyRing, argv = process.argv.slice(2) } = {}) {
  return runTestOnlyAgentHandshakeCli(argv, { rootKeyRing }).then(
    (value) => { process.stdout.write(`${JSON.stringify(value)}\n`); },
    (error) => {
      if (error instanceof NeverShipRefusal) {
        process.stderr.write(`${JSON.stringify({ error: { code: error.code, message: error.message } })}\n`);
        process.exitCode = 87;
        return;
      }
      process.stderr.write(`${JSON.stringify(isSigningWindowExpired(error)
        ? { error: { code: "AGENT_HANDSHAKE_SIGNING_WINDOW_EXPIRED", message: SIGNING_WINDOW_EXPIRED_MESSAGE } }
        : { error: { code: "AGENT_HANDSHAKE_FAILED", message: "Agent handshake operation failed safely." } })}\n`);
      process.exitCode = 1;
    },
  );
}
