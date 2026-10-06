#!/usr/bin/env node
// TEST-ONLY, NEVER SHIP (Track B B3-2, TB/LLD.md §17.4).
//
// Stdio entry for the test-only local adapter. It serves only a build
// directory written by scripts/test-only/build-test-only.mjs, named by
// CLOCKCHAIN_TEST_ONLY_BUILD_DIR (absolute). The endpoint is the loopback
// endpoint recorded in that build; CLOCKCHAIN_LOCAL_ADAPTER_ENDPOINT is
// ignored. Refusals exit before a single JSON-RPC message is served:
//   87  never-ship refusal (production root/pin, non-loopback endpoint,
//       helper/record mismatch) — the code is printed on stderr
//   86  any other asset verification failure
import { NeverShipRefusal } from "../src/local-adapter/never-ship-gate.mjs";
import { startTestOnlyLocalAdapterStdio } from "../src/test-only/adapter.mjs";

try {
  startTestOnlyLocalAdapterStdio({ buildDir: process.env.CLOCKCHAIN_TEST_ONLY_BUILD_DIR });
} catch (error) {
  if (error instanceof NeverShipRefusal) {
    process.stderr.write(`${JSON.stringify({ error: error.code })}\n`);
    process.exit(87);
  }
  process.stderr.write(`${JSON.stringify({ error: "ADAPTER_ASSET_VERIFICATION_FAILED" })}\n`);
  process.exit(86);
}
