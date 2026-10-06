// Track B B3-2: the never-ship test-only adapter 2.2.0 + helper 2.1.8 build
// (TB/LLD.md §17.4). Acceptance: the build refuses to run against the
// production root. Also: loopback-only endpoint, the release adapter refuses
// the test-only helper, and release bundles never contain src/test-only/.
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { generateKeyPairSync } from "node:crypto";
import { mkdtemp, readdir, readFile, rm, stat, writeFile, cp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import test from "node:test";

import { EMBEDDED_HOST_ROOT_KEY_RING } from "../src/agent-cli/trust-roots.mjs";
import { ed25519PublicKeyFingerprint, rawEd25519PublicKey } from "../src/agent-handshake/v2/host-key-certificate.mjs";
import {
  NEVER_SHIP_REFUSALS,
  NeverShipRefusal,
  PRODUCTION_HOST_ROOT_FINGERPRINTS,
  PRODUCTION_HOST_ROOT_KIDS,
  PRODUCTION_HOST_ROOT_PUBLIC_KEYS,
  PRODUCTION_MANIFEST_DIGESTS,
  TEST_ONLY_HELPER_MARKER,
  gateNeverShip,
  isLoopbackTestEndpoint,
} from "../src/local-adapter/never-ship-gate.mjs";
import { ADAPTER_DEFAULT_ENDPOINT, createLocalAdapterServer } from "../src/local-adapter/server.mjs";
import { createTestOnlyLocalAdapterServer } from "../src/test-only/adapter.mjs";
import {
  assertTestOnlyRootKeyRing,
  createTestOnlyAgentCliOperations,
  runTestOnlyAgentHandshakeCli,
} from "../src/test-only/helper.mjs";
import { buildTestOnly } from "../scripts/test-only/build-test-only.mjs";
import { auditAgentHandshakeBundle } from "../scripts/build-agent-handshake-release.mjs";
import { buildAgentCliFixture } from "./support/agent-cli-fixture.mjs";

const execFileAsync = promisify(execFile);
const ROOT = new URL("..", import.meta.url).pathname;
const ENDPOINT = "https://127.0.0.1:19412/next/handshake/mcp";
const PIN = JSON.parse(await readFile(new URL("../release/agent-handshake/pin.json", import.meta.url), "utf8"));

function testRing({ kid = "tb-test-root-2026-10" } = {}) {
  const { publicKey } = generateKeyPairSync("ed25519");
  const raw = rawEd25519PublicKey(publicKey);
  return [{
    kid,
    publicKey: raw,
    fingerprint: ed25519PublicKeyFingerprint(raw),
    notBeforeMs: String(Date.now() - 60_000),
    notAfterMs: String(Date.now() + 24 * 3_600_000),
  }];
}

const refusedWith = (code) => (error) => error instanceof NeverShipRefusal && error.code === code;

async function scratch(t, prefix) {
  const dir = await mkdtemp(join(tmpdir(), prefix));
  t.after(() => rm(dir, { recursive: true, force: true }));
  return dir;
}

// One build shared by the tests below (bundling viem takes a few seconds).
let built = null;
async function builtOnce() {
  if (built === null) {
    const base = await mkdtemp(join(tmpdir(), "tb-test-only-build-"));
    built = { base, ...await buildTestOnly({ outDir: join(base, "out"), rootKeyRing: testRing(), endpoint: ENDPOINT }) };
  }
  return built;
}

test.after(async () => { if (built !== null) await rm(built.base, { recursive: true, force: true }); });

test("the gate's production pins equal the embedded helper ring and release/agent-handshake/pin.json", () => {
  assert.deepEqual(PRODUCTION_HOST_ROOT_KIDS, EMBEDDED_HOST_ROOT_KEY_RING.map((root) => root.kid));
  assert.deepEqual(PRODUCTION_HOST_ROOT_FINGERPRINTS, EMBEDDED_HOST_ROOT_KEY_RING.map((root) => root.fingerprint));
  assert.deepEqual(PRODUCTION_HOST_ROOT_PUBLIC_KEYS, EMBEDDED_HOST_ROOT_KEY_RING.map((root) => root.publicKey));
  assert.deepEqual(PIN.hostRoots.map((root) => root.fingerprint), [...PRODUCTION_HOST_ROOT_FINGERPRINTS]);
  assert.deepEqual(PIN.hostRoots.map((root) => root.kid), [...PRODUCTION_HOST_ROOT_KIDS]);
  assert.deepEqual([PIN.manifestDigest], [...PRODUCTION_MANIFEST_DIGESTS]);
});

test("loopback test endpoints only: https, 127.0.0.1, an explicit port in 19400-19499, no credentials", () => {
  for (const ok of ["https://127.0.0.1:19400/mcp", ENDPOINT, "https://127.0.0.1:19499/"]) assert.equal(isLoopbackTestEndpoint(ok), true, ok);
  for (const bad of [
    ADAPTER_DEFAULT_ENDPOINT,
    "https://mcp.clockchain.network/contract/mcp",
    "http://127.0.0.1:19412/mcp",
    "https://localhost:19412/mcp",
    "https://127.0.0.1/mcp",
    "https://127.0.0.1:19399/mcp",
    "https://127.0.0.1:19500/mcp",
    "https://127.0.0.1:9412/mcp",
    "https://127.0.0.1:3300/mcp",
    "https://u:p@127.0.0.1:19412/mcp",
    "https://0.0.0.0:19412/mcp",
    "https://[::1]:19412/mcp",
    "not a url",
    null,
  ]) assert.equal(isLoopbackTestEndpoint(bad), false, String(bad));
});

test("the test-only helper refuses to run against the production root (by kid, fingerprint or public key)", async () => {
  const [production] = EMBEDDED_HOST_ROOT_KEY_RING;
  const [test0] = testRing();
  const disguised = [
    [production],
    [{ ...production, kid: "tb-test-root" }], // same key, renamed
    [{ ...test0, kid: production.kid }], // production kid on a test key
    [test0, production], // production as the previous root
  ];
  for (const ring of disguised) {
    assert.throws(() => assertTestOnlyRootKeyRing(ring), refusedWith(NEVER_SHIP_REFUSALS.productionRoot));
    assert.throws(() => createTestOnlyAgentCliOperations({ rootKeyRing: ring }), refusedWith(NEVER_SHIP_REFUSALS.productionRoot));
    // Refused before any operation, even --version.
    await assert.rejects(runTestOnlyAgentHandshakeCli(["--version"], { rootKeyRing: ring }), refusedWith(NEVER_SHIP_REFUSALS.productionRoot));
  }
  for (const ring of [[], [test0, test0, test0], [{ ...test0, fingerprint: "f".repeat(64) }], "ring", null]) {
    assert.throws(() => assertTestOnlyRootKeyRing(ring), NeverShipRefusal);
  }
  // The CLI fixture's test key still carries the production kid: refused as is,
  // accepted once it has a test kid of its own.
  const fixture = await buildAgentCliFixture();
  assert.throws(() => assertTestOnlyRootKeyRing(fixture.rootKeyRing), refusedWith(NEVER_SHIP_REFUSALS.productionRoot));
  const ring = fixture.rootKeyRing.map((root) => ({ ...root, kid: "tb-test-root-2026-10" }));
  assert.equal(assertTestOnlyRootKeyRing(ring).length, 1);
  assert.equal(typeof createTestOnlyAgentCliOperations({ rootKeyRing: ring }).dispatch, "function");
  const info = await runTestOnlyAgentHandshakeCli(["--test-only-info"], { rootKeyRing: ring });
  assert.equal(info.buildTag, "test-only");
  assert.equal(info.neverShip, true);
});

test("the test-only helper process exits 87 with TEST_ONLY_PRODUCTION_ROOT when its ring is the production ring", async () => {
  const script = [
    `import { runTestOnlyHelperMain } from ${JSON.stringify(join(ROOT, "src/test-only/helper.mjs"))};`,
    `import { EMBEDDED_HOST_ROOT_KEY_RING } from ${JSON.stringify(join(ROOT, "src/agent-cli/trust-roots.mjs"))};`,
    `await runTestOnlyHelperMain({ rootKeyRing: EMBEDDED_HOST_ROOT_KEY_RING, argv: ["--version"] });`,
  ].join("\n");
  const outcome = await execFileAsync(process.execPath, ["--input-type=module", "--eval", script], { encoding: "utf8" })
    .then(() => ({ code: 0, stderr: "" }), (error) => ({ code: error.code, stderr: error.stderr }));
  assert.equal(outcome.code, 87);
  assert.equal(JSON.parse(outcome.stderr).error.code, "TEST_ONLY_PRODUCTION_ROOT");
});

test("the build refuses the production root, a non-loopback endpoint, and an output path inside the repository", async (t) => {
  const base = await scratch(t, "tb-test-only-refuse-");
  await assert.rejects(
    buildTestOnly({ outDir: join(base, "a"), rootKeyRing: EMBEDDED_HOST_ROOT_KEY_RING, endpoint: ENDPOINT }),
    refusedWith(NEVER_SHIP_REFUSALS.productionRoot),
  );
  await assert.rejects(
    buildTestOnly({ outDir: join(base, "b"), rootKeyRing: testRing(), endpoint: ADAPTER_DEFAULT_ENDPOINT }),
    refusedWith(NEVER_SHIP_REFUSALS.endpoint),
  );
  for (const inside of [join(ROOT, "dist", "test-only"), join(ROOT, "release", "test-only"), ROOT]) {
    await assert.rejects(
      buildTestOnly({ outDir: inside, rootKeyRing: testRing(), endpoint: ENDPOINT }),
      refusedWith(NEVER_SHIP_REFUSALS.output),
    );
  }
  // Nothing was written for the refused builds.
  assert.deepEqual((await readdir(base)).sort(), []);
});

test("the build writes a never-ship record, a marked helper under the test ring, and a non-production pin", async (t) => {
  const { outDir, record, pin, info } = await builtOnce();
  assert.deepEqual((await readdir(outDir)).sort(), ["clockchain-agent-handshake.cjs", "manifest.json", "pin.json", "test-only-build.json"]);
  assert.equal((await stat(outDir)).mode & 0o777, 0o700);
  for (const name of await readdir(outDir)) assert.equal((await stat(join(outDir, name))).mode & 0o777, 0o600, name);
  assert.equal(record.buildTag, "test-only");
  assert.equal(record.neverShip, true);
  assert.equal(record.shipAllowed, false);
  assert.equal(record.endpoint, ENDPOINT);
  assert.ok(!PRODUCTION_MANIFEST_DIGESTS.includes(pin.manifestDigest));
  assert.ok(pin.hostRoots.every((root) => !PRODUCTION_HOST_ROOT_FINGERPRINTS.includes(root.fingerprint)));
  const helper = await readFile(join(outDir, "clockchain-agent-handshake.cjs"), "utf8");
  assert.ok(helper.startsWith(`/* ${TEST_ONLY_HELPER_MARKER}`));
  // The baked ring is the test ring.
  for (const root of pin.hostRoots) assert.ok(helper.includes(root.fingerprint), root.kid);
  // Through the verified bootstrap: the helper reports its tag and its test ring.
  assert.equal(info.buildTag, "test-only");
  assert.deepEqual(info.hostRoots, pin.hostRoots);
});

test("the test-only adapter serves only the recorded loopback endpoint; no option or env redirects it", async (t) => {
  const { outDir } = await builtOnce();
  const tmpRoot = await scratch(t, "tb-test-only-tmp-");
  const urls = [];
  const fetchImpl = async (url) => {
    urls.push(String(url));
    return new Response(JSON.stringify({ jsonrpc: "2.0", id: 1, result: { tools: [] } }), { headers: { "content-type": "application/json" } });
  };
  const previous = process.env.CLOCKCHAIN_LOCAL_ADAPTER_ENDPOINT;
  process.env.CLOCKCHAIN_LOCAL_ADAPTER_ENDPOINT = ADAPTER_DEFAULT_ENDPOINT;
  t.after(() => { if (previous === undefined) delete process.env.CLOCKCHAIN_LOCAL_ADAPTER_ENDPOINT; else process.env.CLOCKCHAIN_LOCAL_ADAPTER_ENDPOINT = previous; });
  const server = createTestOnlyLocalAdapterServer({ buildDir: outDir, fetchImpl, tmpdir: tmpRoot });
  await server.handleMessage({ jsonrpc: "2.0", id: 1, method: "tools/list" });
  assert.ok(urls.length > 0);
  assert.ok(urls.every((url) => url === ENDPOINT), urls.join(","));
  for (const key of ["endpoint", "assetDir", "pin", "testOnlyBuild"]) {
    assert.throws(() => createTestOnlyLocalAdapterServer({ buildDir: outDir, [key]: ADAPTER_DEFAULT_ENDPOINT, fetchImpl, tmpdir: tmpRoot }), NeverShipRefusal, key);
  }
});

test("the release adapter refuses the test-only helper, and the test-only gate refuses production pins and endpoints", async (t) => {
  const { outDir, record, pin } = await builtOnce();
  const tmpRoot = await scratch(t, "tb-test-only-tmp-");
  const fetchImpl = async () => { throw new Error("must not be reached"); };
  // The release entry pointed at a test-only build directory.
  assert.throws(
    () => createLocalAdapterServer({ assetDir: outDir, endpoint: ADAPTER_DEFAULT_ENDPOINT, fetchImpl, tmpdir: tmpRoot }),
    refusedWith(NEVER_SHIP_REFUSALS.helper),
  );
  assert.throws(
    () => createLocalAdapterServer({ assetDir: outDir, endpoint: ENDPOINT, fetchImpl, tmpdir: tmpRoot }),
    refusedWith(NEVER_SHIP_REFUSALS.helper),
  );
  // A test-only record with the production endpoint.
  assert.throws(
    () => createLocalAdapterServer({ assetDir: outDir, endpoint: ADAPTER_DEFAULT_ENDPOINT, testOnlyBuild: record, fetchImpl, tmpdir: tmpRoot }),
    refusedWith(NEVER_SHIP_REFUSALS.endpoint),
  );
  // The gate itself, with production pins.
  const helperBytes = await readFile(join(outDir, "clockchain-agent-handshake.cjs"));
  const prodRootPin = { ...pin, hostRoots: [{ kid: "tb-test-root-2026-10", fingerprint: PRODUCTION_HOST_ROOT_FINGERPRINTS[0] }] };
  assert.throws(() => gateNeverShip({ helperBytes, pin: prodRootPin, endpoint: ENDPOINT, testOnlyBuild: record }), refusedWith(NEVER_SHIP_REFUSALS.productionRoot));
  const prodManifestPin = { ...pin, manifestDigest: PRODUCTION_MANIFEST_DIGESTS[0] };
  assert.throws(
    () => gateNeverShip({ helperBytes, pin: prodManifestPin, endpoint: ENDPOINT, testOnlyBuild: { ...record, manifestDigest: PRODUCTION_MANIFEST_DIGESTS[0] } }),
    refusedWith(NEVER_SHIP_REFUSALS.productionPin),
  );
  // A release helper (no marker) under a test-only record.
  assert.throws(() => gateNeverShip({ helperBytes: Buffer.from("release helper"), pin, endpoint: ENDPOINT, testOnlyBuild: record }), refusedWith(NEVER_SHIP_REFUSALS.helper));
  // A record that is not test-only.
  assert.throws(() => gateNeverShip({ helperBytes, pin, endpoint: ENDPOINT, testOnlyBuild: { ...record, neverShip: false } }), refusedWith(NEVER_SHIP_REFUSALS.record));
  // The release configuration still passes the gate.
  assert.equal(gateNeverShip({ helperBytes: Buffer.from("release helper"), pin: PIN, endpoint: ADAPTER_DEFAULT_ENDPOINT, testOnlyBuild: undefined }), false);
});

test("the test-only stdio entry exits 87 when the build record names a production endpoint or root", async (t) => {
  const { outDir } = await builtOnce();
  const base = await scratch(t, "tb-test-only-bin-");
  const run = (buildDir) => execFileAsync(process.execPath, [join(ROOT, "bin/clockchain-local-adapter-test-only.mjs")], {
    encoding: "utf8",
    env: { PATH: process.env.PATH, HOME: process.env.HOME, TMPDIR: base, CLOCKCHAIN_TEST_ONLY_BUILD_DIR: buildDir },
    timeout: 20_000,
  }).then(() => ({ code: 0, stderr: "" }), (error) => ({ code: error.code, stderr: error.stderr }));
  const tamper = async (name, change) => {
    const dir = join(base, name);
    await cp(outDir, dir, { recursive: true });
    const path = join(dir, "test-only-build.json");
    await writeFile(path, JSON.stringify(change(JSON.parse(await readFile(path, "utf8")))), { mode: 0o600 });
    return dir;
  };
  for (const [name, change, code] of [
    ["endpoint", (r) => ({ ...r, endpoint: ADAPTER_DEFAULT_ENDPOINT }), "TEST_ONLY_NON_LOOPBACK_ENDPOINT"],
    ["root", (r) => ({ ...r, hostRoots: [{ kid: PRODUCTION_HOST_ROOT_KIDS[0], fingerprint: PRODUCTION_HOST_ROOT_FINGERPRINTS[0] }] }), "TEST_ONLY_PRODUCTION_ROOT"],
    ["ship", (r) => ({ ...r, neverShip: false }), "TEST_ONLY_BUILD_RECORD_INVALID"],
  ]) {
    const outcome = await run(await tamper(name, change));
    assert.equal(outcome.code, 87, name);
    assert.equal(JSON.parse(outcome.stderr).error, code, name);
  }
  const missing = await run(join(base, "absent"));
  assert.equal(missing.code, 87);
});

test("release bundles never contain src/test-only/ (helper audit)", () => {
  const metafile = (extra) => ({
    inputs: Object.fromEntries(["node_modules/viem/_esm/index.js", "src/agent-cli/main.mjs", ...extra].map((key) => [key, {}])),
    outputs: { "out.cjs": { entryPoint: "bin/clockchain-agent-handshake.mjs", imports: [] } },
  });
  assert.equal(auditAgentHandshakeBundle(metafile([])).entryPoints, 1);
  assert.throws(() => auditAgentHandshakeBundle(metafile(["src/test-only/helper.mjs"])));
});
