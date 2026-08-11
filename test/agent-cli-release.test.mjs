import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import test from "node:test";

import {
  agentHandshakeReleaseManifestDigest,
  assembleAgentHandshakeReleaseManifest,
  validateAgentHandshakeReleasePin,
  validateAgentHandshakeReleaseManifest,
} from "../scripts/verify-agent-handshake-release.mjs";
import { canonicalBytes } from "../src/core/canonical.mjs";

const prefix = "https://github.com/thetangstr/clockchain-handshake-v2/releases/download/v2.1.2/";
const sourceCommit = "a".repeat(40);
const bytes = Buffer.from("asset");
const sha256 = createHash("sha256").update(bytes).digest("hex");

function asset() {
  const filename = "clockchain-agent-handshake.cjs";
  return {
    platform: "node",
    arch: "any",
    upstreamSupport: "node24_portable",
    filename,
    url: prefix + filename,
    byteLength: String(bytes.length),
    sha256,
    nativeSignature: { type: "none", verified: true, signer: null, timestamp: null, notarized: null },
    execution: {
      verified: true,
      platform: "linux",
      arch: "x64",
      exitCode: "0",
      publicOutputSha256: "b".repeat(64),
    },
  };
}

function manifest() {
  return {
    schema: "clockchain.agent-handshake-release-manifest/v1",
    version: "2.1.2",
    sourceCommit,
    nodeRuntime: "24.6.0",
    assets: [asset()],
  };
}

test("accepts the exact portable helper release and independently recomputes its bytes", () => {
  const value = manifest();
  assert.deepEqual(validateAgentHandshakeReleaseManifest(value, {
    allowedAssetPrefix: prefix,
    bytesByUrl: new Map(value.assets.map((entry) => [entry.url, bytes])),
    expectedSourceCommit: sourceCommit,
  }), value);
});

test("pins the sha256 of the exact published canonical manifest bytes", () => {
  const value = manifest();
  const publishedBytes = canonicalBytes(value);
  assert.equal(
    agentHandshakeReleaseManifestDigest(value),
    createHash("sha256").update(publishedBytes).digest("hex"),
  );
  assert.deepEqual(assembleAgentHandshakeReleaseManifest({
    assets: value.assets,
    bytesByUrl: new Map(value.assets.map((entry) => [entry.url, bytes])),
    nodeRuntime: value.nodeRuntime,
    sourceCommit: value.sourceCommit,
  }), value);
});

test("binds the post-release pin to exact manifest bytes, helper bytes, and host roots", () => {
  const value = manifest();
  const manifestBytes = canonicalBytes(value);
  const pin = {
    version: "2.1.2",
    sourceCommit,
    manifestDigest: createHash("sha256").update(manifestBytes).digest("hex"),
    allowedAssetPrefix: prefix,
    hostRoots: [{ kid: "root-2026-08", fingerprint: "c".repeat(64) }],
  };
  assert.deepEqual(validateAgentHandshakeReleasePin(pin, { manifestBytes, helperBytes: bytes }), pin);
  for (const mutation of [
    { ...pin, manifestDigest: "d".repeat(64) },
    { ...pin, sourceCommit: "b".repeat(40) },
    { ...pin, hostRoots: [] },
    { ...pin, hostRoots: [{ ...pin.hostRoots[0], fingerprint: "not-a-digest" }] },
    { ...pin, hostRoots: [{ ...pin.hostRoots[0], kid: 123 }] },
    { ...pin, hostRoots: [{ ...pin.hostRoots[0], kid: {} }] },
    { ...pin, hostRoots: [{ ...pin.hostRoots[0], fingerprint: 456 }] },
    { ...pin, hostRoots: [pin.hostRoots[0], { ...pin.hostRoots[0], fingerprint: "d".repeat(64) }] },
    { ...pin, hostRoots: [pin.hostRoots[0], { kid: "root-previous", fingerprint: pin.hostRoots[0].fingerprint }] },
    { ...pin, extra: true },
  ]) assert.throws(() => validateAgentHandshakeReleasePin(mutation, { manifestBytes, helperBytes: bytes }));
  assert.throws(() => validateAgentHandshakeReleasePin(pin, { manifestBytes, helperBytes: Buffer.from("tampered") }));
});

test("tracks the independently published helper in a separate post-release pin", async () => {
  const pin = JSON.parse(await readFile(new URL("../release/agent-handshake/pin.json", import.meta.url), "utf8"));
  assert.deepEqual(pin, {
    version: "2.1.1",
    sourceCommit: "8f74f6d953631cbac057426e3540ba73bf607f3b",
    manifestDigest: "681f61d4cde2537ec6953b134e8385e6a716c8d889db0f46fd566c10407c9402",
    allowedAssetPrefix: "https://github.com/thetangstr/clockchain-handshake-v2/releases/download/v2.1.1/",
    hostRoots: [{
      kid: "root-2026-08",
      fingerprint: "da2771c36bf2298525d2bbd8351b6122bb67115e9979624e8bb56537bcf71ed8",
    }],
  });
});

test("rejects unknown keys, duplicates, redirects, digest drift, and native executable substitutions", () => {
  const base = manifest();
  const mutations = [
    { ...base, extra: true },
    { ...base, sourceCommit: "b".repeat(40) },
    { ...base, nodeRuntime: "24.6.1", extraDigest: "c".repeat(64) },
    { ...base, assets: [...base.assets, base.assets[0]] },
    { ...base, assets: base.assets.map((entry, index) => index === 0 ? { ...entry, url: "https://example.invalid/a" } : entry) },
    { ...base, assets: base.assets.map((entry) => ({ ...entry, platform: "darwin", arch: "arm64" })) },
    { ...base, assets: base.assets.map((entry) => ({ ...entry, nativeSignature: { ...entry.nativeSignature, type: "codesign", signer: "unknown" } })) },
    { ...base, assets: base.assets.map((entry) => ({ ...entry, execution: { ...entry.execution, platform: "darwin" } })) },
    { ...base, assets: base.assets.map((entry) => ({ ...entry, upstreamSupport: "node_sea_supported" })) },
  ];
  for (const value of mutations) assert.throws(() => validateAgentHandshakeReleaseManifest(value, {
    allowedAssetPrefix: prefix,
    bytesByUrl: new Map(base.assets.map((entry) => [entry.url, bytes])),
    expectedSourceCommit: sourceCommit,
  }));
});

test("release workflow publishes only the portable helper without external signing or npm credentials", async () => {
  const workflow = await readFile(new URL("../.github/workflows/agent-handshake-cli-release.yml", import.meta.url), "utf8");
  const packageLock = JSON.parse(await readFile(new URL("../package-lock.json", import.meta.url), "utf8"));
  for (const required of [
    "24.18.0", "ubuntu-24.04", "build-agent-handshake-release.mjs bundle",
    "dist/clockchain-agent-handshake.cjs", "actions/attest-build-provenance@v2",
    "gh release create v2.1.2",
  ]) assert.ok(workflow.includes(required), required);
  assert.equal(workflow.includes("self-hosted"), false);
  for (const forbidden of [
    "workflow_dispatch",
    "preflight-secrets", "build-agent-handshake-release.mjs sea", "codesign", "notarytool",
    "signtool", "npm publish", "windows-2025", "macos-15", "macos-15-intel",
    "MAC_CERTIFICATE_P12", "MAC_CERTIFICATE_PASSWORD", "MAC_SIGNER_NAME",
    "APPLE_NOTARY_KEY_P8", "APPLE_NOTARY_KEY_ID", "APPLE_NOTARY_ISSUER_ID",
    "WINDOWS_CERTIFICATE_PFX", "WINDOWS_CERTIFICATE_PASSWORD", "NPM_TOKEN",
  ]) assert.equal(workflow.includes(forbidden), false, forbidden);
  assert.equal(packageLock.packages["node_modules/esbuild"].version, "0.28.2");
  assert.equal(packageLock.packages["node_modules/esbuild"].integrity, "sha512-HKVLS8dvII+xoKW9kmqxbRKrnWEXfJJr/FZhhJmiqIB0e053QNYFqOBouTMO/k5sID4MvCiUCvv8b9M4h32wIA==");
  assert.equal(packageLock.packages["node_modules/postject"].version, "1.0.0-alpha.6");
  assert.equal(packageLock.packages["node_modules/postject"].integrity, "sha512-b9Eb8h2eVqNE8edvKdwqkrY6O7kAwmI8kcnBv1NScolYJbo59XUF0noFq+lxbC1yN20bmC0WBEbDC5H/7ASb0A==");
  const buildSource = await readFile(new URL("../scripts/build-agent-handshake-release.mjs", import.meta.url), "utf8");
  assert.ok(buildSource.includes("useSnapshot: false"));
  assert.ok(buildSource.includes("useCodeCache: false"));
});
