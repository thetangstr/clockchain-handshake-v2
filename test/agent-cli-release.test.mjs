import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import test from "node:test";

import {
  agentHandshakeReleaseManifestDigest,
  validateAgentHandshakeReleaseManifest,
} from "../scripts/verify-agent-handshake-release.mjs";

const prefix = "https://github.com/thetangstr/clockchain-handshake-v2/releases/download/v2.1.0/";
const sourceCommit = "a".repeat(40);
const bytes = Buffer.from("asset");
const sha256 = createHash("sha256").update(bytes).digest("hex");

function asset(platform, arch, nativeSignature, upstreamSupport = "node_sea_supported") {
  const filename = `clockchain-agent-handshake-${platform}-${arch}${platform === "win32" ? ".exe" : ""}`;
  return {
    platform,
    arch,
    upstreamSupport,
    filename,
    url: prefix + filename,
    byteLength: String(bytes.length),
    sha256,
    nativeSignature,
    execution: {
      verified: true,
      platform,
      arch,
      exitCode: "0",
      publicOutputSha256: "b".repeat(64),
    },
  };
}

function manifest() {
  const unsigned = {
    schema: "clockchain.agent-handshake-release-manifest/v1",
    version: "2.1.0",
    sourceCommit,
    nodeRuntime: "24.6.0",
    assets: [
      asset("darwin", "arm64", { type: "codesign", verified: true, signer: "Developer ID Application", timestamp: "2026-08-10T00:00:00.000Z", notarized: true }),
      asset("darwin", "x64", { type: "codesign", verified: true, signer: "Developer ID Application", timestamp: "2026-08-10T00:00:00.000Z", notarized: true }, "clockchain_verified"),
      asset("linux", "arm64", { type: "none", verified: true, signer: null, timestamp: null, notarized: null }),
      asset("linux", "x64", { type: "none", verified: true, signer: null, timestamp: null, notarized: null }),
      asset("win32", "x64", { type: "authenticode", verified: true, signer: "Clockchain", timestamp: "2026-08-10T00:00:00.000Z", notarized: null }),
    ],
  };
  return { ...unsigned, manifestDigest: agentHandshakeReleaseManifestDigest(unsigned) };
}

test("accepts the exact five-platform release record and independently recomputes every byte hash", () => {
  const value = manifest();
  assert.deepEqual(validateAgentHandshakeReleaseManifest(value, {
    allowedAssetPrefix: prefix,
    bytesByUrl: new Map(value.assets.map((entry) => [entry.url, bytes])),
    expectedSourceCommit: sourceCommit,
  }), value);
});

test("rejects unknown keys, duplicates, redirects, digest drift, unsigned native assets, and false Intel claims", () => {
  const base = manifest();
  const mutations = [
    { ...base, extra: true },
    { ...base, sourceCommit: "b".repeat(40) },
    { ...base, manifestDigest: "c".repeat(64) },
    { ...base, assets: [...base.assets, base.assets[0]] },
    { ...base, assets: base.assets.map((entry, index) => index === 0 ? { ...entry, url: "https://example.invalid/a" } : entry) },
    { ...base, assets: base.assets.map((entry, index) => index === 0 ? { ...entry, nativeSignature: { ...entry.nativeSignature, verified: false } } : entry) },
    { ...base, assets: base.assets.map((entry, index) => index === 0 ? { ...entry, nativeSignature: { ...entry.nativeSignature, notarized: false } } : entry) },
    { ...base, assets: base.assets.map((entry, index) => index === 2 ? { ...entry, nativeSignature: { ...entry.nativeSignature, notarized: true } } : entry) },
    { ...base, assets: base.assets.map((entry, index) => index === 1 ? { ...entry, upstreamSupport: "node_sea_supported" } : entry) },
  ];
  for (const value of mutations) assert.throws(() => validateAgentHandshakeReleaseManifest(value, {
    allowedAssetPrefix: prefix,
    bytesByUrl: new Map(base.assets.map((entry) => [entry.url, bytes])),
    expectedSourceCommit: sourceCommit,
  }));
});

test("release workflow pins Node, builders, matching runners, native signing, provenance, and the Intel gate", async () => {
  const workflow = await readFile(new URL("../.github/workflows/agent-handshake-cli-release.yml", import.meta.url), "utf8");
  const packageLock = JSON.parse(await readFile(new URL("../package-lock.json", import.meta.url), "utf8"));
  for (const required of [
    "24.18.0", "ubuntu-24.04", "ubuntu-24.04-arm", "macos-15", "windows-2025",
    "macos-15-intel", "MAC_CERTIFICATE_P12", "codesign", "notarytool submit", "spctl --assess",
    "APPLE_NOTARY_KEY_P8", "APPLE_NOTARY_KEY_ID", "APPLE_NOTARY_ISSUER_ID",
    "signtool", "npm publish --provenance",
    "build-agent-handshake-release.mjs sea",
  ]) assert.ok(workflow.includes(required), required);
  assert.equal(workflow.includes("self-hosted"), false);
  assert.equal(workflow.includes("clockchain-intel-release"), false);
  assert.equal(workflow.match(/security import/g)?.length, 2);
  assert.equal(workflow.match(/security set-key-partition-list/g)?.length, 2);
  assert.equal(workflow.match(/security list-keychains/g)?.length, 2);
  assert.equal(workflow.match(/test "\$\(uname -m\)" = "x86_64"/g)?.length, 1);
  assert.ok(workflow.includes("node -p 'process.arch'"));
  assert.ok(workflow.includes("node -p 'process.platform'"));
  assert.equal(packageLock.packages["node_modules/esbuild"].version, "0.28.2");
  assert.equal(packageLock.packages["node_modules/esbuild"].integrity, "sha512-HKVLS8dvII+xoKW9kmqxbRKrnWEXfJJr/FZhhJmiqIB0e053QNYFqOBouTMO/k5sID4MvCiUCvv8b9M4h32wIA==");
  assert.equal(packageLock.packages["node_modules/postject"].version, "1.0.0-alpha.6");
  assert.equal(packageLock.packages["node_modules/postject"].integrity, "sha512-b9Eb8h2eVqNE8edvKdwqkrY6O7kAwmI8kcnBv1NScolYJbo59XUF0noFq+lxbC1yN20bmC0WBEbDC5H/7ASb0A==");
  const buildSource = await readFile(new URL("../scripts/build-agent-handshake-release.mjs", import.meta.url), "utf8");
  assert.ok(buildSource.includes("useSnapshot: false"));
  assert.ok(buildSource.includes("useCodeCache: false"));
});
