import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdir, mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import test from "node:test";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);
const repoRoot = new URL("..", import.meta.url);
const nodePath = process.execPath;

async function npm(args, cwd) {
  return execFileAsync("npm", args, {
    cwd,
    env: { ...process.env, PATH: `/opt/homebrew/opt/node@24/bin:${process.env.PATH ?? ""}` },
    maxBuffer: 1024 * 1024,
  });
}

async function packPackage(packagePath, destination) {
  const { stdout } = await npm(["pack", resolve(repoRoot.pathname, packagePath), "--pack-destination", destination, "--json"], repoRoot.pathname);
  const [pack] = JSON.parse(stdout);
  return join(destination, pack.filename);
}

test("standalone packages import and run from installed tarballs without repo-relative paths", async () => {
  const tempRoot = await mkdtemp(join(tmpdir(), "handshake-standalone-packages-"));
  try {
    const tarballDir = join(tempRoot, "tarballs");
    const installDir = join(tempRoot, "install");
    await mkdir(tarballDir);
    await mkdir(installDir);

    const protocolTarball = await packPackage("packages/protocol", tarballDir);
    const sdkTarball = await packPackage("packages/sdk", tarballDir);
    const cliTarball = await packPackage("packages/cli", tarballDir);

    await npm(["init", "-y"], installDir);
    await npm(["install", "--ignore-scripts", "--no-package-lock", protocolTarball, sdkTarball, cliTarball], installDir);

    const sdkProbe = `
      import { getHandshakeV3Contract, prepareHandshakeV3Signing } from "@clockchain/handshake-sdk";
      const digestA = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
      const digestB = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
      const contract = getHandshakeV3Contract();
      const prepared = prepareHandshakeV3Signing({
        signingRequestId: "signreq_pack_0123456789",
        actionType: "PROPOSAL",
        sessionId: "sess_pack_0123456789",
        stateVersion: 1,
        role: "INITIATOR",
        policyDigest: digestA,
        statementDigest: digestB,
        nonce: "nonce_pack_0123456789",
        issuedAt: "2026-08-29T20:00:00Z",
        expiresAt: "2026-08-29T20:05:00Z"
      });
      console.log(JSON.stringify({
        protocolVersion: contract.protocolVersion,
        digest: prepared.signingDigest,
        externalBusinessActionPerformed: prepared.externalBusinessActionPerformed
      }));
    `;
    const { stdout: sdkStdout } = await execFileAsync(nodePath, ["--input-type=module", "--eval", sdkProbe], {
      cwd: installDir,
      maxBuffer: 1024 * 1024,
    });
    const sdk = JSON.parse(sdkStdout);
    assert.equal(sdk.protocolVersion, "3.0");
    assert.match(sdk.digest, /^sha256:[0-9a-f]{64}$/);
    assert.equal(sdk.externalBusinessActionPerformed, false);

    const cliPath = join(installDir, "node_modules", ".bin", "clockchain-handshake");
    const { stdout: cliStdout, stderr: cliStderr } = await execFileAsync(cliPath, ["contract"], {
      cwd: installDir,
      maxBuffer: 1024 * 1024,
    });
    assert.equal(cliStderr, "");
    const cli = JSON.parse(cliStdout);
    assert.equal(cli.ok, true);
    assert.equal(cli.result.protocolVersion, "3.0");
    assert.equal(cli.externalBusinessActionPerformed, false);

    const sdkManifest = JSON.parse(await readFile(join(installDir, "node_modules", "@clockchain", "handshake-sdk", "package.json"), "utf8"));
    const cliManifest = JSON.parse(await readFile(join(installDir, "node_modules", "@clockchain", "handshake-cli", "package.json"), "utf8"));
    assert.equal(sdkManifest.dependencies["@clockchain/handshake-protocol"], "0.1.0");
    assert.equal(cliManifest.dependencies["@clockchain/handshake-sdk"], "0.1.0");
    assert.equal(cliManifest.dependencies["@clockchain/handshake-protocol"], "0.1.0");
  } finally {
    await rm(tempRoot, { recursive: true, force: true });
  }
});

test("protocol tarball installs alone with exported v3 protocol truth", async () => {
  const tempRoot = await mkdtemp(join(tmpdir(), "handshake-protocol-alone-"));
  try {
    const tarballDir = join(tempRoot, "tarballs");
    const installDir = join(tempRoot, "install");
    await mkdir(tarballDir);
    await mkdir(installDir);

    const protocolTarball = await packPackage("packages/protocol", tarballDir);
    await npm(["init", "-y"], installDir);
    await npm(["install", "--ignore-scripts", "--no-package-lock", protocolTarball], installDir);

    const probe = `
      import { HANDSHAKE_V3_PROTOCOL_VERSION, createHandshakeV3SigningRequest } from "@clockchain/handshake-protocol/v3";
      const digestA = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
      const digestB = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
      const request = createHandshakeV3SigningRequest({
        signingRequestId: "signreq_protocol_012345",
        actionType: "PROPOSAL",
        sessionId: "sess_protocol_012345",
        stateVersion: 1,
        role: "INITIATOR",
        policyDigest: digestA,
        statementDigest: digestB,
        nonce: "nonce_protocol_012345",
        issuedAt: "2026-08-29T20:00:00Z",
        expiresAt: "2026-08-29T20:05:00Z"
      });
      console.log(JSON.stringify({ protocolVersion: HANDSHAKE_V3_PROTOCOL_VERSION, digest: request.signingDigest }));
    `;
    const { stdout } = await execFileAsync(nodePath, ["--input-type=module", "--eval", probe], {
      cwd: installDir,
      maxBuffer: 1024 * 1024,
    });
    const output = JSON.parse(stdout);
    assert.equal(output.protocolVersion, "3.0");
    assert.match(output.digest, /^sha256:[0-9a-f]{64}$/);
  } finally {
    await rm(tempRoot, { recursive: true, force: true });
  }
});

test("SDK tarball installs with protocol tarball and exact package pin", async () => {
  const tempRoot = await mkdtemp(join(tmpdir(), "handshake-sdk-with-protocol-"));
  try {
    const tarballDir = join(tempRoot, "tarballs");
    const installDir = join(tempRoot, "install");
    await mkdir(tarballDir);
    await mkdir(installDir);

    const protocolTarball = await packPackage("packages/protocol", tarballDir);
    const sdkTarball = await packPackage("packages/sdk", tarballDir);
    await npm(["init", "-y"], installDir);
    await npm(["install", "--ignore-scripts", "--no-package-lock", protocolTarball, sdkTarball], installDir);

    const probe = `
      import { getHandshakeV3Contract } from "@clockchain/handshake-sdk";
      console.log(JSON.stringify(getHandshakeV3Contract().protocolVersion));
    `;
    const { stdout } = await execFileAsync(nodePath, ["--input-type=module", "--eval", probe], {
      cwd: installDir,
      maxBuffer: 1024 * 1024,
    });
    assert.equal(JSON.parse(stdout), "3.0");

    const sdkManifest = JSON.parse(await readFile(join(installDir, "node_modules", "@clockchain", "handshake-sdk", "package.json"), "utf8"));
    assert.equal(sdkManifest.dependencies["@clockchain/handshake-protocol"], "0.1.0");
  } finally {
    await rm(tempRoot, { recursive: true, force: true });
  }
});

test("CLI tarball installs with exact SDK and protocol tarballs and fixture-only output markers", async () => {
  const tempRoot = await mkdtemp(join(tmpdir(), "handshake-cli-with-stack-"));
  try {
    const tarballDir = join(tempRoot, "tarballs");
    const installDir = join(tempRoot, "install");
    await mkdir(tarballDir);
    await mkdir(installDir);

    const protocolTarball = await packPackage("packages/protocol", tarballDir);
    const sdkTarball = await packPackage("packages/sdk", tarballDir);
    const cliTarball = await packPackage("packages/cli", tarballDir);
    await npm(["init", "-y"], installDir);
    await npm(["install", "--ignore-scripts", "--no-package-lock", protocolTarball, sdkTarball, cliTarball], installDir);

    const cliPath = join(installDir, "node_modules", ".bin", "clockchain-handshake");
    const { stdout, stderr } = await execFileAsync(cliPath, ["contract"], {
      cwd: installDir,
      maxBuffer: 1024 * 1024,
    });
    assert.equal(stderr, "");
    const output = JSON.parse(stdout);
    assert.equal(output.ok, true);
    assert.equal(output.verificationMode, "explicit_fixture_only");
    assert.equal(output.clockchainTrustVerified, false);
    assert.equal(output.externalBusinessActionPerformed, false);

    const cliManifest = JSON.parse(await readFile(join(installDir, "node_modules", "@clockchain", "handshake-cli", "package.json"), "utf8"));
    assert.equal(cliManifest.dependencies["@clockchain/handshake-sdk"], "0.1.0");
    assert.equal(cliManifest.dependencies["@clockchain/handshake-protocol"], "0.1.0");
  } finally {
    await rm(tempRoot, { recursive: true, force: true });
  }
});
