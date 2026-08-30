import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import {
  getHandshakeV3Contract,
  getHandshakeV3ToolDescriptor,
  listHandshakeV3Tools,
  prepareHandshakeV3Signing,
  validateHandshakeV3CliResultShape,
  validateHandshakeV3SdkToolInput,
  validateHandshakeV3SdkToolResult,
  verifyHandshakeV3SdkCertificate,
  verifyHandshakeV3SdkContinuation,
} from "@clockchain/handshake-sdk";
import {
  handshakeV3CertificateSignedProjection as protocolCertificateProjection,
  handshakeV3Digest as protocolDigest,
} from "@clockchain/handshake-protocol/v3";

const digestA = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const digestB = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const digestC = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

function certificate() {
  const unsigned = {
    certificateId: "cert_sdk_0123456789",
    sessionId: "sess_sdk_0123456789",
    certificateDigest: digestA,
    policyDigest: digestA,
    partyDigests: [digestB, digestC],
    clockchainNetwork: "sepolia",
    trustRootId: "root-2026-08",
    issuedAt: "2026-08-29T20:00:00Z",
    expiresAt: "2026-08-29T21:00:00Z",
    issuerSignature: "s".repeat(32),
  };
  return {
    ...unsigned,
    certificateDigest: protocolDigest(protocolCertificateProjection(unsigned)),
  };
}

async function withTempDir(fn) {
  const directory = await mkdtemp(join(tmpdir(), "handshake-sdk-test-"));
  try {
    return await fn(directory);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
}

test("SDK exposes immutable contract and tool discovery metadata from protocol v3", () => {
  const contract = getHandshakeV3Contract();
  const tools = listHandshakeV3Tools();
  const descriptor = getHandshakeV3ToolDescriptor("agent_handshake_session_join");

  assert.equal(contract.protocolVersion, "3.0");
  assert.equal(contract.schemaVersion, "3.0.0-draft.2");
  assert.equal(Object.isFrozen(contract), true);
  assert.equal(tools.includes("agent_handshake_result_verify"), true);
  assert.equal(descriptor.name, "agent_handshake_session_join");
  assert.equal(Object.isFrozen(descriptor.inputSchema), true);
  assert.throws(() => getHandshakeV3ToolDescriptor("agent_handshake_business_action"), { code: "SCHEMA_INVALID" });
});

test("SDK validates tool inputs and results without network, persistence, or authority side effects", () => {
  assert.equal(validateHandshakeV3SdkToolInput("agent_handshake_session_get_result", {
    sessionId: "sess_sdk_0123456789",
  }).tool, "agent_handshake_session_get_result");

  const result = validateHandshakeV3SdkToolResult("agent_handshake_session_cancel", {
    sessionId: "sess_sdk_0123456789",
    state: "CANCELLED",
  });
  assert.equal(result.state, "CANCELLED");

  assert.throws(() => validateHandshakeV3SdkToolInput("agent_handshake_session_get_result", {
    sessionId: "sess_sdk_0123456789",
    businessContent: "pay now",
  }), { code: "SCHEMA_INVALID" });
});

test("SDK prepares typed signing bytes and digest but never signs", () => {
  const prepared = prepareHandshakeV3Signing({
    signingRequestId: "signreq_sdk_0123456789",
    actionType: "PROPOSAL",
    sessionId: "sess_sdk_0123456789",
    stateVersion: 1,
    role: "INITIATOR",
    policyDigest: digestA,
    statementDigest: digestB,
    nonce: "nonce_sdk_0123456789",
    issuedAt: "2026-08-29T20:00:00Z",
    expiresAt: "2026-08-29T20:05:00Z",
  });

  assert.equal(prepared.request.signingRequestId, "signreq_sdk_0123456789");
  assert.equal(prepared.externalBusinessActionPerformed, false);
  assert.equal(prepared.signature, undefined);
  assert.equal(prepared.privateKey, undefined);
  assert.equal(JSON.parse(Buffer.from(prepared.bytesBase64Url, "base64url").toString("utf8")).role, "INITIATOR");
});

test("SDK certificate and continuation verification require caller-supplied adapters", async () => {
  await assert.rejects(() => verifyHandshakeV3SdkCertificate({
    certificate: certificate(),
    now: "2026-08-29T20:01:00Z",
  }), { code: "RESULT_VERIFICATION_FAILED" });

  await assert.rejects(() => verifyHandshakeV3SdkContinuation({
    certificate: certificate(),
    continuation: {},
    now: "2026-08-29T20:01:00Z",
    verifyIssuerSignature: async () => true,
    getRevocationStatus: async () => "GOOD",
  }), { code: "RESULT_VERIFICATION_FAILED" });
});

test("SDK verification adapter callbacks are explicit and receive the signed digest", async () => {
  const cert = certificate();
  let signedDigestSeen;
  const result = await verifyHandshakeV3SdkCertificate({
    certificate: cert,
    expectedPolicyDigest: digestA,
    now: "2026-08-29T20:01:00Z",
    verifyIssuerSignature: async ({ signedDigest }) => {
      signedDigestSeen = signedDigest;
      return true;
    },
    getRevocationStatus: async (handle) => handle === cert.certificateId ? "GOOD" : "REVOKED",
  });

  assert.equal(result.certificateValid, true);
  assert.equal(signedDigestSeen, cert.certificateDigest);
});

test("SDK result-shape helper validates JSON CLI envelopes only", () => {
  const result = {};
  const value = validateHandshakeV3CliResultShape({
    ok: true,
    command: "contract",
    verificationMode: "explicit_fixture_only",
    clockchainTrustVerified: false,
    externalBusinessActionPerformed: false,
    result,
  });
  assert.equal(value.ok, true);
  assert.notEqual(value.result, result);
  assert.equal(Object.isFrozen(value), true);
  assert.equal(Object.isFrozen(value.result), true);
  result.mutatedAfterValidation = true;
  assert.equal(value.result.mutatedAfterValidation, undefined);

  assert.throws(() => validateHandshakeV3CliResultShape({
    ok: true,
    command: "contract",
    verificationMode: "explicit_fixture_only",
    clockchainTrustVerified: false,
    externalBusinessActionPerformed: true,
    result: {},
  }), { code: "SCHEMA_INVALID" });
  assert.throws(() => validateHandshakeV3CliResultShape({
    ok: true,
    command: "contract",
    externalBusinessActionPerformed: false,
    result: {},
  }), { code: "SCHEMA_INVALID" });
});

test("SDK result-shape helper fails closed on hostile envelope objects", () => {
  const value = validateHandshakeV3CliResultShape({
    ok: true,
    command: "contract",
    verificationMode: "explicit_fixture_only",
    clockchainTrustVerified: false,
    externalBusinessActionPerformed: false,
    result: {
      protocolVersion: "3.0",
    },
  });
  assert.equal(value.ok, true);
  const accessor = {};
  Object.defineProperty(accessor, "ok", {
    enumerable: true,
    get() {
      throw new Error("raw getter detail");
    },
  });
  assert.throws(() => validateHandshakeV3CliResultShape(accessor), { code: "SCHEMA_INVALID" });

  const proxy = new Proxy({}, {
    ownKeys() {
      throw new Error("raw ownKeys detail");
    },
  });
  assert.throws(() => validateHandshakeV3CliResultShape(proxy), { code: "SCHEMA_INVALID" });

  const descriptorTrap = new Proxy({ ok: true }, {
    getOwnPropertyDescriptor() {
      throw new Error("raw descriptor detail");
    },
  });
  assert.throws(() => validateHandshakeV3CliResultShape(descriptorTrap), { code: "SCHEMA_INVALID" });

  const prototypeTrap = new Proxy({}, {
    getPrototypeOf() {
      throw new Error("raw prototype detail");
    },
  });
  assert.throws(() => validateHandshakeV3CliResultShape(prototypeTrap), { code: "SCHEMA_INVALID" });

  assert.throws(() => validateHandshakeV3CliResultShape({ [Symbol("secret")]: true }), { code: "SCHEMA_INVALID" });
  assert.throws(() => validateHandshakeV3CliResultShape(Object.assign([], { ok: true })), { code: "SCHEMA_INVALID" });

  const cycle = {
    ok: true,
    command: "contract",
    verificationMode: "explicit_fixture_only",
    clockchainTrustVerified: false,
    externalBusinessActionPerformed: false,
    result: {},
  };
  cycle.result.self = cycle;
  assert.throws(() => validateHandshakeV3CliResultShape(cycle), { code: "SCHEMA_INVALID" });
});

test("SDK package dry-run includes source and tests without server or runtime files", async () => {
  await withTempDir(async () => {
    const { execFile } = await import("node:child_process");
    const { promisify } = await import("node:util");
    const execFileAsync = promisify(execFile);
    const packageRoot = new URL("..", import.meta.url);
    const { stdout } = await execFileAsync("npm", ["pack", "--dry-run", "--json"], {
      cwd: packageRoot,
      maxBuffer: 1024 * 1024,
    });
    const [pack] = JSON.parse(stdout);
    const files = new Set(pack.files.map((entry) => entry.path));
    assert.equal(files.has("src/index.mjs"), true);
    assert.equal([...files].some((file) => /server|supervisor|wallet|relay/i.test(file)), false);
  });
});
