import assert from "node:assert/strict";
import { execFile as execFileCallback } from "node:child_process";
import { generateKeyPairSync } from "node:crypto";
import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import test from "node:test";
import { promisify } from "node:util";
import { fileURLToPath } from "node:url";

import { digestHex } from "../src/core/canonical.mjs";
import { buildSignedResult } from "../src/core/result.mjs";

const execFile = promisify(execFileCallback);
const ROOT = resolve(join(fileURLToPath(new URL(".", import.meta.url)), ".."));
const SESSION_ID = "00000000-0000-4000-8000-000000000000";

function envelope({ outcome = "AUTHORIZED", sessionId = SESSION_ID } = {}) {
  const { privateKey } = generateKeyPairSync("ed25519");
  return buildSignedResult({
    issuedAtMs: "1785802329000",
    keyId: "test-host",
    parties: {
      payer: { address: "0x" + "a".repeat(40), agentId: "9400", reference: "eip155:11155111:0x8004a818bfb912233c491871b3d84c89a494bd9e:9400" },
      payee: { address: "0x" + "b".repeat(40), agentId: "9401", reference: "eip155:11155111:0x8004a818bfb912233c491871b3d84c89a494bd9e:9401" },
    },
    privateKeyPem: privateKey.export({ format: "pem", type: "pkcs8" }),
    sessionDigest: "d".repeat(64),
    sessionId,
    verdict: {
      outcome, paymentMoved: false,
      transitions: [
        { blockHeight: "1", blockTimeRaw: "2026-08-04T01:15:57.916Z", digest: "a".repeat(64), kind: "proposal", ledgerId: "11111111-1111-4111-8111-111111111111" },
        { blockHeight: "2", blockTimeRaw: "2026-08-04T01:16:19.233Z", digest: "b".repeat(64), kind: "acceptance", ledgerId: "22222222-2222-4222-8222-222222222222" },
        { blockHeight: "3", blockTimeRaw: "2026-08-04T01:16:41.735Z", digest: "c".repeat(64), kind: "acknowledgment", ledgerId: "33333333-3333-4333-8333-333333333333" },
      ],
    },
  });
}

async function proof(t, value, role, {
  expectedPublicKey = value?.signer?.publicKey,
  sessionId = SESSION_ID,
} = {}) {
  const directory = await mkdtemp(join(tmpdir(), "certificate-proof-"));
  t.after(() => import("node:fs/promises").then(({ rm }) => rm(directory, { recursive: true, force: true })));
  const file = join(directory, "certificate.json");
  await writeFile(file, JSON.stringify(value));
  return execFile(process.execPath, [
    "bin/certificate-proof.mjs", "verify", "--file", file, "--role", role,
    "--expected-public-key", expectedPublicKey, "--session-id", sessionId,
  ], { cwd: ROOT });
}

test("certificate proof emits the exact public payer terminal object", async (t) => {
  const signed = envelope();
  const { stdout, stderr } = await proof(t, signed, "payer");
  assert.equal(stderr, "");
  assert.deepEqual(JSON.parse(stdout), {
    role: "payer", sessionId: SESSION_ID, address: "0x" + "a".repeat(40), agentId: "9400",
    certificateDigest: digestHex(signed.result), certificateVerified: true, paymentMoved: false,
  });
  assert.equal(stdout.trim().split("\n").length, 1);
});

test("certificate proof selects the payee party for requestor", async (t) => {
  const signed = envelope();
  const { stdout } = await proof(t, signed, "requestor");
  assert.deepEqual(JSON.parse(stdout), {
    role: "requestor", sessionId: SESSION_ID, address: "0x" + "b".repeat(40), agentId: "9401",
    certificateDigest: digestHex(signed.result), certificateVerified: true, paymentMoved: false,
  });
});

for (const [name, mutate, role] of [
  ["malformed", () => ({ certificate: "not an envelope" }), "payer"],
  ["tampered", (signed) => ({ ...signed, result: { ...signed.result, outcome: "REFUSED" } }), "payer"],
  ["payment moved", (signed) => ({ ...signed, result: { ...signed.result, paymentMoved: true } }), "payer"],
  ["wrong role", (signed) => signed, "toString"],
]) {
  test(`certificate proof fails closed for ${name} input`, async (t) => {
    await assert.rejects(proof(t, mutate(envelope()), role), (error) => {
      assert.equal(error.code, 1);
      assert.equal(error.stdout, "");
      assert.equal(error.stderr, "Certificate proof failed.\n");
      return true;
    });
  });
}

test("certificate proof rejects a valid envelope signed by a foreign key", async (t) => {
  const signed = envelope();
  const foreignKey = envelope().signer.publicKey;
  await assert.rejects(proof(t, signed, "payer", { expectedPublicKey: foreignKey }), (error) => {
    assert.equal(error.code, 1);
    assert.equal(error.stderr, "Certificate proof failed.\n");
    return true;
  });
});

test("certificate proof rejects a certificate for another session", async (t) => {
  const signed = envelope();
  await assert.rejects(
    proof(t, signed, "payer", { sessionId: "11111111-1111-4111-8111-111111111111" }),
    (error) => error.code === 1 && error.stdout === "" && error.stderr === "Certificate proof failed.\n",
  );
});

test("certificate proof rejects a genuinely signed negative outcome", async (t) => {
  const signed = envelope({ outcome: "EXPIRED" });
  await assert.rejects(
    proof(t, signed, "payer"),
    (error) => error.code === 1 && error.stdout === "" && error.stderr === "Certificate proof failed.\n",
  );
});

test("certificate proof requires both trust-root flags", async (t) => {
  const signed = envelope();
  const directory = await mkdtemp(join(tmpdir(), "certificate-proof-flags-"));
  t.after(() => import("node:fs/promises").then(({ rm }) => rm(directory, { recursive: true, force: true })));
  const file = join(directory, "certificate.json");
  await writeFile(file, JSON.stringify(signed));
  await assert.rejects(
    execFile(process.execPath, ["bin/certificate-proof.mjs", "verify", "--file", file, "--role", "payer"], { cwd: ROOT }),
    (error) => error.code === 1 && error.stderr === "Certificate proof failed.\n",
  );
});
