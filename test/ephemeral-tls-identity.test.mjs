import assert from "node:assert/strict";
import { X509Certificate } from "node:crypto";
import { lstat, mkdir, mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { createEphemeralTlsIdentity } from "../src/testing/ephemeral-tls-identity.mjs";

test("ephemeral TLS identity creates a private P-256 certificate and destroys every file", async (t) => {
  const parent = await mkdtemp(join(tmpdir(), "clockchain-ephemeral-tls-"));
  const root = join(parent, "party");
  t.after(() => rm(parent, { recursive: true, force: true }));
  const identity = await createEphemeralTlsIdentity({
    hostname: "initiator.task.local",
    opensslPath: "/opt/homebrew/bin/openssl",
    root,
  });
  assert.equal(identity.schema, "clockchain.ephemeral-tls-identity/v1");
  assert.match(identity.certificateSha256, /^[0-9a-f]{64}$/);
  assert.match(identity.certificate, /BEGIN CERTIFICATE/);
  assert.match(identity.privateKey, /BEGIN PRIVATE KEY/);
  const cert = new X509Certificate(identity.certificate);
  assert.match(cert.subjectAltName, /DNS:initiator\.task\.local/);
  assert.equal(cert.publicKey.asymmetricKeyType, "ec");
  assert.equal((await lstat(identity.keyPath)).mode & 0o777, 0o600);
  assert.equal((await lstat(identity.certificatePath)).mode & 0o777, 0o600);
  assert.doesNotMatch(JSON.stringify(identity.publicEvidence()), /private|keyPath|certificatePath|BEGIN/i);
  await identity.destroy();
  await assert.rejects(() => readFile(identity.keyPath), { code: "ENOENT" });
  await assert.rejects(() => identity.destroy(), /Ephemeral TLS identity failed safely/);
});

test("ephemeral TLS identity rejects preexisting roots and unsafe hostnames", async (t) => {
  const parent = await mkdtemp(join(tmpdir(), "clockchain-ephemeral-tls-reject-"));
  t.after(() => rm(parent, { recursive: true, force: true }));
  await assert.rejects(
    () => createEphemeralTlsIdentity({ hostname: "example.com;touch /tmp/pwned", opensslPath: "/opt/homebrew/bin/openssl", root: join(parent, "bad") }),
    /Ephemeral TLS identity failed safely/,
  );
  const existing = join(parent, "existing");
  await mkdir(existing, { mode: 0o700 });
  await assert.rejects(
    () => createEphemeralTlsIdentity({ hostname: "responder.task.local", opensslPath: "/opt/homebrew/bin/openssl", root: existing }),
    /Ephemeral TLS identity failed safely/,
  );
});
