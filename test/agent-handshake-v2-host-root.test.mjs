import assert from "node:assert/strict";
import { chmod, mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { loadHostRoot } from "../src/agent-handshake/v2/host-root.mjs";
import { ed25519 } from "./support/agent-handshake-v2-fixture.mjs";

test("host root loads only from one private file with an exact key id", async () => {
  const directory = await mkdtemp(join(tmpdir(), "host-root-"));
  await chmod(directory, 0o700);
  const path = join(directory, "root.pem");
  const root = ed25519("root-2026-08");
  await writeFile(path, root.privateKeyPem, { mode: 0o600 });
  const loaded = await loadHostRoot({
    env: { CLOCKCHAIN_HOST_ROOT_KEY_ID: root.keyId, CLOCKCHAIN_HOST_ROOT_KEY_FILE: path },
  });
  assert.equal(loaded.keyId, root.keyId);
  assert.equal(typeof loaded.privateKeyPem, "string");
  assert.equal("publicKey" in loaded, true);
});

test("missing, weak, inline, permissive, or malformed root configuration fails", async () => {
  await assert.rejects(() => loadHostRoot({ env: {} }));
  await assert.rejects(() => loadHostRoot({ env: { CLOCKCHAIN_HOST_ROOT_PRIVATE_KEY: "secret" } }));
  const directory = await mkdtemp(join(tmpdir(), "host-root-bad-"));
  await chmod(directory, 0o700);
  const path = join(directory, "root.pem");
  await writeFile(path, "not a key", { mode: 0o600 });
  await assert.rejects(() => loadHostRoot({
    env: { CLOCKCHAIN_HOST_ROOT_KEY_ID: "root-2026-08", CLOCKCHAIN_HOST_ROOT_KEY_FILE: path },
  }));
});
