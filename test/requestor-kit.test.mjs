import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const REQUESTOR = new URL("../bin/requestor.mjs", import.meta.url);

async function requestorSource() {
  return readFile(REQUESTOR, "utf8");
}

test("requestor binds the handshake repository key to the validated invitation", async () => {
  const source = await requestorSource();

  assert.match(source, /assertHandshakeRepositoryKey/);
  assert.match(
    source,
    /assertHandshakeRepositoryKey\(\{\s*discovery:\s*DISCOVERY,/s,
    "requestor must compare the host's handshake key to the already-validated discovery document",
  );
  assert.match(
    source,
    /verifyResultEnvelope\(envelope,\s*\{\s*expectedPublicKey:\s*DISCOVERY\.operatorPublicKey\s*\}\)/s,
    "closing certificate verification must use the invitation key, not the untrusted handshake body",
  );
});

test("requestor cannot bypass discovery validation with explicit relay/session flags", async () => {
  const source = await requestorSource();

  assert.ok(
    !source.includes("if (RELAY_URL && SESSION_ID) return;"),
    "explicit relay/session flags must not skip the invitation fetch and validation path",
  );
});
