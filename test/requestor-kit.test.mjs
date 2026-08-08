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

test("requestor checks the host key after handshake_required and before watching or role work", async () => {
  const source = await requestorSource();
  const handshakeIndex = source.indexOf('awaitKind("handshake_required"');
  const keyCheckIndex = source.indexOf("assertHandshakeRepositoryKey", handshakeIndex);
  const watchingIndex = source.indexOf('kind: "watching"', handshakeIndex);
  const roleIndex = source.indexOf("runPayeeRole", handshakeIndex);

  assert.notEqual(handshakeIndex, -1, "handshake_required intake must exist");
  assert.notEqual(keyCheckIndex, -1, "repository-key binding check must exist after handshake intake");
  assert.notEqual(watchingIndex, -1, "watching signal must exist");
  assert.notEqual(roleIndex, -1, "requestor role work must exist");
  assert.ok(handshakeIndex < keyCheckIndex, "key binding must happen after handshake_required intake");
  assert.ok(keyCheckIndex < watchingIndex, "key binding must happen before watching is posted");
  assert.ok(keyCheckIndex < roleIndex, "key binding must happen before runPayeeRole");
});

test("requestor-facing host-key prose does not say operator key", async () => {
  const source = await requestorSource();

  assert.ok(!source.includes("operator key"), "requestor CLI prose must say session host key");
  assert.ok(!source.includes("The operator covered"), "requestor CLI funding prose must name the session host");
  assert.ok(!source.includes("independent verifier's signed certificate"));
  assert.match(source, /session host key/);
  assert.match(source, /The session host covered our registration gas/);
  assert.match(source, /independent checker's signed certificate/);
});

test("requestor cannot bypass discovery validation with explicit relay/session flags", async () => {
  const source = await requestorSource();

  assert.ok(
    !source.includes("if (RELAY_URL && SESSION_ID) return;"),
    "explicit relay/session flags must not skip the invitation fetch and validation path",
  );
});
