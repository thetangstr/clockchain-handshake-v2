import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import { exportAgentHandshakeV2Fixture } from "../scripts/export-agent-handshake-v2-fixture.mjs";

test("published v2 canonical fixture is a deterministic export of the reviewed Handshake source", async () => {
  const published = JSON.parse(await readFile(new URL("./fixtures/agent-handshake-v2-canonical.json", import.meta.url), "utf8"));
  assert.deepEqual(await exportAgentHandshakeV2Fixture(published.handshakeSourceCommit), published);
  assert.equal(JSON.stringify(published).toLowerCase().includes("privatekey"), false);
});
