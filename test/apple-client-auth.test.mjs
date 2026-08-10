import assert from "node:assert/strict";
import { mkdtemp, readFile, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import {
  installAppleClientAuthentication,
  loadAppleClientAuthentication,
} from "../src/testing/apple-client-auth.mjs";

async function fixture(name, value, mode = 0o600) {
  const root = await mkdtemp(join(tmpdir(), "clockchain-apple-auth-"));
  const source = join(root, name);
  await writeFile(source, `${JSON.stringify(value)}\n`, { mode });
  return { root, source };
}

test("Codex authentication is the only existing state installed into a disposable home", async () => {
  const value = {
    OPENAI_API_KEY: null,
    auth_mode: "chatgpt",
    last_refresh: "2026-08-10T00:00:00Z",
    tokens: {
      access_token: "codex-access-secret",
      account_id: "account",
      id_token: "codex-id-secret",
      refresh_token: "codex-refresh-secret",
    },
  };
  const { root, source } = await fixture("auth.json", value);
  const home = join(root, "fresh-home");
  const authentication = await loadAppleClientAuthentication({ client: "codex", source });
  assert.deepEqual(authentication.environment, {});
  assert.deepEqual(authentication.secretCanaries, [
    "codex-access-secret", "codex-id-secret", "codex-refresh-secret",
  ]);
  const destination = await installAppleClientAuthentication({ authentication, home });
  assert.equal(destination, join(home, "auth.json"));
  assert.deepEqual(JSON.parse(await readFile(destination, "utf8")), value);
  assert.equal((await stat(destination)).mode & 0o777, 0o600);
});

test("Claude Code authentication is installed without global settings or history", async () => {
  const value = {
    claudeAiOauth: {
      accessToken: "claude-access-secret",
      expiresAt: 1785759820545,
      refreshToken: "claude-refresh-secret",
    },
  };
  const { root, source } = await fixture("credentials.json", value);
  const home = join(root, "fresh-home");
  const authentication = await loadAppleClientAuthentication({ client: "claude", source });
  assert.deepEqual(authentication.secretCanaries, ["claude-access-secret", "claude-refresh-secret"]);
  const destination = await installAppleClientAuthentication({ authentication, home });
  assert.equal(destination, join(home, ".claude", ".credentials.json"));
  assert.deepEqual(JSON.parse(await readFile(destination, "utf8")), value);
  assert.equal((await stat(destination)).mode & 0o777, 0o600);
});

test("Claude Code can install the macOS Keychain credential without exporting other client state", async () => {
  const root = await mkdtemp(join(tmpdir(), "clockchain-apple-keychain-"));
  const home = join(root, "fresh-home");
  const serialized = JSON.stringify({
    claudeAiOauth: {
      accessToken: "keychain-access-secret",
      expiresAt: 1785759820545,
      refreshToken: "keychain-refresh-secret",
    },
  });
  const authentication = await loadAppleClientAuthentication({ client: "claude", serialized });
  assert.equal(authentication.source, null);
  assert.deepEqual(authentication.secretCanaries, ["keychain-access-secret", "keychain-refresh-secret"]);
  const destination = await installAppleClientAuthentication({ authentication, home });
  assert.equal(await readFile(destination, "utf8"), serialized);
  assert.equal((await stat(destination)).mode & 0o777, 0o600);
});

test("authentication input must be private and match the selected client", async () => {
  const open = await fixture("open.json", {
    tokens: { access_token: "a", id_token: "b", refresh_token: "c" },
  }, 0o644);
  await assert.rejects(
    loadAppleClientAuthentication({ client: "codex", source: open.source }),
    /Apple client authentication failed safely/,
  );

  const wrong = await fixture("wrong.json", {
    claudeAiOauth: { accessToken: "a", expiresAt: 1, refreshToken: "b" },
  });
  await assert.rejects(
    loadAppleClientAuthentication({ client: "codex", source: wrong.source }),
    /Apple client authentication failed safely/,
  );
});
