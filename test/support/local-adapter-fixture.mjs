// Shared harness for local-adapter tests: a pinned asset directory, an adapter
// server wired to a fake upstream, and coordinator-shaped helper steps. Mirrors
// the helpers in test/local-adapter.test.mjs.
import { createHash } from "node:crypto";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  AGENT_HANDSHAKE_HELPER_VERSION,
  AGENT_HANDSHAKE_RELEASE_ASSET_PREFIX,
} from "../../src/agent-handshake/v2/constants.mjs";
import { canonicalBytes } from "../../src/core/canonical.mjs";
import { VERIFIED_HELPER_BOOTSTRAP } from "../../src/harness/verified-release-action-recorder.mjs";
import {
  ADAPTER_APPROVAL_TOOL,
  createLocalAdapterServer,
} from "../../src/local-adapter/server.mjs";

export const sha256 = (value) => createHash("sha256").update(value).digest("hex");
export const SESSION = "11111111-2222-4333-8444-555555555555";
export const SOURCE_COMMIT = "a".repeat(40);
export const HELPER_SOURCE = '"use strict";\n// local-adapter test helper\n';
export const REFUSAL = "Clockchain local adapter refused the action.";
export const WITHHELD =
  "[withheld by clockchain-local-adapter: this digest-bound step is staged " +
  "privately; execute it by calling authorize_local_action]";
export const ENDPOINT = "https://upstream.test/handshake/mcp";

export function fixtureManifest(helperBytes = Buffer.from(HELPER_SOURCE)) {
  return {
    schema: "clockchain.agent-handshake-release-manifest/v1",
    version: AGENT_HANDSHAKE_HELPER_VERSION,
    sourceCommit: SOURCE_COMMIT,
    nodeRuntime: "24.6.0",
    assets: [{
      platform: "node",
      arch: "any",
      upstreamSupport: "node24_portable",
      filename: "clockchain-agent-handshake.cjs",
      url: `${AGENT_HANDSHAKE_RELEASE_ASSET_PREFIX}clockchain-agent-handshake.cjs`,
      byteLength: String(helperBytes.length),
      sha256: sha256(helperBytes),
      nativeSignature: {
        type: "none", verified: null, signer: null, timestamp: null, notarized: null,
      },
      execution: {
        verified: true, platform: "linux", arch: "x64", exitCode: "0",
        publicOutputSha256: "b".repeat(64),
      },
    }],
  };
}

export function fixturePin(manifestBytes) {
  return {
    version: AGENT_HANDSHAKE_HELPER_VERSION,
    sourceCommit: SOURCE_COMMIT,
    manifestDigest: sha256(manifestBytes),
    allowedAssetPrefix: AGENT_HANDSHAKE_RELEASE_ASSET_PREFIX,
    hostRoots: [{ kid: "root-2026-08", fingerprint: "c".repeat(64) }],
  };
}

export async function makeAssetDir(t, { helperBytes = Buffer.from(HELPER_SOURCE), manifestBytes, pin } = {}) {
  const dir = await mkdtemp(join(tmpdir(), "local-adapter-assets-"));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const manifest = manifestBytes ?? canonicalBytes(fixtureManifest(helperBytes));
  const pinValue = pin ?? fixturePin(manifest);
  await writeFile(join(dir, "manifest.json"), manifest, { mode: 0o600 });
  await writeFile(join(dir, "clockchain-agent-handshake.cjs"), helperBytes, { mode: 0o600 });
  await writeFile(join(dir, "pin.json"), `${JSON.stringify(pinValue)}\n`, { mode: 0o600 });
  return { assetDir: dir, helperBytes, manifestBytes: manifest, pin: pinValue };
}

export function fakeResponse(body, { contentType = "application/json", ok = true } = {}) {
  const text = typeof body === "string" ? body : JSON.stringify(body);
  return {
    ok,
    headers: { get: (name) => (name.toLowerCase() === "content-type" ? contentType : null) },
    text: async () => text,
  };
}

export async function makeContext(t, options = {}) {
  const fixture = await makeAssetDir(t, options.fixture ?? {});
  const tmpRoot = options.tmpdir ?? await mkdtemp(join(tmpdir(), "local-adapter-tmp-"));
  t.after(() => rm(tmpRoot, { recursive: true, force: true }));
  const make = (overrides = {}) => createLocalAdapterServer({
    assetDir: fixture.assetDir,
    endpoint: ENDPOINT,
    fetchImpl: async () => fakeResponse({ jsonrpc: "2.0", id: 1, result: {} }),
    tmpdir: tmpRoot,
    ...options.server,
    ...overrides,
  });
  return { fixture, make, tmpRoot };
}

// Mirrors the coordinator's helperStep()/compactHelperStep(): the verified
// prefix is fixed, the state-dir token is the only double-quoted word, and the
// optional payload is appended verbatim.
export function helperStep({
  manifestDigest,
  operation = "init",
  payload,
  role = "initiator",
  sessionId = SESSION,
  shellCommand,
  ...overrides
}) {
  const command = shellCommand ?? (() => {
    const prefix =
      `node --input-type=commonjs --eval '${VERIFIED_HELPER_BOOTSTRAP}' ` +
      `${manifestDigest} ./manifest.json ./clockchain-agent-handshake.cjs`;
    let suffix = `${operation} --state-dir "\${TMPDIR%/}/.clockchain/handshakes/${sessionId}/${role}"`;
    if (payload !== undefined) suffix += ` --payload-base64url ${payload}`;
    return `${prefix} ${suffix}`;
  })();
  return {
    operation,
    role,
    sessionId,
    approvalTool: ADAPTER_APPROVAL_TOOL,
    commandLength: Buffer.byteLength(command),
    commandSha256: sha256(command),
    shellCommand: command,
    ...overrides,
  };
}

export const b64u = (value) => Buffer.from(JSON.stringify(value)).toString("base64url");
export const rpcResult = (body) => ({ content: [{ type: "text", text: JSON.stringify(body) }] });

export function upstreamResult(result) {
  return async (url, init) => {
    const request = JSON.parse(init.body);
    const value = typeof result === "function" ? result(request) : result;
    return fakeResponse({ jsonrpc: "2.0", id: request.id, result: value });
  };
}

export const call = (server, id, name, args = {}) =>
  server.handleMessage({ jsonrpc: "2.0", id, method: "tools/call", params: { name, arguments: args } });

export const cliResult = (operation, extra = {}) =>
  `${JSON.stringify({
    schema: "clockchain.agent-handshake-cli-result/v1",
    helperVersion: AGENT_HANDSHAKE_HELPER_VERSION,
    operation,
    ...extra,
  })}\n`;
