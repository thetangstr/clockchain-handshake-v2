import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import {
  AGENT_HANDSHAKE_HELPER_VERSION,
  AGENT_HANDSHAKE_RELEASE_ASSET_PREFIX,
} from "../src/agent-handshake/v2/constants.mjs";
import { canonicalBytes } from "../src/core/canonical.mjs";
import { VERIFIED_HELPER_BOOTSTRAP } from "../src/harness/verified-release-action-recorder.mjs";
import {
  ADAPTER_APPROVAL_TOOL,
  ADAPTER_TOOL,
  createLocalAdapterServer,
  loadPinnedAssets,
} from "../src/local-adapter/server.mjs";

const sha256 = (value) => createHash("sha256").update(value).digest("hex");
const SESSION = "11111111-2222-4333-8444-555555555555";
const SOURCE_COMMIT = "a".repeat(40);
const HELPER_SOURCE = '"use strict";\n// local-adapter test helper\n';
const REFUSAL = "Clockchain local adapter refused the action.";
const ENDPOINT = "https://upstream.test/handshake/mcp";

const POLICY = Object.freeze({
  schema: "clockchain.agent-handshake-policy/v1",
  protocol: "clockchain.agent-handshake/v2",
  role: "initiator",
  mcpOrigin: "https://mcp.clockchain.network",
  reference: "NS-1847",
  statementDigest: "e".repeat(64),
  maxValidForSeconds: "90",
  identityPolicy: Object.freeze({
    erc8004: "not_required",
    chainId: null,
    registryAddress: null,
  }),
  externalBusinessActionsAllowed: false,
});

function fixtureManifest(helperBytes = Buffer.from(HELPER_SOURCE)) {
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

function fixturePin(manifestBytes) {
  return {
    version: AGENT_HANDSHAKE_HELPER_VERSION,
    sourceCommit: SOURCE_COMMIT,
    manifestDigest: sha256(manifestBytes),
    allowedAssetPrefix: AGENT_HANDSHAKE_RELEASE_ASSET_PREFIX,
    hostRoots: [{ kid: "root-2026-08", fingerprint: "c".repeat(64) }],
  };
}

// manifestBytes may be supplied pre-encoded so a tamper case can hold the
// helper constant while the bytes under test change.
async function makeAssetDir(t, { helperBytes = Buffer.from(HELPER_SOURCE), manifestBytes, pin } = {}) {
  const dir = await mkdtemp(join(tmpdir(), "local-adapter-assets-"));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const manifest = manifestBytes ?? canonicalBytes(fixtureManifest(helperBytes));
  const pinValue = pin ?? fixturePin(manifest);
  await writeFile(join(dir, "manifest.json"), manifest, { mode: 0o600 });
  await writeFile(join(dir, "clockchain-agent-handshake.cjs"), helperBytes, { mode: 0o600 });
  await writeFile(join(dir, "pin.json"), `${JSON.stringify(pinValue)}\n`, { mode: 0o600 });
  return { assetDir: dir, helperBytes, manifestBytes: manifest, pin: pinValue };
}

async function makeContext(t, options = {}) {
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
function helperStep({
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

function signingRequestRecord(overrides = {}) {
  return {
    schema: "clockchain.agent-handshake-signing-request/v1",
    helperVersion: AGENT_HANDSHAKE_HELPER_VERSION,
    operation: "proposal",
    role: "initiator",
    sessionId: SESSION,
    repositorySha: SOURCE_COMMIT,
    sessionDeadlineMs: "1786337600000",
    policyDigest: "f".repeat(64),
    externalBusinessActionPerformed: false,
    ...overrides,
  };
}

const b64u = (value) => Buffer.from(JSON.stringify(value)).toString("base64url");
const rpcResult = (body) => ({ content: [{ type: "text", text: JSON.stringify(body) }] });

function fakeResponse(body, { contentType = "application/json", ok = true } = {}) {
  const text = typeof body === "string" ? body : JSON.stringify(body);
  return {
    ok,
    headers: { get: (name) => (name.toLowerCase() === "content-type" ? contentType : null) },
    text: async () => text,
  };
}

function upstreamResult(result) {
  return async (url, init) => {
    const request = JSON.parse(init.body);
    const value = typeof result === "function" ? result(request) : result;
    return fakeResponse({ jsonrpc: "2.0", id: request.id, result: value });
  };
}

const call = (server, id, name, args = {}) =>
  server.handleMessage({ jsonrpc: "2.0", id, method: "tools/call", params: { name, arguments: args } });

const cliResult = (operation, extra = {}) =>
  `${JSON.stringify({
    schema: "clockchain.agent-handshake-cli-result/v1",
    helperVersion: AGENT_HANDSHAKE_HELPER_VERSION,
    operation,
    ...extra,
  })}\n`;

test("startup gate loads a pinned asset directory", async (t) => {
  const { assetDir, pin } = await makeAssetDir(t);
  const assets = loadPinnedAssets({ assetDir });
  assert.equal(assets.pin.manifestDigest, pin.manifestDigest);
  assert.equal(assets.manifestPath, join(assetDir, "manifest.json"));
  assert.equal(assets.helperPath, join(assetDir, "clockchain-agent-handshake.cjs"));
});

test("startup gate fails closed on tampered helper bytes", async (t) => {
  // The manifest is canonical for the pristine helper; the helper file differs.
  const fixture = await makeAssetDir(t, {
    helperBytes: Buffer.from("tampered"),
    manifestBytes: canonicalBytes(fixtureManifest()),
  });
  assert.throws(() => loadPinnedAssets({ assetDir: fixture.assetDir }), /refused/);
});

test("startup gate rejects wrong manifestDigest, wrong version, and noncanonical manifest", async (t) => {
  const manifestBytes = canonicalBytes(fixtureManifest());
  for (const pin of [
    { ...fixturePin(manifestBytes), manifestDigest: "d".repeat(64) },
    { ...fixturePin(manifestBytes), version: "0.0.0" },
    { ...fixturePin(manifestBytes), hostRoots: [] },
    { ...fixturePin(manifestBytes), allowedAssetPrefix: "https://evil.example/" },
  ]) {
    const fixture = await makeAssetDir(t, { pin });
    assert.throws(() => loadPinnedAssets({ assetDir: fixture.assetDir }), /refused/);
  }
  // A manifest whose bytes are not the canonical encoding fails closed even
  // when the pin digest is recomputed over those exact bytes.
  const sloppy = Buffer.from(`${JSON.stringify(fixtureManifest(), null, 2)}\n`);
  const fixture = await makeAssetDir(t, { manifestBytes: sloppy, pin: fixturePin(sloppy) });
  assert.throws(() => loadPinnedAssets({ assetDir: fixture.assetDir }), /refused/);
});

test("accepts a well-formed step and executes it with the verified argv", async (t) => {
  const runCalls = [];
  const { fixture, make, tmpRoot } = await makeContext(t);
  const step = helperStep({ manifestDigest: fixture.pin.manifestDigest });
  const server = make({
    fetchImpl: upstreamResult(rpcResult({ localAction: { helperStep: step } })),
    runHelper: async (input) => {
      runCalls.push(input);
      return { code: 0, stderr: "", stdout: cliResult("init") };
    },
  });
  const proxied = await call(server, 1, "agent_handshake_join", { access: "x" });
  assert.equal(proxied.error, undefined);
  assert.equal(server.pendingCount(), 1);
  const executed = await call(server, 2, ADAPTER_TOOL);
  assert.equal(runCalls.length, 1);
  const { args, file } = runCalls[0];
  assert.equal(file, process.execPath);
  assert.deepEqual(args.slice(0, 4), [
    "--input-type=commonjs", "--eval", VERIFIED_HELPER_BOOTSTRAP, fixture.pin.manifestDigest,
  ]);
  assert.equal(args[4], join(fixture.assetDir, "manifest.json"));
  assert.equal(args[5], join(fixture.assetDir, "clockchain-agent-handshake.cjs"));
  assert.deepEqual(args.slice(6), [
    "init", "--state-dir",
    join(tmpRoot, `.clockchain/handshakes/${SESSION}/initiator`),
  ]);
  assert.equal(executed.result.isError, undefined);
  assert.equal(JSON.parse(executed.result.content[0].text).operation, "init");
  assert.equal(server.pendingCount(), 0);
});

test("payload-bearing steps pass --payload-base64url through to the helper argv", async (t) => {
  const runCalls = [];
  const { fixture, make } = await makeContext(t);
  const encoded = b64u(signingRequestRecord());
  const step = helperStep({
    manifestDigest: fixture.pin.manifestDigest,
    operation: "sign",
    payload: encoded,
  });
  const server = make({
    fetchImpl: upstreamResult(rpcResult({ localAction: { helperStep: step } })),
    runHelper: async (input) => {
      runCalls.push(input);
      return { code: 0, stderr: "", stdout: cliResult("sign") };
    },
  });
  await call(server, 1, "agent_handshake_next", {});
  await call(server, 2, ADAPTER_TOOL);
  assert.equal(runCalls[0].args[6], "sign");
  assert.deepEqual(runCalls[0].args.slice(-2), ["--payload-base64url", encoded]);
});

test("stages helperSteps arrays FIFO and executes exactly one step per call", async (t) => {
  const operations = [];
  const { fixture, make } = await makeContext(t);
  const steps = ["init", "policy", "inspect"].map((operation) => helperStep({
    manifestDigest: fixture.pin.manifestDigest,
    operation,
    payload: operation === "policy" ? b64u(POLICY) : undefined,
  }));
  const server = make({
    fetchImpl: upstreamResult(rpcResult({ localAction: { helperSteps: steps } })),
    runHelper: async (input) => {
      operations.push(input.args[6]);
      return { code: 0, stderr: "", stdout: cliResult(input.args[6]) };
    },
  });
  await call(server, 1, "agent_handshake_join", {});
  assert.equal(server.pendingCount(), 3);
  for (const [index, operation] of ["init", "policy", "inspect"].entries()) {
    const response = await call(server, index + 2, ADAPTER_TOOL);
    assert.equal(JSON.parse(response.result.content[0].text).operation, operation);
  }
  assert.deepEqual(operations, ["init", "policy", "inspect"]);
  const empty = await call(server, 9, ADAPTER_TOOL);
  assert.equal(empty.result.isError, true);
});

test("a byte-identical step re-issued on a later poll is not staged twice", async (t) => {
  const { fixture, make } = await makeContext(t);
  const step = helperStep({ manifestDigest: fixture.pin.manifestDigest });
  const server = make({
    fetchImpl: upstreamResult(rpcResult({ localAction: { helperStep: step } })),
    runHelper: async () => ({ code: 0, stderr: "", stdout: cliResult("init") }),
  });
  // The coordinator re-issues an unchanged localAction on each poll while a
  // step stays pending; re-staging it would shift the queue head away from the
  // step the caller just read.
  await call(server, 1, "agent_handshake_next", {});
  await call(server, 2, "agent_handshake_next", {});
  await call(server, 3, "agent_handshake_next", {});
  assert.equal(server.pendingCount(), 1);
  const executed = await call(server, 4, ADAPTER_TOOL);
  assert.equal(JSON.parse(executed.result.content[0].text).operation, "init");
  assert.equal(server.pendingCount(), 0);
});

test("rejects malformed steps: approval tool, digests, prefix, suffix, and field bindings", async (t) => {
  const { fixture, make } = await makeContext(t);
  const manifestDigest = fixture.pin.manifestDigest;
  const good = helperStep({ manifestDigest });
  const mutations = [
    { ...good, approvalTool: "mcp__other__authorize_local_action" },
    { ...good, approvalTool: "Bash" },
    { ...good, commandSha256: "0".repeat(64) },
    { ...good, commandLength: good.commandLength + 1 },
    { ...good, shellCommand: good.shellCommand.replace("node --input-type=commonjs", "node --input-type=module") },
    { ...good, shellCommand: good.shellCommand.replace("./manifest.json", "/etc/manifest.json") },
    { ...good, shellCommand: good.shellCommand.replace("${TMPDIR%/}", "$TMPDIR") },
    { ...good, shellCommand: `${good.shellCommand} --extra flag` },
    { ...good, shellCommand: good.shellCommand.replace('"${TMPDIR%/', '"; rm -rf / #"${TMPDIR%/') },
    { ...good, sessionId: "99999999-2222-4333-8444-555555555555" },
    { ...good, role: "responder" },
    { ...good, operation: "inspect" },
    { ...good, extraKey: true },
    { ...good, shellCommandFetch: 42 },
  ];
  for (const mutation of mutations) {
    const server = make({
      fetchImpl: upstreamResult(rpcResult({ localAction: { helperStep: mutation } })),
    });
    const response = await call(server, 1, "agent_handshake_status", {});
    assert.equal(response.result.isError, true, JSON.stringify(mutation));
    assert.equal(response.result.content[0].text, REFUSAL);
    assert.equal(server.pendingCount(), 0);
  }
});

test("payload rules: required for policy/sign/verify-certificate, forbidden otherwise", async (t) => {
  const { fixture, make } = await makeContext(t);
  const manifestDigest = fixture.pin.manifestDigest;
  const refused = async (step) => {
    const server = make({
      fetchImpl: upstreamResult(rpcResult({ localAction: { helperStep: step } })),
    });
    const response = await call(server, 1, "agent_handshake_next", {});
    assert.equal(response.result.isError, true);
    assert.equal(server.pendingCount(), 0);
  };
  // init carrying a payload it must not have
  await refused(helperStep({ manifestDigest, payload: b64u({ a: 1 }) }));
  // policy without a payload
  await refused(helperStep({ manifestDigest, operation: "policy" }));
  // sign without a payload
  await refused(helperStep({ manifestDigest, operation: "sign" }));
  // policy whose role disagrees with the step
  await refused(helperStep({
    manifestDigest, operation: "policy",
    payload: b64u({ ...POLICY, role: "responder" }),
  }));
  // policy that fails schema validation entirely
  await refused(helperStep({
    manifestDigest, operation: "policy", payload: b64u({ bogus: true }),
  }));
  // sign payloads with broken binds
  for (const record of [
    signingRequestRecord({ helperVersion: "0.0.0" }),
    signingRequestRecord({ sessionId: "99999999-2222-4333-8444-555555555555" }),
    signingRequestRecord({ role: "responder" }),
    signingRequestRecord({ externalBusinessActionPerformed: true }),
    signingRequestRecord({ operation: "init" }),
    signingRequestRecord({ schema: "other/v1" }),
  ]) {
    await refused(helperStep({ manifestDigest, operation: "sign", payload: b64u(record) }));
  }
  // verify-certificate binds
  for (const record of [
    { schema: "other/v1" },
    { helperVersion: "0.0.0" },
    { role: "responder" },
    { sessionId: "99999999-2222-4333-8444-555555555555" },
    { externalBusinessActionPerformed: true },
  ]) {
    await refused(helperStep({
      manifestDigest,
      operation: "verify-certificate",
      payload: b64u({
        schema: "clockchain.agent-handshake-certificate-verification/v1",
        helperVersion: AGENT_HANDSHAKE_HELPER_VERSION,
        role: "initiator",
        sessionId: SESSION,
        externalBusinessActionPerformed: false,
        ...record,
      }),
    }));
  }
  // non-base64url and non-JSON payloads
  await refused(helperStep({ manifestDigest, operation: "sign", payload: "not*b64url" }));
  await refused(helperStep({ manifestDigest, operation: "sign", payload: b64u("not json") }));
});

test("accepts sign and verify-certificate payloads that satisfy every bind", async (t) => {
  const { fixture, make } = await makeContext(t);
  const manifestDigest = fixture.pin.manifestDigest;
  const steps = [
    helperStep({ manifestDigest, operation: "sign", payload: b64u(signingRequestRecord()) }),
    helperStep({
      manifestDigest,
      operation: "verify-certificate",
      payload: b64u({
        schema: "clockchain.agent-handshake-certificate-verification/v1",
        helperVersion: AGENT_HANDSHAKE_HELPER_VERSION,
        role: "initiator",
        sessionId: SESSION,
        repositorySha: SOURCE_COMMIT,
        sessionDeadlineMs: "1786337600000",
        certificate: {},
        externalBusinessActionPerformed: false,
      }),
    }),
  ];
  const server = make({
    fetchImpl: upstreamResult(rpcResult({ localAction: { helperSteps: steps } })),
  });
  const response = await call(server, 1, "agent_handshake_next", {});
  assert.equal(response.result.isError, undefined);
  assert.equal(server.pendingCount(), 2);
});

test("upstream proxy parses SSE and plain JSON, and tools/list appends the adapter tool", async (t) => {
  const { make } = await makeContext(t);
  const sse = make({
    fetchImpl: async (url, init) => {
      const request = JSON.parse(init.body);
      return {
        ok: true,
        headers: { get: () => "text/event-stream" },
        text: async () => [
          "event: message",
          `data: {"jsonrpc":"2.0","id":${request.id},"result":{"tools":[`,
          `data: {"name":"agent_handshake_join"}]}}`,
          "",
        ].join("\n"),
      };
    },
  });
  const listed = await sse.handleMessage({ jsonrpc: "2.0", id: 7, method: "tools/list", params: {} });
  assert.deepEqual(listed.result.tools.map((tool) => tool.name), [
    "agent_handshake_join", ADAPTER_TOOL,
  ]);
  assert.deepEqual(listed.result.tools.at(-1).inputSchema, {
    type: "object", properties: {}, additionalProperties: false,
  });

  const plain = make({
    fetchImpl: async (url, init) => {
      const request = JSON.parse(init.body);
      assert.equal(init.headers["content-type"], "application/json");
      assert.equal(init.headers.accept, "application/json, text/event-stream");
      return fakeResponse({ jsonrpc: "2.0", id: request.id, result: { tools: [] } });
    },
  });
  const listedPlain = await plain.handleMessage({ jsonrpc: "2.0", id: 8, method: "tools/list" });
  assert.equal(listedPlain.result.tools.length, 1);
});

test("tools/call forwards params verbatim and returns upstream errors verbatim", async (t) => {
  const calls = [];
  const { make } = await makeContext(t);
  const server = make({
    fetchImpl: async (url, init) => {
      const request = JSON.parse(init.body);
      calls.push(request);
      if (request.method === "tools/call" && request.params.name === "fail_me") {
        return fakeResponse({ jsonrpc: "2.0", id: request.id, error: { code: -32000, message: "upstream said no" } });
      }
      return fakeResponse({ jsonrpc: "2.0", id: request.id, result: { ok: true } });
    },
  });
  const forwarded = await call(server, 3, "agent_handshake_status", { access: "tok", deep: { n: 1 } });
  assert.deepEqual(forwarded.result, { ok: true });
  const sent = calls.find((entry) => entry.method === "tools/call");
  assert.deepEqual(sent.params, {
    name: "agent_handshake_status",
    arguments: { access: "tok", deep: { n: 1 } },
  });
  const failed = await call(server, 4, "fail_me", {});
  assert.deepEqual(failed.error, { code: -32000, message: "upstream said no" });
});

test("initialize proxies upstream lazily and falls back when unreachable", async (t) => {
  let initCalls = 0;
  const { make } = await makeContext(t);
  const server = make({
    fetchImpl: async (url, init) => {
      const request = JSON.parse(init.body);
      if (request.method === "initialize") {
        initCalls += 1;
        return fakeResponse({
          jsonrpc: "2.0", id: request.id,
          result: {
            protocolVersion: "2025-06-18",
            instructions: "UPSTREAM-INSTRUCTIONS",
            capabilities: { tools: {} },
          },
        });
      }
      return fakeResponse({ jsonrpc: "2.0", id: request.id, result: {} });
    },
  });
  const response = await server.handleMessage({
    jsonrpc: "2.0", id: 1, method: "initialize",
    params: {
      protocolVersion: "2024-11-05",
      capabilities: {},
      clientInfo: { name: "test", version: "0" },
    },
  });
  assert.equal(response.result.serverInfo.name, "clockchain-local-adapter");
  assert.equal(response.result.serverInfo.version, AGENT_HANDSHAKE_HELPER_VERSION);
  assert.equal(response.result.instructions, "UPSTREAM-INSTRUCTIONS");
  assert.equal(response.result.protocolVersion, "2024-11-05");
  // A second initialize reuses the cached upstream result.
  await server.handleMessage({ jsonrpc: "2.0", id: 2, method: "initialize" });
  assert.equal(initCalls, 1);

  const offline = make({ fetchImpl: async () => { throw new Error("offline"); } });
  const fallback = await offline.handleMessage({ jsonrpc: "2.0", id: 1, method: "initialize" });
  assert.equal(fallback.result.serverInfo.name, "clockchain-local-adapter");
  assert.equal(typeof fallback.result.instructions, "string");
  assert.equal(fallback.error, undefined);
});

test("execution surfaces only the helper stderr code and validates stdout shape", async (t) => {
  const { fixture, make, tmpRoot } = await makeContext(t);
  const step = helperStep({ manifestDigest: fixture.pin.manifestDigest });
  const stage = upstreamResult(rpcResult({ localAction: { helperStep: step } }));
  const failing = make({
    fetchImpl: stage,
    runHelper: async () => ({
      code: 1,
      stderr: '{"error":{"code":"AGENT_HANDSHAKE_FAILED","message":"secret detail"}}\n',
      stdout: "",
    }),
  });
  await call(failing, 1, "agent_handshake_join", {});
  const failed = await call(failing, 2, ADAPTER_TOOL);
  assert.equal(failed.result.isError, true);
  assert.equal(failed.result.content[0].text, "AGENT_HANDSHAKE_FAILED");

  for (const stdout of [
    cliResult("init", { schema: "other/v1" }),
    cliResult("init", { helperVersion: "0.0.0" }),
    cliResult("inspect"),
    "not json\n",
  ]) {
    const server = make({
      fetchImpl: stage,
      runHelper: async () => ({ code: 0, stderr: "", stdout }),
      tmpdir: tmpRoot,
    });
    await call(server, 1, "agent_handshake_join", {});
    const response = await call(server, 2, ADAPTER_TOOL);
    assert.equal(response.result.isError, true, stdout);
    assert.equal(response.result.content[0].text, REFUSAL);
  }
});

test("staged entries older than the TTL are dropped at execution time", async (t) => {
  let now = 1_000_000;
  const { fixture, make } = await makeContext(t);
  const step = helperStep({ manifestDigest: fixture.pin.manifestDigest });
  const server = make({
    fetchImpl: upstreamResult(rpcResult({ localAction: { helperStep: step } })),
    now: () => now,
    runHelper: async () => ({ code: 0, stderr: "", stdout: cliResult("init") }),
  });
  await call(server, 1, "agent_handshake_join", {});
  assert.equal(server.pendingCount(), 1);
  now += 21 * 60_000;
  const response = await call(server, 2, ADAPTER_TOOL);
  assert.equal(response.result.isError, true);
  assert.equal(response.result.content[0].text, "Clockchain local adapter has no staged action to execute.");
  assert.equal(server.pendingCount(), 0);
});

test("unknown methods, notifications, and adapter argument discipline", async (t) => {
  const { make } = await makeContext(t);
  const server = make();
  const unknown = await server.handleMessage({ jsonrpc: "2.0", id: 5, method: "bogus/method" });
  assert.equal(unknown.error.code, -32601);
  const ping = await server.handleMessage({ jsonrpc: "2.0", id: 6, method: "ping" });
  assert.deepEqual(ping.result, {});
  for (const notification of [
    { jsonrpc: "2.0", method: "notifications/initialized" },
    { jsonrpc: "2.0", method: "notifications/cancelled", params: {} },
    { jsonrpc: "2.0", method: "tools/list" }, // no id — a notification shape
  ]) {
    assert.equal(await server.handleMessage(notification), null);
  }
  const withArgs = await call(server, 7, ADAPTER_TOOL, { digest: "x" });
  assert.equal(withArgs.error.code, -32602);
});
