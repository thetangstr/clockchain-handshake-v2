import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import {
  AGENT_HANDSHAKE_HELPER_NODE_MAJOR,
  AGENT_HANDSHAKE_HELPER_VERSION,
  AGENT_HANDSHAKE_RELEASE_ASSET_PREFIX,
} from "../src/agent-handshake/v2/constants.mjs";
import { canonicalBytes } from "../src/core/canonical.mjs";
import { VERIFIED_HELPER_BOOTSTRAP } from "../src/harness/verified-release-action-recorder.mjs";
import {
  isSupportedNodeVersion,
  unsupportedNodeVersionMessage,
} from "../src/local-adapter/node-support.mjs";
import {
  ADAPTER_APPROVAL_TOOL,
  ADAPTER_RELEASE_MISMATCH_REFUSAL,
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

test("forwarded results withhold runnable shell text while the staged step still executes", async (t) => {
  const runCalls = [];
  const { fixture, make } = await makeContext(t);
  const step = helperStep({
    manifestDigest: fixture.pin.manifestDigest,
    shellCommandFetch: `curl -fsS "https://mcp.clockchain.network/handshake/local-action/${"a".repeat(64)}" -o "/tmp/x.sh" && bash "/tmp/x.sh"`,
  });
  const server = make({
    fetchImpl: upstreamResult(rpcResult({
      localAction: {
        executor: "pinned_helper",
        stateDirectoryCommand: `mkdir -p -m 700 "\${TMPDIR%/}/.clockchain/handshakes/${SESSION}/initiator"`,
        helperStep: step,
      },
    })),
    runHelper: async (input) => {
      runCalls.push(input);
      return { code: 0, stderr: "", stdout: cliResult("init") };
    },
  });
  const response = await call(server, 1, "agent_handshake_invite", {});
  const visible = JSON.parse(response.result.content[0].text);
  assert.equal(visible.localAction.helperStep.shellCommand, "[withheld by clockchain-local-adapter: this digest-bound step is staged privately; execute it by calling authorize_local_action]");
  assert.equal(visible.localAction.helperStep.shellCommandFetch, "[withheld by clockchain-local-adapter: this digest-bound step is staged privately; execute it by calling authorize_local_action]");
  assert.equal(visible.localAction.stateDirectoryCommand, "[withheld by clockchain-local-adapter: this digest-bound step is staged privately; execute it by calling authorize_local_action]");
  assert.equal(visible.localAction.helperStep.commandSha256, step.commandSha256);
  assert.equal(visible.localAction.helperStep.approvalTool, ADAPTER_APPROVAL_TOOL);
  assert.equal(server.pendingCount(), 1);
  const executed = await call(server, 2, ADAPTER_TOOL);
  assert.equal(runCalls.length, 1);
  assert.equal(JSON.parse(executed.result.content[0].text).operation, "init");
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

test("a structurally valid step pinned to a different release digest gets the upgrade refusal", async (t) => {
  const { fixture, make } = await makeContext(t);
  const wrongDigest = "0".repeat(64);
  assert.notEqual(wrongDigest, fixture.pin.manifestDigest);
  // helperStep() recomputes commandLength/commandSha256 over the command it
  // builds, so every field is self-consistent — only the embedded release
  // pin differs from what this adapter vendors. That is exactly what a step
  // minted against a newer release (different manifestDigest, helper version,
  // or allowedAssetPrefix) looks like on the wire.
  for (const step of [
    helperStep({ manifestDigest: wrongDigest }),
    helperStep({
      manifestDigest: wrongDigest,
      operation: "sign",
      payload: b64u(signingRequestRecord()),
    }),
  ]) {
    const server = make({
      fetchImpl: upstreamResult(rpcResult({ localAction: { helperStep: step } })),
    });
    const response = await call(server, 1, "agent_handshake_next", {});
    assert.equal(response.result.isError, true);
    assert.equal(response.result.content[0].text, ADAPTER_RELEASE_MISMATCH_REFUSAL);
    assert.match(response.result.content[0].text, /npx -y @d4d\.group\/local-adapter@latest/);
    assert.match(response.result.content[0].text, /must not be bypassed/);
    assert.equal(server.pendingCount(), 0);
  }
});

test("a malformed step still gets the generic refusal even with a wrong digest", async (t) => {
  const { make } = await makeContext(t);
  const wrongDigest = "0".repeat(64);
  const wrongDigestStep = helperStep({ manifestDigest: wrongDigest });
  const mutations = [
    // field/suffix disagreement stays generic even though the digest differs
    { ...wrongDigestStep, sessionId: "99999999-2222-4333-8444-555555555555" },
    { ...wrongDigestStep, role: "responder" },
    { ...wrongDigestStep, operation: "inspect" },
    // a digest slot that is not a sha256 at all
    helperStep({ manifestDigest: "not-a-digest" }),
    // wrong digest plus a suffix that fails the grammar
    (() => {
      const step = helperStep({ manifestDigest: wrongDigest });
      const shellCommand = `${step.shellCommand} --extra flag`;
      return {
        ...step,
        shellCommand,
        commandLength: Buffer.byteLength(shellCommand),
        commandSha256: sha256(shellCommand),
      };
    })(),
  ];
  for (const mutation of mutations) {
    const server = make({
      fetchImpl: upstreamResult(rpcResult({ localAction: { helperStep: mutation } })),
    });
    const response = await call(server, 1, "agent_handshake_status", {});
    assert.equal(response.result.isError, true, JSON.stringify(mutation));
    assert.equal(response.result.content[0].text, REFUSAL);
    assert.doesNotMatch(response.result.content[0].text, /upgrade|npx|local-adapter@latest/);
    assert.equal(server.pendingCount(), 0);
  }
});

test("Node version preflight: only >= the required major is supported", () => {
  const required = Number.parseInt(AGENT_HANDSHAKE_HELPER_NODE_MAJOR, 10);
  assert.equal(isSupportedNodeVersion(required), true);
  assert.equal(isSupportedNodeVersion(String(required)), true);
  assert.equal(isSupportedNodeVersion(`${required}.0.0`), true);
  assert.equal(isSupportedNodeVersion(required + 1), true);
  assert.equal(isSupportedNodeVersion(required - 1), false);
  assert.equal(isSupportedNodeVersion(`${required - 1}.9.9`), false);
  assert.equal(isSupportedNodeVersion("22.23.1"), false);
  // Unparseable input fails closed.
  for (const bad of ["garbage", "", undefined, null, NaN]) {
    assert.equal(isSupportedNodeVersion(bad), false, String(bad));
  }
  const message = unsupportedNodeVersionMessage("22.23.1");
  assert.match(message, /requires Node\.js >= 24 \(found v22\.23\.1\)/);
  assert.match(message, /https:\/\/nodejs\.org/);
  assert.match(message, /nvm\/fnm\/volta/);
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
    "agent_handshake_join", ADAPTER_TOOL, "sign_agent_contract_bind",
  ]);
  assert.deepEqual(listed.result.tools.find((tool) => tool.name === ADAPTER_TOOL).inputSchema, {
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
  assert.deepEqual(listedPlain.result.tools.map((tool) => tool.name), [
    ADAPTER_TOOL, "sign_agent_contract_bind",
  ]);
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

test("a verified verify-certificate step records the session for sign_agent_contract_bind (L3)", async (t) => {
  const { layDownSession, testSessionKey } = await import("./helpers/contract-bind-session.mjs");
  const key = testSessionKey("integration");
  const sessionDeadlineMs = 1_790_000_600_000;
  const validUntilMs = sessionDeadlineMs - 30_000;
  let nowMs = sessionDeadlineMs - 120_000;
  const { fixture, make, tmpRoot } = await makeContext(t);
  await layDownSession(tmpRoot, { sessionId: SESSION, role: "initiator", privateKey: key.privateKey, verified: false });
  const verifyStep = (deadline) => helperStep({
    manifestDigest: fixture.pin.manifestDigest,
    operation: "verify-certificate",
    payload: b64u({
      schema: "clockchain.agent-handshake-certificate-verification/v1",
      helperVersion: AGENT_HANDSHAKE_HELPER_VERSION,
      role: "initiator",
      sessionId: SESSION,
      repositorySha: SOURCE_COMMIT,
      sessionDeadlineMs: String(deadline),
      certificate: { hostSessionKeyCertificate: { certificate: { validUntilMs: String(validUntilMs) } } },
      externalBusinessActionPerformed: false,
    }),
  });
  let helperOutput = { certificateVerified: false, outcome: "VERIFIED", role: "initiator", sessionId: SESSION, identity: { sessionKeyAddress: key.address } };
  let deadline = sessionDeadlineMs;
  const server = make({
    contractBind: { tokenKeyIds: ["klb1"], serverKeyIds: ["contract-server"] },
    fetchImpl: upstreamResult(() => rpcResult({ localAction: { helperStep: verifyStep(deadline) } })),
    now: () => nowMs,
    runHelper: async () => ({ code: 0, stderr: "", stdout: cliResult("verify-certificate", helperOutput) }),
  });
  const bind = () => call(server, 99, "sign_agent_contract_bind", {
    domain: "agent-contract.bind/v1", runId: SESSION, side: "initiator",
    tokenKeyId: "klb1", serverKeyId: "contract-server",
    challenge: "ab".repeat(32), issuedAt: new Date(nowMs).toISOString(),
  });
  const refusedText = (code) => `Clockchain local adapter refused the bind statement (${code}).`;

  // An unverified certificate leaves no record: bind refuses.
  await call(server, 1, "agent_handshake_next", {});
  await call(server, 2, ADAPTER_TOOL);
  assert.equal((await bind()).result.content[0].text, refusedText("BIND_SESSION_NOT_VERIFIED"));

  // A verified certificate (re-issued step with a new digest) records the
  // session; expiry = min(sessionDeadlineMs, certificate validUntilMs).
  helperOutput = { ...helperOutput, certificateVerified: true };
  deadline = sessionDeadlineMs + 1;
  await call(server, 3, "agent_handshake_next", {});
  const executed = await call(server, 4, ADAPTER_TOOL);
  assert.equal(executed.result.isError, undefined);
  const signed = await bind();
  assert.equal(signed.result.isError, undefined, signed.result.content[0].text);
  assert.equal(JSON.parse(signed.result.content[0].text).sessionKeyAddress, key.address);
  nowMs = validUntilMs;
  assert.equal((await bind()).result.content[0].text, refusedText("BIND_SESSION_EXPIRED"));
});

test("2.1.11: a corrupted accept_invitation is refused locally, a good one is forwarded", async (t) => {
  const calls = [];
  const { make } = await makeContext(t);
  const server = make({
    fetchImpl: async (url, init) => {
      const request = JSON.parse(init.body);
      calls.push(request);
      return fakeResponse({ jsonrpc: "2.0", id: request.id, result: rpcResult({ roleAccess: "ccra_x" }) });
    },
  });
  const payload = Buffer.from(JSON.stringify({
    alg: "HS256", allowedTools: ["agent_handshake_accept_invitation"], aud: "clockchain-agent-handshake",
    expMs: "2", iss: "https://mcp.clockchain.network", jti: "b532fc9a-385f-448f-a90f-a16f26056f37",
    kid: "role-2026-08-active", nbfMs: "1", role: "responder", sessionId: SESSION,
    statementDigest: "e".repeat(64), typ: "clockchain-agent-handshake-role-access", v: 1,
  })).toString("base64url");
  const good = `${payload}.${"A".repeat(43)}`;
  const corrupted = Buffer.from(Buffer.from(payload, "base64url").toString().replace('"expMs"', '"expms"')).toString("base64url");
  const bad = `${corrupted}.${"A".repeat(43)}`;
  assert.notEqual(bad, good);
  assert.equal(bad.length, good.length);
  const refused = await call(server, 1, "agent_handshake_accept_invitation", { invitation: bad });
  assert.equal(refused.result.isError, true);
  assert.match(refused.result.content[0].text, /^INVITATION_CORRUPTED: /);
  assert.equal(calls.filter((c) => c.method === "tools/call").length, 0);
  const ok = await call(server, 2, "agent_handshake_accept_invitation", { invitation: good, acceptanceIdempotencyKey: "k1" });
  assert.equal(ok.result.isError, undefined);
  const forwarded = calls.filter((c) => c.method === "tools/call");
  assert.equal(forwarded.length, 1);
  assert.deepEqual(forwarded[0].params.arguments, { invitation: good, acceptanceIdempotencyKey: "k1" });
});

// ---- 2.1.12: invitation pass-by-reference (live p6-l-2026-10-02-1) ---------

const { putInvitationRef, claimInvitationRef } = await import("../src/local-adapter/invitation-refs.mjs");

function genuineInvitation(overrides = {}) {
  const payload = Buffer.from(JSON.stringify({
    alg: "HS256", allowedTools: ["agent_handshake_accept_invitation"], aud: "clockchain-agent-handshake",
    expMs: "2", iss: "https://mcp.clockchain.network", jti: "b532fc9a-385f-448f-a90f-a16f26056f37",
    kid: "role-2026-08-active", nbfMs: "1", role: "responder", sessionId: SESSION,
    statementDigest: "e".repeat(64), typ: "clockchain-agent-handshake-role-access", v: 1, ...overrides,
  })).toString("base64url");
  return `${payload}.${"A".repeat(43)}`;
}

function recordingUpstream(calls, respond) {
  return async (url, init) => {
    const request = JSON.parse(init.body);
    calls.push(request);
    return fakeResponse({ jsonrpc: "2.0", id: request.id, result: respond(request) });
  };
}

const toolCalls = (calls) => calls.filter((c) => c.method === "tools/call");

test("2.1.12: tools/list advertises invitationRef on accept_invitation", async (t) => {
  const { make } = await makeContext(t);
  const upstreamTool = {
    name: "agent_handshake_accept_invitation",
    description: "Accept a Responder invitation.",
    inputSchema: {
      type: "object",
      properties: { invitation: { type: "string", minLength: 80, maxLength: 4096 }, acceptanceIdempotencyKey: { type: "string" } },
      required: ["invitation"],
      additionalProperties: false,
    },
  };
  const server = make({ fetchImpl: upstreamResult({ tools: [upstreamTool, { name: "agent_handshake_join", inputSchema: { type: "object" } }] }) });
  const listed = await server.handleMessage({ jsonrpc: "2.0", id: 1, method: "tools/list", params: {} });
  const accept = listed.result.tools.find((tool) => tool.name === "agent_handshake_accept_invitation");
  assert.equal(accept.inputSchema.properties.invitationRef.type, "string");
  assert.equal(accept.inputSchema.properties.invitationRef.pattern, "^invref_[0-9a-f]{32}$");
  assert.equal((accept.inputSchema.required ?? []).includes("invitation"), false);
  assert.match(accept.description, /invitationRef/);
  // Refs mode: the raw invitation is no longer offered at all.
  const strict = make({ invitationRefs: true, fetchImpl: upstreamResult({ tools: [upstreamTool] }) });
  const strictListed = await strict.handleMessage({ jsonrpc: "2.0", id: 2, method: "tools/list", params: {} });
  const strictAccept = strictListed.result.tools.find((tool) => tool.name === "agent_handshake_accept_invitation");
  assert.equal(strictAccept.inputSchema.properties.invitation, undefined);
  assert.deepEqual(strictAccept.inputSchema.required, ["invitationRef"]);
});

test("2.1.12: accept_invitation by invitationRef forwards the exact stored bytes and consumes the ref", async (t) => {
  const calls = [];
  const { make, tmpRoot } = await makeContext(t);
  const server = make({ fetchImpl: recordingUpstream(calls, () => rpcResult({ roleAccess: "ccra_x" })) });
  const invitation = genuineInvitation();
  const ref = await putInvitationRef({ tmpRoot, kind: "received", invitation });
  const ok = await call(server, 1, "agent_handshake_accept_invitation", { invitationRef: ref, acceptanceIdempotencyKey: "k1" });
  assert.equal(ok.result.isError, undefined);
  assert.equal(toolCalls(calls).length, 1);
  assert.deepEqual(toolCalls(calls)[0].params, {
    name: "agent_handshake_accept_invitation",
    arguments: { invitation, acceptanceIdempotencyKey: "k1" },
  });
  // Single use: the same ref again is unknown and never reaches upstream.
  const again = await call(server, 2, "agent_handshake_accept_invitation", { invitationRef: ref });
  assert.equal(again.result.isError, true);
  assert.match(again.result.content[0].text, /^INVITATION_REF_UNKNOWN: /);
  assert.equal(toolCalls(calls).length, 1);
});

test("2.1.12: a refused or failed upstream accept releases the ref for a retry", async (t) => {
  const calls = [];
  let mode = "refuse";
  const { make, tmpRoot } = await makeContext(t);
  const server = make({
    fetchImpl: async (url, init) => {
      const request = JSON.parse(init.body);
      calls.push(request);
      if (mode === "down") return fakeResponse("", { ok: false });
      const result = mode === "refuse"
        ? { content: [{ type: "text", text: "{\"error\":\"V2CoordinatorError\",\"retryable\":true}" }], isError: true }
        : rpcResult({ roleAccess: "ccra_x" });
      return fakeResponse({ jsonrpc: "2.0", id: request.id, result });
    },
  });
  const invitation = genuineInvitation();
  const ref = await putInvitationRef({ tmpRoot, kind: "received", invitation });
  const refused = await call(server, 1, "agent_handshake_accept_invitation", { invitationRef: ref });
  assert.equal(refused.result.isError, true);
  mode = "down";
  const failed = await call(server, 2, "agent_handshake_accept_invitation", { invitationRef: ref });
  assert.ok(failed.error !== undefined);
  mode = "ok";
  const ok = await call(server, 3, "agent_handshake_accept_invitation", { invitationRef: ref });
  assert.equal(ok.result.isError, undefined);
  assert.deepEqual(toolCalls(calls).map((c) => c.params.arguments.invitation), [invitation, invitation, invitation]);
});

test("2.1.12: ref argument discipline — unknown ref, both forms, extra keys, wrong kind", async (t) => {
  const calls = [];
  const { make, tmpRoot } = await makeContext(t);
  const server = make({ fetchImpl: recordingUpstream(calls, () => rpcResult({ roleAccess: "ccra_x" })) });
  const invitation = genuineInvitation();
  const issued = await putInvitationRef({ tmpRoot, kind: "issued", invitation });
  const received = await putInvitationRef({ tmpRoot, kind: "received", invitation });
  const cases = [
    [{ invitationRef: `invref_${"0".repeat(32)}` }, /^INVITATION_REF_UNKNOWN: /],
    [{ invitationRef: issued }, /^INVITATION_REF_UNKNOWN: /],
    [{ invitationRef: received, invitation }, /^INVITATION_REF_INVALID: /],
    [{ invitationRef: received, extra: 1 }, /^INVITATION_REF_INVALID: /],
    [{ invitationRef: 42 }, /^INVITATION_REF_UNKNOWN: /],
  ];
  let id = 10;
  for (const [args, expected] of cases) {
    const response = await call(server, id++, "agent_handshake_accept_invitation", args);
    assert.equal(response.result.isError, true, JSON.stringify(Object.keys(args)));
    assert.match(response.result.content[0].text, expected);
    assert.equal(response.result.content[0].text.includes(invitation), false);
  }
  assert.equal(toolCalls(calls).length, 0);
  // The wrong-kind and both-forms attempts did not burn the refs.
  assert.equal((await claimInvitationRef({ tmpRoot, ref: issued, kind: "issued" })).invitation, invitation);
  assert.equal((await claimInvitationRef({ tmpRoot, ref: received, kind: "received" })).invitation, invitation);
});

test("2.1.12: a malformed invitation behind a ref is refused locally as the counterparty's and consumed", async (t) => {
  const calls = [];
  const { make, tmpRoot } = await makeContext(t);
  const server = make({ fetchImpl: recordingUpstream(calls, () => rpcResult({ roleAccess: "ccra_x" })) });
  const good = genuineInvitation();
  const [segment, sig] = good.split(".");
  const altered = `${Buffer.from(Buffer.from(segment, "base64url").toString().replace('"expMs"', '"expms"')).toString("base64url")}.${sig}`;
  const ref = await putInvitationRef({ tmpRoot, kind: "received", invitation: altered });
  const refused = await call(server, 1, "agent_handshake_accept_invitation", { invitationRef: ref });
  assert.equal(refused.result.isError, true);
  assert.match(refused.result.content[0].text, /^INVITATION_CORRUPTED: /);
  assert.match(refused.result.content[0].text, /sealed/);
  assert.equal(toolCalls(calls).length, 0);
  const again = await call(server, 2, "agent_handshake_accept_invitation", { invitationRef: ref });
  assert.match(again.result.content[0].text, /^INVITATION_REF_UNKNOWN: /);
});

test("2.1.12 refs mode: a raw invitation is refused without reaching the coordinator", async (t) => {
  const calls = [];
  const { make } = await makeContext(t);
  const server = make({ invitationRefs: true, fetchImpl: recordingUpstream(calls, () => rpcResult({ roleAccess: "ccra_x" })) });
  const response = await call(server, 1, "agent_handshake_accept_invitation", { invitation: genuineInvitation() });
  assert.equal(response.result.isError, true);
  assert.match(response.result.content[0].text, /^INVITATION_BY_REFERENCE_REQUIRED: /);
  assert.equal(toolCalls(calls).length, 0);
});

test("2.1.12 refs mode: agent_handshake_invite returns responderInvitationRef, never the invitation", async (t) => {
  const calls = [];
  const { make, tmpRoot } = await makeContext(t);
  const invitation = genuineInvitation();
  const body = { sessionId: SESSION, roleAccess: "csha_init", responderInvitation: invitation, statementDigest: "e".repeat(64) };
  const server = make({
    invitationRefs: true,
    fetchImpl: recordingUpstream(calls, () => ({ ...rpcResult(body), structuredContent: body })),
  });
  const response = await call(server, 1, "agent_handshake_invite", { reference: "r", statement: "s", validForSeconds: "90" });
  assert.equal(response.result.isError, undefined);
  const text = response.result.content[0].text;
  assert.equal(text.includes(invitation), false);
  assert.equal(JSON.stringify(response.result).includes(invitation), false);
  const parsed = JSON.parse(text);
  assert.equal(parsed.responderInvitation, undefined);
  assert.match(parsed.responderInvitationRef, /^invref_[0-9a-f]{32}$/);
  assert.equal(parsed.roleAccess, "csha_init");
  assert.equal(parsed.sessionId, SESSION);
  assert.equal(response.result.structuredContent.responderInvitation, undefined);
  assert.equal(response.result.structuredContent.responderInvitationRef, parsed.responderInvitationRef);
  const claim = await claimInvitationRef({ tmpRoot, ref: parsed.responderInvitationRef, kind: "issued" });
  assert.equal(claim.invitation, invitation);
});

test("2.1.12: without refs mode agent_handshake_invite is passed through unchanged", async (t) => {
  const { make } = await makeContext(t);
  const invitation = genuineInvitation();
  const body = { sessionId: SESSION, roleAccess: "csha_init", responderInvitation: invitation };
  const server = make({ fetchImpl: upstreamResult(rpcResult(body)) });
  const response = await call(server, 1, "agent_handshake_invite", { reference: "r", statement: "s", validForSeconds: "90" });
  assert.equal(JSON.parse(response.result.content[0].text).responderInvitation, invitation);
});

test("2.1.12: refs mode is switched on by CLOCKCHAIN_LOCAL_ADAPTER_INVITATION_REFS=1", async (t) => {
  const { make } = await makeContext(t);
  const previous = process.env.CLOCKCHAIN_LOCAL_ADAPTER_INVITATION_REFS;
  process.env.CLOCKCHAIN_LOCAL_ADAPTER_INVITATION_REFS = "1";
  t.after(() => {
    if (previous === undefined) delete process.env.CLOCKCHAIN_LOCAL_ADAPTER_INVITATION_REFS;
    else process.env.CLOCKCHAIN_LOCAL_ADAPTER_INVITATION_REFS = previous;
  });
  const calls = [];
  const server = make({ fetchImpl: recordingUpstream(calls, () => rpcResult({})) });
  const response = await call(server, 1, "agent_handshake_accept_invitation", { invitation: genuineInvitation() });
  assert.match(response.result.content[0].text, /^INVITATION_BY_REFERENCE_REQUIRED: /);
});

// ---- 2.1.13: deliver-first guard (live p6-l-2026-10-02-2) ------------------
// The buyer created the invite in refs mode, then ran its staged local
// init/policy/inspect steps and never sealed or delivered the invitation; the
// provider waited ten minutes for nothing. In refs mode the adapter now refuses
// the initiator's staged steps and join/next/submit progression for a session
// while the invitation ref it issued for that session is unconsumed.

const SESSION_2 = "22222222-3333-4444-8555-666666666666";
const { INVITATION_REF_TTL_MS: REF_TTL_MS } = await import("../src/local-adapter/invitation-refs.mjs");
const { access: fsAccess } = await import("node:fs/promises");

async function deliverFirstContext(t, { invitationRefs = true } = {}) {
  const ctx = await makeContext(t);
  const calls = [];
  const runs = [];
  const clock = { nowMs: 1_800_000_000_000 };
  const inviteBodies = new Map();
  const stepsBySession = new Map();
  const steps = (sessionId) => {
    if (!stepsBySession.has(sessionId)) {
      stepsBySession.set(sessionId, ["init", "inspect"].map((operation) =>
        helperStep({ manifestDigest: ctx.fixture.pin.manifestDigest, operation, sessionId })));
    }
    return stepsBySession.get(sessionId);
  };
  let nextInvite = SESSION;
  const server = ctx.make({
    invitationRefs,
    now: () => clock.nowMs,
    fetchImpl: recordingUpstream(calls, (request) => {
      if (request.params?.name === "agent_handshake_invite") {
        const sessionId = nextInvite;
        const body = {
          sessionId,
          roleAccess: `csha_${sessionId.slice(0, 8)}`,
          responderInvitation: genuineInvitation({ sessionId }),
          localAction: { helperSteps: steps(sessionId) },
        };
        inviteBodies.set(sessionId, body);
        return { ...rpcResult(body), structuredContent: body };
      }
      return rpcResult({ ok: true });
    }),
    runHelper: async (input) => {
      runs.push(input);
      return { code: 0, stderr: "", stdout: cliResult(input.args[6]) };
    },
  });
  const invite = async (id, sessionId = SESSION) => {
    nextInvite = sessionId;
    const response = await call(server, id, "agent_handshake_invite", { reference: "r", statement: "s", validForSeconds: "90" });
    return JSON.parse(response.result.content[0].text);
  };
  const refPath = (ref) => join(ctx.tmpRoot, ".clockchain", "invitation-refs", `${ref}.json`);
  const exists = (path) => fsAccess(path).then(() => true, () => false);
  // What the company signer's seal_to does with { plaintextRef }: claim the
  // issued record and consume it once the box is sealed.
  const sealTo = async (ref) => (await claimInvitationRef({ tmpRoot: ctx.tmpRoot, ref, kind: "issued", nowMs: clock.nowMs })).consume();
  return { ...ctx, calls, runs, clock, server, invite, refPath, exists, sealTo };
}

test("2.2.0: version is 2.2.0 (the 2.1.13 guard ships unchanged in behaviour)", async () => {
  const { LOCAL_ADAPTER_VERSION: version } = await import("../src/agent-handshake/v2/constants.mjs");
  assert.equal(version, "2.2.0");
});

test("2.1.13 refs mode: the initiator's staged steps are refused until the issued ref is sealed", async (t) => {
  const { server, invite, runs, sealTo, refPath, exists } = await deliverFirstContext(t);
  const issued = await invite(1);
  assert.match(issued.responderInvitationRef, /^invref_[0-9a-f]{32}$/);
  assert.equal(server.pendingCount(), 2);

  const refused = await call(server, 2, ADAPTER_TOOL);
  assert.equal(refused.result.isError, true);
  const text = refused.result.content[0].text;
  assert.match(text, /^DELIVER_INVITATION_FIRST: /);
  assert.ok(text.includes(issued.responderInvitationRef), "the refusal carries the ref");
  assert.match(text, /deliver this invitation reference to the provider through your company signer before continuing/);
  // The refusal names no tool: the company signer decides how it delivers.
  assert.doesNotMatch(text, /seal_to|deliver_invitation|rendezvous_|sealed box/);
  assert.equal(runs.length, 0, "nothing executed");
  assert.equal(server.pendingCount(), 2, "the staged steps stay queued");
  assert.equal(await exists(refPath(issued.responderInvitationRef)), true, "the refusal never consumes the ref");

  await sealTo(issued.responderInvitationRef);
  const executed = await call(server, 3, ADAPTER_TOOL);
  assert.equal(executed.result.isError, undefined, executed.result.content[0].text);
  assert.equal(runs.length, 1);
  assert.equal(runs[0].args[6], "init");
  assert.equal((await call(server, 4, ADAPTER_TOOL)).result.isError, undefined);
  assert.equal(runs.length, 2);
});

test("2.1.13 refs mode: join/next/submit for the initiator session are refused locally until delivery", async (t) => {
  const { server, invite, calls, sealTo } = await deliverFirstContext(t);
  const issued = await invite(1);
  const before = toolCalls(calls).length;
  let id = 10;
  for (const name of ["agent_handshake_join", "agent_handshake_next", "agent_handshake_submit", "agent_handshake_submit_checkpoint"]) {
    const refused = await call(server, id++, name, { access: issued.roleAccess });
    assert.equal(refused.result?.isError, true, name);
    assert.match(refused.result.content[0].text, /^DELIVER_INVITATION_FIRST: /, name);
    assert.ok(refused.result.content[0].text.includes(issued.responderInvitationRef));
  }
  assert.equal(toolCalls(calls).length, before, "nothing reached the coordinator");
  // Read-only status is not progression and another session's access is not this one.
  assert.equal((await call(server, id++, "agent_handshake_status", { access: issued.roleAccess })).result.isError, undefined);
  assert.equal((await call(server, id++, "agent_handshake_join", { access: "csha_other" })).result.isError, undefined);

  await sealTo(issued.responderInvitationRef);
  const joined = await call(server, id++, "agent_handshake_join", { access: issued.roleAccess });
  assert.equal(joined.result.isError, undefined);
  assert.equal(toolCalls(calls).at(-1).params.name, "agent_handshake_join");
});

test("2.1.13 refs mode: a seal_to that claimed then released the ref has not delivered it", async (t) => {
  const { server, invite, runs, clock, tmpRoot } = await deliverFirstContext(t);
  const issued = await invite(1);
  const claim = await claimInvitationRef({ tmpRoot, ref: issued.responderInvitationRef, kind: "issued", nowMs: clock.nowMs });
  await claim.release();
  const refused = await call(server, 2, ADAPTER_TOOL);
  assert.match(refused.result.content[0].text, /^DELIVER_INVITATION_FIRST: /);
  assert.equal(runs.length, 0);
});

test("2.1.13 refs mode: an expired undelivered ref returns a distinct refusal and never deadlocks", async (t) => {
  const { server, invite, runs, clock, refPath, exists, sealTo } = await deliverFirstContext(t);
  const stale = await invite(1);
  clock.nowMs += REF_TTL_MS;
  const expired = await call(server, 2, ADAPTER_TOOL);
  assert.equal(expired.result.isError, true);
  const text = expired.result.content[0].text;
  assert.match(text, /^DELIVER_INVITATION_EXPIRED: /);
  assert.doesNotMatch(text, /^DELIVER_INVITATION_FIRST/);
  assert.ok(text.includes(stale.responderInvitationRef));
  assert.match(text, /create a fresh invitation/i);
  assert.equal(runs.length, 0);
  assert.equal(server.pendingCount(), 0, "the stale session's steps were discarded");
  assert.equal(await exists(refPath(stale.responderInvitationRef)), false, "the expired bearer record is removed");
  // The stale session's progression keeps the same distinct refusal.
  const join = await call(server, 3, "agent_handshake_join", { access: stale.roleAccess });
  assert.match(join.result.content[0].text, /^DELIVER_INVITATION_EXPIRED: /);

  // A fresh invitation proceeds normally once delivered.
  const fresh = await invite(4, SESSION_2);
  assert.notEqual(fresh.responderInvitationRef, stale.responderInvitationRef);
  assert.match((await call(server, 5, ADAPTER_TOOL)).result.content[0].text, /^DELIVER_INVITATION_FIRST: /);
  await sealTo(fresh.responderInvitationRef);
  const executed = await call(server, 6, ADAPTER_TOOL);
  assert.equal(executed.result.isError, undefined, executed.result.content[0].text);
  assert.equal(runs.length, 1);
  assert.ok(runs[0].args[8].endsWith(`/${SESSION_2}/initiator`));
});

test("2.1.13 refs mode: a fresh invite after an unnoticed expiry abandons the stale session instead of treating the swept record as delivered", async (t) => {
  const { server, invite, runs, clock, refPath, exists, sealTo } = await deliverFirstContext(t);
  const stale = await invite(1);
  clock.nowMs += REF_TTL_MS + 1;
  // No authorize call in between: the next put sweeps the expired record.
  const fresh = await invite(2, SESSION_2);
  assert.equal(await exists(refPath(stale.responderInvitationRef)), false);
  await sealTo(fresh.responderInvitationRef);
  const executed = await call(server, 3, ADAPTER_TOOL);
  assert.equal(executed.result.isError, undefined, executed.result.content[0].text);
  assert.ok(runs[0].args[8].endsWith(`/${SESSION_2}/initiator`), "the stale session's step never runs");
  const join = await call(server, 4, "agent_handshake_join", { access: stale.roleAccess });
  assert.match(join.result.content[0].text, /^DELIVER_INVITATION_EXPIRED: /);
});

test("2.1.13: without refs mode there is no deliver-first guard", async (t) => {
  const { server, invite, runs } = await deliverFirstContext(t, { invitationRefs: false });
  const issued = await invite(1);
  assert.equal(typeof issued.responderInvitation, "string");
  assert.equal((await call(server, 2, ADAPTER_TOOL)).result.isError, undefined);
  assert.equal(runs.length, 1);
});
