// 2.2.0 handshake by reference: the adapter fills every long handshake value
// (role access, session key address, policy digest, signatures, checkpoint,
// invite terms) from its own staged results, hides the signatures from the
// model, and journals every forwarded call, every local tool call and every
// adapter-side refusal on one hash chain (C-ADP-1, TB/LLD.md §8.4).
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import {
  AGENT_HANDSHAKE_HELPER_VERSION,
  AGENT_HANDSHAKE_RELEASE_ASSET_PREFIX,
  LOCAL_ADAPTER_VERSION,
} from "../src/agent-handshake/v2/constants.mjs";
import { canonicalBytes } from "../src/core/canonical.mjs";
import { VERIFIED_HELPER_BOOTSTRAP } from "../src/harness/verified-release-action-recorder.mjs";
import { putInvitationRef } from "../src/local-adapter/invitation-refs.mjs";
import {
  ADAPTER_APPROVAL_TOOL,
  ADAPTER_DEFAULT_ENDPOINT,
  ADAPTER_TOOL,
  createLocalAdapterServer,
} from "../src/local-adapter/server.mjs";
import {
  ADAPTER_FORWARDS_FILE,
  DEFAULT_INVITE_BUDGET,
  INVITE_BUDGET_ENV,
  INVITE_TERMS_ENV,
  PUBLISHED_INVITE_TERMS,
  createForwardJournal,
  forwardEntryHash,
  resultDigest,
} from "../src/local-adapter/fill-from-local.mjs";
import { CONTRACT_BIND_TOOL } from "../src/local-adapter/contract-bind.mjs";

const sha256 = (value) => createHash("sha256").update(value).digest("hex");
const SESSION = "11111111-2222-4333-8444-555555555555";
const SESSION_2 = "22222222-3333-4444-8555-666666666666";
const ENDPOINT = "https://upstream.test/handshake/mcp";
const CHECKSUM_ADDRESS = "0xAbCdEf0123456789aBcDeF0123456789AbCdEf01";
const ADDRESS = CHECKSUM_ADDRESS.toLowerCase();
const POLICY_DIGEST = "f".repeat(64);
const SIG_1 = `0x${"1".repeat(130)}`;
const SIG_2 = `0x${"2".repeat(130)}`;
const SIG_3 = `0x${"3".repeat(130)}`;
const CHECKPOINT = Object.freeze({
  schema: "clockchain.agent-handshake-commitment-checkpoint/v1",
  sessionId: SESSION,
  role: "initiator",
  artifactType: "proposal",
  sequence: "1",
  signature: { address: ADDRESS, algorithm: "eip191", value: SIG_2 },
});

function fixtureManifest(helperBytes) {
  return {
    schema: "clockchain.agent-handshake-release-manifest/v1",
    version: AGENT_HANDSHAKE_HELPER_VERSION,
    sourceCommit: "a".repeat(40),
    nodeRuntime: "24.6.0",
    assets: [{
      platform: "node", arch: "any", upstreamSupport: "node24_portable",
      filename: "clockchain-agent-handshake.cjs",
      url: `${AGENT_HANDSHAKE_RELEASE_ASSET_PREFIX}clockchain-agent-handshake.cjs`,
      byteLength: String(helperBytes.length), sha256: sha256(helperBytes),
      nativeSignature: { type: "none", verified: null, signer: null, timestamp: null, notarized: null },
      execution: { verified: true, platform: "linux", arch: "x64", exitCode: "0", publicOutputSha256: "b".repeat(64) },
    }],
  };
}

async function makeAssetDir(t) {
  const dir = await mkdtemp(join(tmpdir(), "fill-assets-"));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const helperBytes = Buffer.from('"use strict";\n// fill test helper\n');
  const manifest = canonicalBytes(fixtureManifest(helperBytes));
  const pin = {
    version: AGENT_HANDSHAKE_HELPER_VERSION, sourceCommit: "a".repeat(40), manifestDigest: sha256(manifest),
    allowedAssetPrefix: AGENT_HANDSHAKE_RELEASE_ASSET_PREFIX,
    hostRoots: [{ kid: "root-2026-08", fingerprint: "c".repeat(64) }],
  };
  await writeFile(join(dir, "manifest.json"), manifest, { mode: 0o600 });
  await writeFile(join(dir, "clockchain-agent-handshake.cjs"), helperBytes, { mode: 0o600 });
  await writeFile(join(dir, "pin.json"), `${JSON.stringify(pin)}\n`, { mode: 0o600 });
  return { assetDir: dir, pin };
}

function helperStep({ manifestDigest, operation, sessionId = SESSION, role = "initiator", payload }) {
  const prefix = `node --input-type=commonjs --eval '${VERIFIED_HELPER_BOOTSTRAP}' ` +
    `${manifestDigest} ./manifest.json ./clockchain-agent-handshake.cjs`;
  let suffix = `${operation} --state-dir "\${TMPDIR%/}/.clockchain/handshakes/${sessionId}/${role}"`;
  if (payload !== undefined) suffix += ` --payload-base64url ${payload}`;
  const command = `${prefix} ${suffix}`;
  return {
    operation, role, sessionId, approvalTool: ADAPTER_APPROVAL_TOOL,
    commandLength: Buffer.byteLength(command), commandSha256: sha256(command), shellCommand: command,
  };
}

const b64u = (value) => Buffer.from(JSON.stringify(value)).toString("base64url");
function signPayload(operation, { sessionId = SESSION, role = "initiator", nonce = "1" } = {}) {
  return b64u({
    schema: "clockchain.agent-handshake-signing-request/v1",
    helperVersion: AGENT_HANDSHAKE_HELPER_VERSION,
    operation, role, sessionId, repositorySha: "a".repeat(40),
    sessionDeadlineMs: "1786337600000", policyDigest: POLICY_DIGEST,
    externalBusinessActionPerformed: false, nonce,
  });
}

const cliResult = (operation, extra = {}) => `${JSON.stringify({
  schema: "clockchain.agent-handshake-cli-result/v1",
  helperVersion: AGENT_HANDSHAKE_HELPER_VERSION,
  operation, ...extra,
})}\n`;

function fakeResponse(body, extraHeaders = {}) {
  const text = JSON.stringify(body);
  return { ok: true, headers: { get: (name) => (String(name).toLowerCase() === "content-type" ? "application/json" : (extraHeaders[String(name).toLowerCase()] ?? null)) }, text: async () => text };
}

const rpcResult = (body) => ({ content: [{ type: "text", text: JSON.stringify(body) }], structuredContent: body });
const call = (server, id, name, args = {}) =>
  server.handleMessage({ jsonrpc: "2.0", id, method: "tools/call", params: { name, arguments: args } });
const toolCalls = (calls) => calls.filter((c) => c.method === "tools/call");
const errorText = (response) => {
  assert.equal(response.result?.isError, true, JSON.stringify(response));
  return response.result.content[0].text;
};

// A small coordinator double: invite/accept return a role access plus the
// staged helper steps the next authorize calls run; every call returns a
// serverNonce; `refuse` makes the next call of a tool an isError refusal.
async function context(t, { serverOptions = {}, helperSign = [SIG_1, SIG_2, SIG_3] } = {}) {
  const fixture = await makeAssetDir(t);
  const tmpRoot = await mkdtemp(join(tmpdir(), "fill-tmp-"));
  t.after(() => rm(tmpRoot, { recursive: true, force: true }));
  const md = fixture.pin.manifestDigest;
  const calls = [];
  const sentHeaders = [];
  const refuse = new Set();
  // the generic host between sessions: its NON-error transient body (live p6-ta-2026-10-03-5)
  const transient = { next: 0, isError: false, status: null, body: null, throwCode: null };
  let nonce = 0;
  const steps = {
    invite: (sessionId) => [
      helperStep({ manifestDigest: md, operation: "init", sessionId }),
      helperStep({ manifestDigest: md, operation: "inspect", sessionId }),
    ],
    accept: (sessionId) => [
      helperStep({ manifestDigest: md, operation: "init", sessionId, role: "responder" }),
      helperStep({ manifestDigest: md, operation: "inspect", sessionId, role: "responder" }),
    ],
  };
  let nextSession = SESSION;
  let queuedSteps = [];
  const signQueue = [...helperSign];
  const server = createLocalAdapterServer({
    assetDir: fixture.assetDir,
    endpoint: ENDPOINT,
    tmpdir: tmpRoot,
    fetchImpl: async (url, init) => {
      const request = JSON.parse(init.body);
      calls.push(request);
      sentHeaders.push(init.headers);
      const name = request.params?.name;
      const serverNonce = `0x${String(++nonce).padStart(32, "0")}`;
      if (name === "agent_handshake_invite" && transient.next > 0) {
        transient.next -= 1;
        if (transient.throwCode !== null) throw Object.assign(new TypeError("fetch failed"), { cause: { code: transient.throwCode } });
        if (transient.status !== null) return { ok: false, status: transient.status, headers: { get: () => "text/html" }, text: async () => "Bad Gateway" };
        const body = transient.body ?? { error: "HANDSHAKE_TEMPORARILY_UNAVAILABLE", retryable: true, retryAfterMs: 120000 };
        return fakeResponse({ jsonrpc: "2.0", id: request.id, result: { ...rpcResult(body), ...(transient.isError ? { isError: true } : {}) } });
      }
      if (refuse.has(name)) {
        refuse.delete(name);
        return fakeResponse({ jsonrpc: "2.0", id: request.id, result: { content: [{ type: "text", text: JSON.stringify({ error: "V2CoordinatorError", retryable: true, serverNonce }) }], isError: true } });
      }
      let body = { ok: true, serverNonce };
      if (name === "agent_handshake_invite") {
        body = { sessionId: nextSession, role: "initiator", roleAccess: `csha_${nextSession.slice(0, 8)}_init_xxxxxxxx`, responderInvitation: "x".repeat(100), serverNonce, localAction: { helperSteps: steps.invite(nextSession) } };
      } else if (name === "agent_handshake_accept_invitation") {
        body = { sessionId: nextSession, role: "responder", roleAccess: `csha_${nextSession.slice(0, 8)}_resp_xxxxxxxx`, serverNonce, localAction: { helperSteps: steps.accept(nextSession) } };
      } else if (queuedSteps.length > 0 && name === "agent_handshake_next") {
        body = { serverNonce, localAction: { helperSteps: queuedSteps } };
        queuedSteps = [];
      }
      // The opt-in nonce echo (only when the request asked for it), distinct from any body nonce.
      const echo = init.headers?.["x-clockchain-receipt"] === "1"
        ? { _meta: { "clockchain/receipt": { serverNonce: `0x${"e".repeat(24)}${String(nonce).padStart(8, "0")}`, receiptHash: `0x${"c".repeat(63)}${nonce % 10}` } } }
        : {};
      return fakeResponse({ jsonrpc: "2.0", id: request.id, result: { ...rpcResult(body), ...echo } });
    },
    runHelper: async (input) => {
      const operation = input.args[6];
      if (operation === "init") return { code: 0, stderr: "", stdout: cliResult("init", { address: CHECKSUM_ADDRESS }) };
      if (operation === "inspect") return { code: 0, stderr: "", stdout: cliResult("inspect", { address: ADDRESS, policyDigest: POLICY_DIGEST, registration: null }) };
      if (operation === "sign") {
        const payload = JSON.parse(Buffer.from(input.args[10], "base64url").toString("utf8"));
        const signatureHex = signQueue.shift();
        const checkpoint = ["proposal", "acceptance"].includes(payload.operation) ? { ...CHECKPOINT, signature: { ...CHECKPOINT.signature, value: SIG_3 } } : null;
        return { code: 0, stderr: "", stdout: cliResult("sign", { address: ADDRESS, bytesSha256: "d".repeat(64), signatureHex, checkpoint }) };
      }
      return { code: 0, stderr: "", stdout: cliResult(operation) };
    },
    ...serverOptions,
  });
  const stageSigns = (operations, { sessionId = SESSION, role = "initiator" } = {}) => {
    queuedSteps = operations.map((operation, index) =>
      helperStep({ manifestDigest: md, operation: "sign", sessionId, role, payload: signPayload(operation, { sessionId, role, nonce: String(index) }) }));
  };
  const setSession = (sessionId) => { nextSession = sessionId; };
  return { server, calls, sentHeaders, refuse, transient, tmpRoot, stageSigns, setSession, md };
}

const lastForwarded = (calls) => toolCalls(calls).at(-1).params;

function genuineInvitation() {
  const payload = Buffer.from(JSON.stringify({
    alg: "HS256", allowedTools: ["agent_handshake_accept_invitation"], aud: "clockchain-agent-handshake",
    expMs: "2", iss: "https://mcp.clockchain.network", jti: "b532fc9a-385f-448f-a90f-a16f26056f37",
    kid: "role-2026-08-active", nbfMs: "1", role: "responder", sessionId: SESSION,
    statementDigest: "e".repeat(64), typ: "clockchain-agent-handshake-role-access", v: 1,
  })).toString("base64url");
  return `${payload}.${"A".repeat(43)}`;
}

test("2.2.1: version is 2.2.1", () => {
  assert.equal(LOCAL_ADAPTER_VERSION, "2.2.1");
});

test("2.2.0 tools/list: every handshake tool takes no long argument and access is optional", async (t) => {
  const fixtures = JSON.parse(await readFile(new URL("./fixtures/handshake-upstream-tools-2.1.8.json", import.meta.url), "utf8"));
  const fixture = await makeAssetDir(t);
  const server = createLocalAdapterServer({
    assetDir: fixture.assetDir,
    endpoint: ADAPTER_DEFAULT_ENDPOINT,
    invitationRefs: true,
    fetchImpl: async (url, init) => {
      const request = JSON.parse(init.body);
      return fakeResponse({ jsonrpc: "2.0", id: request.id, result: { tools: fixtures.tools } });
    },
  });
  const listed = await server.handleMessage({ jsonrpc: "2.0", id: 1, method: "tools/list", params: {} });
  const byName = Object.fromEntries(listed.result.tools.map((tool) => [tool.name, tool]));
  const props = (name) => Object.keys(byName[name].inputSchema.properties ?? {}).sort();
  const required = (name) => byName[name].inputSchema.required ?? [];
  assert.deepEqual(props("agent_handshake_invite"), ["reference"]);
  assert.deepEqual(required("agent_handshake_invite"), []);
  assert.deepEqual(props("agent_handshake_join"), ["access"]);
  assert.deepEqual(props("agent_handshake_submit"), ["access"]);
  assert.deepEqual(props("agent_handshake_submit_checkpoint"), ["access"]);
  assert.deepEqual(props("agent_handshake_next"), ["access", "waitMs"]);
  assert.deepEqual(props("agent_handshake_status"), ["access"]);
  assert.deepEqual(props("agent_handshake_get_certificate"), ["access"]);
  assert.deepEqual(props("agent_handshake_accept_invitation"), ["acceptanceIdempotencyKey", "invitationRef"]);
  for (const name of ["agent_handshake_join", "agent_handshake_submit", "agent_handshake_submit_checkpoint", "agent_handshake_next", "agent_handshake_status", "agent_handshake_get_certificate"]) {
    assert.deepEqual(required(name), [], name);
    assert.match(byName[name].description, /adapter/i, name);
  }
  // The §1 lint over every model-facing handshake tool: no object input and
  // no string pattern admitting more than 40 hex/base64 chars.
  for (const tool of listed.result.tools) {
    if (tool.name === "sign_agent_contract_bind") continue; // signer-only, hidden by the bind composite (WP2)
    for (const [key, schema] of Object.entries(tool.inputSchema.properties ?? {})) {
      assert.notEqual(schema.type, "object", `${tool.name}.${key}`);
      assert.equal(schema.anyOf, undefined, `${tool.name}.${key}`);
      const pattern = schema.pattern ?? "";
      const longHex = /\{(4[1-9]|[5-9][0-9]|[1-9][0-9]{2,})\}/.test(pattern);
      assert.equal(longHex, false, `${tool.name}.${key} pattern ${pattern}`);
    }
  }
});

test("2.2.0 tools/list: without pinned terms the invite schema is left as published", async (t) => {
  const fixtures = JSON.parse(await readFile(new URL("./fixtures/handshake-upstream-tools-2.1.8.json", import.meta.url), "utf8"));
  const fixture = await makeAssetDir(t);
  const server = createLocalAdapterServer({
    assetDir: fixture.assetDir,
    endpoint: ENDPOINT,
    fetchImpl: async (url, init) => fakeResponse({ jsonrpc: "2.0", id: JSON.parse(init.body).id, result: { tools: fixtures.tools } }),
  });
  const listed = await server.handleMessage({ jsonrpc: "2.0", id: 1, method: "tools/list", params: {} });
  const invite = listed.result.tools.find((tool) => tool.name === "agent_handshake_invite");
  const upstream = fixtures.tools.find((tool) => tool.name === "agent_handshake_invite");
  assert.deepEqual(invite, upstream);
});

test("2.2.0 join: access, helperVersion, sessionKeyAddress and policyDigest come from the adapter's own results", async (t) => {
  const { server, calls } = await context(t);
  const invited = JSON.parse((await call(server, 1, "agent_handshake_invite", { reference: "r", statement: "s", validForSeconds: "90" })).result.content[0].text);
  const initd = await call(server, 2, ADAPTER_TOOL);
  assert.equal(initd.result.isError, undefined, JSON.stringify(initd));
  const inspected = await call(server, 3, ADAPTER_TOOL);
  const visible = inspected.result.content[0].text;
  assert.equal(visible.includes(ADDRESS), false, "the full address is not shown");
  assert.equal(visible.includes(POLICY_DIGEST), false, "the policy digest is not shown");
  assert.equal(JSON.parse(visible).operation, "inspect");
  const joined = await call(server, 4, "agent_handshake_join", {});
  assert.equal(joined.result.isError, undefined, JSON.stringify(joined));
  assert.deepEqual(lastForwarded(calls), {
    name: "agent_handshake_join",
    arguments: { access: invited.roleAccess, helperVersion: AGENT_HANDSHAKE_HELPER_VERSION, sessionKeyAddress: ADDRESS, policyDigest: POLICY_DIGEST },
  });
});

test("2.2.0 join: a model-supplied value must equal the local one byte for byte", async (t) => {
  const { server, calls } = await context(t);
  const invited = JSON.parse((await call(server, 1, "agent_handshake_invite", { reference: "r", statement: "s", validForSeconds: "90" })).result.content[0].text);
  await call(server, 2, ADAPTER_TOOL);
  await call(server, 3, ADAPTER_TOOL);
  const before = toolCalls(calls).length;
  const wrong = `0x${"9".repeat(40)}`;
  const text = errorText(await call(server, 4, "agent_handshake_join", { sessionKeyAddress: wrong }));
  assert.match(text, /^LOCAL_VALUE_MISMATCH: /);
  assert.match(text, /sessionKeyAddress/);
  assert.equal(text.includes(ADDRESS), false);
  assert.equal(errorText(await call(server, 5, "agent_handshake_join", { policyDigest: "0".repeat(64) })).startsWith("LOCAL_VALUE_MISMATCH: "), true);
  assert.equal(errorText(await call(server, 6, "agent_handshake_join", { helperVersion: "9.9.9" })).startsWith("LOCAL_VALUE_MISMATCH: "), true);
  assert.equal(errorText(await call(server, 7, "agent_handshake_join", { access: invited.roleAccess, sessionKeyAddress: wrong })).startsWith("LOCAL_VALUE_MISMATCH: "), true);
  assert.equal(toolCalls(calls).length, before, "nothing was forwarded");
  // An old brief that copies the exact values still works (checksum casing is the same address).
  const ok = await call(server, 8, "agent_handshake_join", { access: invited.roleAccess, helperVersion: AGENT_HANDSHAKE_HELPER_VERSION, sessionKeyAddress: CHECKSUM_ADDRESS, policyDigest: POLICY_DIGEST });
  assert.equal(ok.result.isError, undefined);
  assert.equal(lastForwarded(calls).arguments.sessionKeyAddress, CHECKSUM_ADDRESS, "a supplied equal value is forwarded as the model wrote it");
});

test("2.2.0 sign: the signature and checkpoint are held locally and submitted in order with no arguments", async (t) => {
  const { server, calls, stageSigns } = await context(t);
  const invited = JSON.parse((await call(server, 1, "agent_handshake_invite", { reference: "r", statement: "s", validForSeconds: "90" })).result.content[0].text);
  await call(server, 2, ADAPTER_TOOL);
  await call(server, 3, ADAPTER_TOOL);
  await call(server, 4, "agent_handshake_join", {});
  stageSigns(["identity_claim", "proposal"]);
  await call(server, 5, "agent_handshake_next", {});
  const first = await call(server, 6, ADAPTER_TOOL);
  const second = await call(server, 7, ADAPTER_TOOL);
  for (const response of [first, second]) {
    const text = response.result.content[0].text;
    for (const secret of [SIG_1, SIG_2, SIG_3]) assert.equal(text.includes(secret.slice(2, 40)), false);
    const parsed = JSON.parse(text);
    assert.equal(parsed.signed, true);
    assert.equal(parsed.heldLocally, true);
    assert.equal(parsed.signatureHex, undefined);
    assert.equal(parsed.checkpoint, undefined);
  }
  assert.equal(JSON.parse(first.result.content[0].text).checkpointHeldLocally, false);
  assert.equal(JSON.parse(second.result.content[0].text).checkpointHeldLocally, true);

  assert.equal((await call(server, 8, "agent_handshake_submit", {})).result.isError, undefined);
  assert.deepEqual(lastForwarded(calls).arguments, { access: invited.roleAccess, policyDigest: POLICY_DIGEST, signatureHex: SIG_1 });
  assert.equal((await call(server, 9, "agent_handshake_submit_checkpoint", {})).result.isError, undefined);
  assert.deepEqual(lastForwarded(calls).arguments, {
    access: invited.roleAccess,
    artifactSignatureHex: SIG_2,
    checkpoint: { ...CHECKPOINT, signature: { ...CHECKPOINT.signature, value: SIG_3 } },
  });
  assert.equal((await call(server, 10, "agent_handshake_submit", {})).result.isError, undefined);
  assert.deepEqual(lastForwarded(calls).arguments, { access: invited.roleAccess, policyDigest: POLICY_DIGEST, signatureHex: SIG_2 });
  // Both signatures are spent: a further submit gets no signature (the coordinator answers as before).
  await call(server, 11, "agent_handshake_submit", {});
  assert.deepEqual(lastForwarded(calls).arguments, { access: invited.roleAccess, policyDigest: POLICY_DIGEST });
});

test("2.2.0 sign: a refused submit keeps the signature for the retry; a wrong signature never leaves the machine", async (t) => {
  const { server, calls, stageSigns, refuse } = await context(t);
  await call(server, 1, "agent_handshake_invite", { reference: "r", statement: "s", validForSeconds: "90" });
  await call(server, 2, ADAPTER_TOOL);
  await call(server, 3, ADAPTER_TOOL);
  stageSigns(["identity_claim"]);
  await call(server, 4, "agent_handshake_next", {});
  await call(server, 5, ADAPTER_TOOL);
  const before = toolCalls(calls).length;
  assert.match(errorText(await call(server, 6, "agent_handshake_submit", { signatureHex: SIG_2 })), /^LOCAL_VALUE_MISMATCH: .*signatureHex/);
  assert.equal(toolCalls(calls).length, before);
  refuse.add("agent_handshake_submit");
  assert.equal((await call(server, 7, "agent_handshake_submit", {})).result.isError, true);
  assert.equal(lastForwarded(calls).arguments.signatureHex, SIG_1);
  assert.equal((await call(server, 8, "agent_handshake_submit", { signatureHex: SIG_1 })).result.isError, undefined);
  assert.equal(lastForwarded(calls).arguments.signatureHex, SIG_1);
});

test("2.2.0 access: optional with one live session, SESSION_AMBIGUOUS with two, forwarded as given with none", async (t) => {
  const { server, calls, setSession } = await context(t);
  await call(server, 1, "agent_handshake_status", {});
  assert.deepEqual(lastForwarded(calls).arguments, {}, "no session held: nothing to fill");
  const first = JSON.parse((await call(server, 2, "agent_handshake_invite", { reference: "r", statement: "s", validForSeconds: "90" })).result.content[0].text);
  await call(server, 3, "agent_handshake_status", {});
  assert.deepEqual(lastForwarded(calls).arguments, { access: first.roleAccess });
  setSession(SESSION_2);
  const second = JSON.parse((await call(server, 4, "agent_handshake_invite", { reference: "r", statement: "s", validForSeconds: "90" })).result.content[0].text);
  const count = toolCalls(calls).length;
  const ambiguous = errorText(await call(server, 5, "agent_handshake_next", {}));
  assert.match(ambiguous, /^SESSION_AMBIGUOUS: /);
  assert.equal(ambiguous.includes(first.roleAccess), false);
  assert.equal(toolCalls(calls).length, count);
  await call(server, 6, "agent_handshake_get_certificate", { access: second.roleAccess });
  assert.deepEqual(lastForwarded(calls).arguments, { access: second.roleAccess });
  // An access this adapter never saw is forwarded untouched (the coordinator is its authority).
  await call(server, 7, "agent_handshake_join", { access: "csha_other_xxxxxxxxxxxxxxxxx" });
  assert.deepEqual(lastForwarded(calls).arguments, { access: "csha_other_xxxxxxxxxxxxxxxxx" });
});

test("2.2.0 accept: the responder's role access from the accept result fills later calls", async (t) => {
  const { server, calls, tmpRoot } = await context(t);
  const goodRef = await putInvitationRef({ tmpRoot, kind: "received", invitation: genuineInvitation() });
  const accepted = await call(server, 1, "agent_handshake_accept_invitation", { invitationRef: goodRef });
  assert.equal(accepted.result.isError, undefined, JSON.stringify(accepted));
  const roleAccess = JSON.parse(accepted.result.content[0].text).roleAccess;
  await call(server, 2, ADAPTER_TOOL);
  await call(server, 3, ADAPTER_TOOL);
  await call(server, 4, "agent_handshake_join", {});
  assert.deepEqual(lastForwarded(calls).arguments, { access: roleAccess, helperVersion: AGENT_HANDSHAKE_HELPER_VERSION, sessionKeyAddress: ADDRESS, policyDigest: POLICY_DIGEST });
});

test("2.2.0 invite: pinned published terms are filled; any other value is refused locally", async (t) => {
  const pinned = { reference: "R-1", statement: "Alpha and Beta authorize these agents for 90 seconds.", validForSeconds: "90", identityPolicy: { erc8004: "not_required", chainId: null, registryAddress: null } };
  const { server, calls } = await context(t, { serverOptions: { inviteTerms: pinned } });
  const ok = await call(server, 1, "agent_handshake_invite", {});
  assert.equal(ok.result.isError, undefined);
  assert.deepEqual(lastForwarded(calls).arguments, pinned);
  const count = toolCalls(calls).length;
  assert.match(errorText(await call(server, 2, "agent_handshake_invite", { reference: "R-2" })), /^LOCAL_VALUE_MISMATCH: .*reference/);
  assert.match(errorText(await call(server, 3, "agent_handshake_invite", { identityPolicy: { erc8004: "required_fresh", chainId: "eip155:11155111", registryAddress: "0x8004a818bfb912233c491871b3d84c89a494bd9e" } })), /^LOCAL_VALUE_MISMATCH: .*identityPolicy/);
  assert.equal(toolCalls(calls).length, count);
  // The exact pinned values (key order aside) are accepted.
  const same = await call(server, 4, "agent_handshake_invite", { identityPolicy: { registryAddress: null, chainId: null, erc8004: "not_required" }, reference: "R-1" });
  assert.equal(same.result.isError, undefined);
});

test("2.2.0 invite: the default hosted endpoint pins the coordinator's published terms; the env overrides; a bad pin fails closed", async (t) => {
  assert.equal(PUBLISHED_INVITE_TERMS.reference, "NS-1847");
  assert.equal(PUBLISHED_INVITE_TERMS.validForSeconds, "90");
  assert.equal(PUBLISHED_INVITE_TERMS.identityPolicy.erc8004, "required_fresh");
  const previous = process.env[INVITE_TERMS_ENV];
  t.after(() => { if (previous === undefined) delete process.env[INVITE_TERMS_ENV]; else process.env[INVITE_TERMS_ENV] = previous; });
  delete process.env[INVITE_TERMS_ENV];
  const hosted = await context(t, { serverOptions: { endpoint: ADAPTER_DEFAULT_ENDPOINT } });
  await call(hosted.server, 1, "agent_handshake_invite", {});
  assert.deepEqual(lastForwarded(hosted.calls).arguments, PUBLISHED_INVITE_TERMS);

  const env = { reference: "E-1", statement: "env terms", validForSeconds: "60", identityPolicy: { erc8004: "not_required", chainId: null, registryAddress: null } };
  process.env[INVITE_TERMS_ENV] = JSON.stringify(env);
  const overridden = await context(t);
  await call(overridden.server, 1, "agent_handshake_invite", {});
  assert.deepEqual(lastForwarded(overridden.calls).arguments, env);

  process.env[INVITE_TERMS_ENV] = JSON.stringify({ ...env, extra: 1 });
  const broken = await context(t);
  assert.match(errorText(await call(broken.server, 1, "agent_handshake_invite", {})), /^INVITE_TERMS_PIN_INVALID: /);
  assert.equal(toolCalls(broken.calls).length, 0);
});

test("2.2.0 refs mode: the deliver-first guard still applies when access is omitted", async (t) => {
  const { server, calls } = await context(t, { serverOptions: { invitationRefs: true } });
  await call(server, 1, "agent_handshake_invite", { reference: "r", statement: "s", validForSeconds: "90" });
  const count = toolCalls(calls).length;
  for (const name of ["agent_handshake_join", "agent_handshake_next", "agent_handshake_submit", "agent_handshake_submit_checkpoint"]) {
    assert.match(errorText(await call(server, 2, name, {})), /^DELIVER_INVITATION_FIRST: /, name);
  }
  assert.equal(toolCalls(calls).length, count);
});

test("2.2.0 journal (C-ADP-1): every forwarded call, filled or not, and every local call is journaled, hash-chained, 0600", async (t) => {
  const { server, tmpRoot, stageSigns } = await context(t);
  await call(server, 1, "agent_handshake_invite", { reference: "r", statement: "s", validForSeconds: "90" });
  await call(server, 2, ADAPTER_TOOL);
  await call(server, 3, ADAPTER_TOOL);
  await call(server, 4, "agent_handshake_status", { access: "csha_11111111_init_xxxxxxxx" }); // nothing filled: a forward line all the same
  await call(server, 5, "agent_handshake_join", {});
  stageSigns(["identity_claim"]);
  await call(server, 6, "agent_handshake_next", { waitMs: 0 });
  await call(server, 7, ADAPTER_TOOL);
  await call(server, 8, "agent_handshake_submit", { policyDigest: POLICY_DIGEST });
  const path = join(tmpRoot, ADAPTER_FORWARDS_FILE);
  assert.equal((await stat(path)).mode & 0o777, 0o600);
  assert.equal((await stat(join(path, ".."))).mode & 0o777, 0o700);
  const all = (await readFile(path, "utf8")).trim().split("\n").map((line) => JSON.parse(line));
  assert.deepEqual(all.map((line) => [line.kind, line.tool]), [
    ["forward", "agent_handshake_invite"],
    ["local", ADAPTER_TOOL],
    ["local", ADAPTER_TOOL],
    ["forward", "agent_handshake_status"],
    ["forward", "agent_handshake_join"],
    ["forward", "agent_handshake_next"],
    ["local", ADAPTER_TOOL],
    ["forward", "agent_handshake_submit"],
  ]);
  let prev = null;
  all.forEach((line, index) => {
    assert.equal(line.v, 1);
    assert.equal(line.seq, index);
    assert.equal(line.prevHash, prev);
    assert.equal(line.hash, forwardEntryHash(line));
    assert.equal(line.outcome, "ok");
    prev = line.hash;
  });
  for (const line of all.filter((l) => l.kind === "forward")) assert.match(line.serverNonce, /^0x[0-9a-f]{32}$/);
  // Unfilled forwards: the forwarded args are the model's, nothing filled.
  for (const line of [all[0], all[3]]) {
    assert.deepEqual(line.filled, []);
    assert.deepEqual(line.forwardedArgs, line.modelArgs);
  }
  // Local lines: the staged step, the receipt that carried it, the result digest.
  const locals = all.filter((l) => l.kind === "local");
  assert.deepEqual(locals.map((l) => l.operation), ["init", "inspect", "sign"]);
  assert.deepEqual(all[0].stagedStepDigests, [locals[0].stagedStepDigest, locals[1].stagedStepDigest]);
  assert.deepEqual(all[5].stagedStepDigests, [locals[2].stagedStepDigest]);
  for (const [local, source] of [[locals[0], all[0]], [locals[1], all[0]], [locals[2], all[5]]]) {
    assert.equal(local.sessionId, SESSION);
    assert.equal(local.role, "initiator");
    assert.match(local.stagedStepDigest, /^[0-9a-f]{64}$/);
    assert.deepEqual(local.localActionSource, { sessionId: SESSION, receiptHash: source.receiptHash });
    assert.match(local.resultDigest, /^[0-9a-f]{64}$/);
  }
  const lines = all.filter((l) => l.kind === "forward" && l.filled.length > 0);
  assert.deepEqual(lines.map((line) => line.tool), ["agent_handshake_join", "agent_handshake_next", "agent_handshake_submit"]);
  assert.deepEqual(lines[0].modelArgs, {});
  assert.deepEqual(lines[0].filled, ["access", "helperVersion", "sessionKeyAddress", "policyDigest"]);
  assert.deepEqual(lines[0].forwardedArgs, { access: "csha_11111111_init_xxxxxxxx", helperVersion: AGENT_HANDSHAKE_HELPER_VERSION, sessionKeyAddress: ADDRESS, policyDigest: POLICY_DIGEST });
  assert.deepEqual(lines[1].filled, ["access"]);
  assert.deepEqual(lines[1].forwardedArgs, { waitMs: 0, access: "csha_11111111_init_xxxxxxxx" });
  assert.deepEqual(lines[2].modelArgs, { policyDigest: POLICY_DIGEST });
  assert.deepEqual(lines[2].filled, ["access", "signatureHex"]);
  // Every model field equals the same forwarded field (R8 condition 2).
  for (const line of all.filter((l) => l.kind === "forward")) {
    for (const [key, value] of Object.entries(line.modelArgs)) assert.deepEqual(line.forwardedArgs[key], value);
  }
});

test("2.2.0 journal: accept_invitation by reference is journaled with the expanded invitation", async (t) => {
  const { server, tmpRoot } = await context(t);
  const genuine = genuineInvitation();
  const ref = await putInvitationRef({ tmpRoot, kind: "received", invitation: genuine });
  await call(server, 1, "agent_handshake_accept_invitation", { invitationRef: ref, acceptanceIdempotencyKey: "k1" });
  const [line] = (await readFile(join(tmpRoot, ADAPTER_FORWARDS_FILE), "utf8")).trim().split("\n").map((l) => JSON.parse(l));
  assert.equal(line.tool, "agent_handshake_accept_invitation");
  assert.deepEqual(line.modelArgs, { invitationRef: ref, acceptanceIdempotencyKey: "k1" });
  assert.deepEqual(line.forwardedArgs, { invitation: genuine, acceptanceIdempotencyKey: "k1" });
  assert.deepEqual(line.filled, ["invitation"]);
  assert.deepEqual(line.dropped, ["invitationRef"]);
});

// --- per-run invite budget (plan: at most 3 handshake invites per run) -------------------

const PINNED_TERMS = { reference: "R-1", statement: "Alpha and Beta authorize these agents for 90 seconds.", validForSeconds: "90", identityPolicy: { erc8004: "not_required", chainId: null, registryAddress: null } };
const inviteCalls = (calls) => toolCalls(calls).filter((c) => c.params.name === "agent_handshake_invite");

test("invite budget: the default is 3 per run; the 4th invite is refused INVITE_BUDGET_EXHAUSTED and never forwarded", async (t) => {
  assert.equal(DEFAULT_INVITE_BUDGET, 3);
  const previous = process.env[INVITE_BUDGET_ENV];
  t.after(() => { if (previous === undefined) delete process.env[INVITE_BUDGET_ENV]; else process.env[INVITE_BUDGET_ENV] = previous; });
  delete process.env[INVITE_BUDGET_ENV];
  const { server, calls } = await context(t, { serverOptions: { inviteTerms: PINNED_TERMS } });
  for (let i = 1; i <= 3; i += 1) assert.equal((await call(server, i, "agent_handshake_invite", {})).result.isError, undefined, `invite ${i}`);
  const text = errorText(await call(server, 4, "agent_handshake_invite", {}));
  assert.match(text, /^INVITE_BUDGET_EXHAUSTED: this run already sent 3 of its 3 allowed handshake invitations/);
  assert.match(text, /Nothing was sent to the coordinator/);
  assert.deepEqual(JSON.parse(text.slice(text.indexOf("{"))), { refusal: "INVITE_BUDGET_EXHAUSTED", tool: "agent_handshake_invite", sent: 3, budget: 3 });
  assert.equal(inviteCalls(calls).length, 3);
  // and it stays refused; other tools still pass
  assert.match(errorText(await call(server, 5, "agent_handshake_invite", {})), /^INVITE_BUDGET_EXHAUSTED: /);
  assert.equal((await call(server, 6, "agent_handshake_status", { access: "csha_11111111_init_xxxxxxxx" })).result.isError, undefined);
});

test("invite budget: a coordinator-refused invite counts (it was sent); a locally refused one does not", async (t) => {
  const { server, calls, refuse } = await context(t, { serverOptions: { inviteTerms: PINNED_TERMS } });
  refuse.add("agent_handshake_invite");
  assert.equal((await call(server, 1, "agent_handshake_invite", {})).result.isError, true); // sent, refused upstream
  assert.match(errorText(await call(server, 2, "agent_handshake_invite", { reference: "R-2" })), /^LOCAL_VALUE_MISMATCH: /); // never sent
  await call(server, 3, "agent_handshake_invite", {});
  await call(server, 4, "agent_handshake_invite", {});
  assert.match(errorText(await call(server, 5, "agent_handshake_invite", {})), /^INVITE_BUDGET_EXHAUSTED: .*3 of its 3/);
  assert.equal(inviteCalls(calls).length, 3);
});

test("invite budget: also caps a proxied invite (no pinned terms), and concurrent invites never overshoot", async (t) => {
  const { server, calls } = await context(t, { serverOptions: { inviteTerms: null } });
  const results = await Promise.all([1, 2, 3, 4, 5].map((i) => call(server, i, "agent_handshake_invite", { reference: "r", statement: "s", validForSeconds: "90" })));
  assert.equal(results.filter((r) => r.result?.isError === true).length, 2);
  assert.equal(inviteCalls(calls).length, 3);
});

test("invite budget: a restarted adapter (same run epoch) seeds the count from the forwarding journal", async (t) => {
  const first = await context(t, { serverOptions: { inviteTerms: PINNED_TERMS } });
  await call(first.server, 1, "agent_handshake_invite", {});
  await call(first.server, 2, "agent_handshake_invite", {});
  // a KeepAlive restart: a fresh server on the same TMPDIR
  const fixtureCalls = [];
  const second = createLocalAdapterServer({
    assetDir: (await makeAssetDir(t)).assetDir,
    endpoint: ENDPOINT,
    tmpdir: first.tmpRoot,
    inviteTerms: PINNED_TERMS,
    fetchImpl: async (url, init) => {
      const request = JSON.parse(init.body);
      fixtureCalls.push(request);
      return fakeResponse({ jsonrpc: "2.0", id: request.id, result: rpcResult({ sessionId: SESSION_2, role: "initiator", roleAccess: "csha_22222222_init_xxxxxxxx", serverNonce: `0x${"9".repeat(32)}` }) });
    },
  });
  assert.equal((await call(second, 3, "agent_handshake_invite", {})).result.isError, undefined);
  assert.match(errorText(await call(second, 4, "agent_handshake_invite", {})), /^INVITE_BUDGET_EXHAUSTED: .*3 of its 3/);
  assert.equal(inviteCalls(fixtureCalls).length, 1);
});

test("invite budget: the option / env override it; null or \"off\" removes the cap; a malformed value fails closed", async (t) => {
  const one = await context(t, { serverOptions: { inviteTerms: PINNED_TERMS, inviteBudget: 1 } });
  await call(one.server, 1, "agent_handshake_invite", {});
  assert.match(errorText(await call(one.server, 2, "agent_handshake_invite", {})), /1 of its 1/);

  const uncapped = await context(t, { serverOptions: { inviteTerms: PINNED_TERMS, inviteBudget: null } });
  for (let i = 1; i <= 5; i += 1) assert.equal((await call(uncapped.server, i, "agent_handshake_invite", {})).result.isError, undefined);

  const previous = process.env[INVITE_BUDGET_ENV];
  t.after(() => { if (previous === undefined) delete process.env[INVITE_BUDGET_ENV]; else process.env[INVITE_BUDGET_ENV] = previous; });
  process.env[INVITE_BUDGET_ENV] = "2";
  const env = await context(t, { serverOptions: { inviteTerms: PINNED_TERMS } });
  await call(env.server, 1, "agent_handshake_invite", {});
  await call(env.server, 2, "agent_handshake_invite", {});
  assert.match(errorText(await call(env.server, 3, "agent_handshake_invite", {})), /2 of its 2/);

  for (const bad of ["0", "-1", "3.5", "abc", "1000"]) {
    process.env[INVITE_BUDGET_ENV] = bad;
    const broken = await context(t, { serverOptions: { inviteTerms: PINNED_TERMS } });
    assert.match(errorText(await call(broken.server, 1, "agent_handshake_invite", {})), /^INVITE_BUDGET_PIN_INVALID: /, bad);
    assert.equal(inviteCalls(broken.calls).length, 0, bad);
  }
  delete process.env[INVITE_BUDGET_ENV];
  const zero = await context(t, { serverOptions: { inviteTerms: PINNED_TERMS, inviteBudget: 0 } });
  assert.match(errorText(await call(zero.server, 1, "agent_handshake_invite", {})), /^INVITE_BUDGET_PIN_INVALID: /);
  assert.equal(inviteCalls(zero.calls).length, 0);
});

// --- transient invite refusals do not spend the budget (live p6-ta-2026-10-03-5) ----------

const journalLines = async (tmpRoot) =>
  (await readFile(join(tmpRoot, ADAPTER_FORWARDS_FILE), "utf8")).split("\n").filter(Boolean).map((l) => JSON.parse(l));
// C-ADP-1: a forward line's outcome, or a refused-local line's refusal code.
const outcomeOrCode = (l) => (l.kind === "refused-local" ? l.code : l.outcome);

test("invite budget: an invite the coordinator refused as transient (host between sessions) does not count; it is journaled \"transient\"", async (t) => {
  const { server, calls, transient, tmpRoot } = await context(t, { serverOptions: { inviteTerms: PINNED_TERMS } });
  transient.next = 5;
  for (let i = 1; i <= 5; i += 1) {
    const r = await call(server, i, "agent_handshake_invite", {});
    assert.equal(r.result.isError, undefined, `transient ${i} is relayed as the host answered it`);
    assert.equal(r.result.structuredContent.error, "HANDSHAKE_TEMPORARILY_UNAVAILABLE");
  }
  // three real invites still fit; the fourth is over budget
  for (let i = 6; i <= 8; i += 1) assert.equal((await call(server, i, "agent_handshake_invite", {})).result.isError, undefined, `invite ${i}`);
  assert.match(errorText(await call(server, 9, "agent_handshake_invite", {})), /^INVITE_BUDGET_EXHAUSTED: .*3 of its 3/);
  assert.equal(inviteCalls(calls).length, 8);
  const lines = (await journalLines(tmpRoot)).filter((l) => l.tool === "agent_handshake_invite");
  // C-ADP-1: the locally refused 9th invite is a refused-local line with its code.
  assert.deepEqual(lines.map(outcomeOrCode), ["transient", "transient", "transient", "transient", "transient", "ok", "ok", "ok", "INVITE_BUDGET_EXHAUSTED"]);
  assert.deepEqual(lines.map((l) => l.kind), [...Array(8).fill("forward"), "refused-local"]);
  for (const l of lines) assert.equal(l.hash, forwardEntryHash(l));
});

test("invite budget: an isError transient body (v2 public tools) is transient too; any other refusal still counts", async (t) => {
  const { server, calls, transient, refuse, tmpRoot } = await context(t, { serverOptions: { inviteTerms: PINNED_TERMS } });
  transient.next = 2;
  transient.isError = true;
  await call(server, 1, "agent_handshake_invite", {});
  await call(server, 2, "agent_handshake_invite", {});
  refuse.add("agent_handshake_invite"); // isError V2CoordinatorError (retryable): sent, counts
  await call(server, 3, "agent_handshake_invite", {});
  await call(server, 4, "agent_handshake_invite", {});
  await call(server, 5, "agent_handshake_invite", {});
  assert.match(errorText(await call(server, 6, "agent_handshake_invite", {})), /^INVITE_BUDGET_EXHAUSTED: .*3 of its 3/);
  assert.equal(inviteCalls(calls).length, 5);
  assert.deepEqual((await journalLines(tmpRoot)).map(outcomeOrCode), ["transient", "transient", "refused", "ok", "ok", "INVITE_BUDGET_EXHAUSTED"]);
});

test("invite budget: a body with a session in it is never transient, whatever its error field says", async (t) => {
  const { isTransientInviteRefusal } = await import("../src/local-adapter/fill-from-local.mjs");
  const body = { error: "HANDSHAKE_TEMPORARILY_UNAVAILABLE", retryable: true, retryAfterMs: 5000 };
  assert.equal(isTransientInviteRefusal({ result: rpcResult(body) }), true);
  assert.equal(isTransientInviteRefusal({ result: rpcResult({ ...body, sessionId: SESSION }) }), false);
  assert.equal(isTransientInviteRefusal({ result: rpcResult({ ...body, roleAccess: "csha_x" }) }), false);
  assert.equal(isTransientInviteRefusal({ result: rpcResult({ ...body, retryable: false }) }), false);
  assert.equal(isTransientInviteRefusal({ result: rpcResult({ error: "HANDSHAKE_UNAVAILABLE", retryable: true }) }), false);
  assert.equal(isTransientInviteRefusal({ error: { code: -32603, message: "upstream failed" } }), false);
  assert.equal(isTransientInviteRefusal({ result: { content: [{ type: "text", text: "not json" }] } }), false);
});

test("invite budget: a restarted adapter recounts from the journal without the transient lines", async (t) => {
  const first = await context(t, { serverOptions: { inviteTerms: PINNED_TERMS } });
  first.transient.next = 3;
  for (let i = 1; i <= 3; i += 1) await call(first.server, i, "agent_handshake_invite", {}); // transient
  await call(first.server, 4, "agent_handshake_invite", {}); // minted: counts
  const fixtureCalls = [];
  const second = createLocalAdapterServer({
    assetDir: (await makeAssetDir(t)).assetDir,
    endpoint: ENDPOINT,
    tmpdir: first.tmpRoot,
    inviteTerms: PINNED_TERMS,
    fetchImpl: async (url, init) => {
      const request = JSON.parse(init.body);
      fixtureCalls.push(request);
      return fakeResponse({ jsonrpc: "2.0", id: request.id, result: rpcResult({ sessionId: SESSION_2, role: "initiator", roleAccess: "csha_22222222_init_xxxxxxxx", serverNonce: `0x${"9".repeat(32)}` }) });
    },
  });
  assert.equal((await call(second, 5, "agent_handshake_invite", {})).result.isError, undefined);
  assert.equal((await call(second, 6, "agent_handshake_invite", {})).result.isError, undefined);
  assert.match(errorText(await call(second, 7, "agent_handshake_invite", {})), /^INVITE_BUDGET_EXHAUSTED: .*3 of its 3/);
  assert.equal(inviteCalls(fixtureCalls).length, 2);
});

test("invite budget: a proxied (unpinned) transient invite gives its reservation back too", async (t) => {
  const { server, calls, transient } = await context(t, { serverOptions: { inviteTerms: null } });
  transient.next = 4;
  const args = { reference: "r", statement: "s", validForSeconds: "90" };
  for (let i = 1; i <= 4; i += 1) await call(server, i, "agent_handshake_invite", args);
  for (let i = 5; i <= 7; i += 1) assert.equal((await call(server, i, "agent_handshake_invite", args)).result.isError, undefined);
  assert.match(errorText(await call(server, 8, "agent_handshake_invite", args)), /^INVITE_BUDGET_EXHAUSTED: /);
  assert.equal(inviteCalls(calls).length, 7);
});

test("invite budget: an invite that never reached the coordinator (host restarting: 502/503, connection refused) is refused UPSTREAM_UNAVAILABLE and does not count", async (t) => {
  for (const variant of [{ status: 502 }, { status: 503 }, { throwCode: "ECONNREFUSED" }]) {
    const { server, transient, tmpRoot } = await context(t, { serverOptions: { inviteTerms: PINNED_TERMS } });
    transient.next = 4;
    Object.assign(transient, variant);
    for (let i = 1; i <= 4; i += 1) {
      const r = await call(server, i, "agent_handshake_invite", {});
      assert.match(r.error?.message ?? "", /^UPSTREAM_UNAVAILABLE: the coordinator was not reached/, JSON.stringify(variant));
    }
    for (let i = 5; i <= 7; i += 1) assert.equal((await call(server, i, "agent_handshake_invite", {})).result.isError, undefined);
    assert.match(errorText(await call(server, 8, "agent_handshake_invite", {})), /^INVITE_BUDGET_EXHAUSTED: .*3 of its 3/);
    assert.deepEqual((await journalLines(tmpRoot)).map(outcomeOrCode), ["transient", "transient", "transient", "transient", "ok", "ok", "ok", "INVITE_BUDGET_EXHAUSTED"]);
  }
});

test("invite budget: any other upstream failure (a 500, a timeout) may have applied: generic error, and it counts", async (t) => {
  const { server, transient, tmpRoot } = await context(t, { serverOptions: { inviteTerms: PINNED_TERMS } });
  transient.next = 1;
  transient.status = 500;
  const r = await call(server, 1, "agent_handshake_invite", {});
  assert.equal(r.error?.message, "Clockchain local adapter upstream request failed.");
  await call(server, 2, "agent_handshake_invite", {});
  await call(server, 3, "agent_handshake_invite", {});
  assert.match(errorText(await call(server, 4, "agent_handshake_invite", {})), /^INVITE_BUDGET_EXHAUSTED: /);
  assert.deepEqual((await journalLines(tmpRoot)).map(outcomeOrCode), ["error", "ok", "ok", "INVITE_BUDGET_EXHAUSTED"]);
});

test("invite budget: the host's window-ended refusal (RENDEZVOUS_UNAVAILABLE, no session) does not count", async (t) => {
  const { server, transient } = await context(t, { serverOptions: { inviteTerms: PINNED_TERMS } });
  transient.next = 2;
  transient.body = { reason: "RENDEZVOUS_UNAVAILABLE", message: "Generic host stopped." };
  await call(server, 1, "agent_handshake_invite", {});
  transient.isError = true;
  await call(server, 2, "agent_handshake_invite", {});
  for (let i = 3; i <= 5; i += 1) assert.equal((await call(server, i, "agent_handshake_invite", {})).result.isError, undefined);
  assert.match(errorText(await call(server, 6, "agent_handshake_invite", {})), /^INVITE_BUDGET_EXHAUSTED: /);
});

test("2.2.0 receipt echo: every upstream call asks for it; the journal line carries the echoed nonce (preferred over any body nonce) and receipt hash", async (t) => {
  const { server, tmpRoot, sentHeaders } = await context(t);
  await call(server, 1, "agent_handshake_invite", { reference: "r", statement: "s", validForSeconds: "90" });
  await call(server, 2, ADAPTER_TOOL);
  await call(server, 3, "agent_handshake_join", {});
  assert.ok(sentHeaders.length >= 2);
  for (const h of sentHeaders) assert.equal(h["x-clockchain-receipt"], "1");
  const all = (await readFile(join(tmpRoot, ADAPTER_FORWARDS_FILE), "utf8")).trim().split("\n").map((line) => JSON.parse(line));
  // C-ADP-1: forward, local (authorize), forward. Every forward line carries
  // the echo; the local line names the receipt that carried its step.
  assert.deepEqual(all.map((line) => line.kind), ["forward", "local", "forward"]);
  const lines = all.filter((line) => line.kind === "forward");
  for (const line of lines) {
    assert.match(line.serverNonce, /^0xe{24}\d{8}$/);
    assert.match(line.receiptHash, /^0x[0-9a-f]{64}$/);
  }
  assert.equal(all[1].localActionSource.receiptHash, all[0].receiptHash);
});

// 2.2.0 receipt session: the adapter keeps the coordinator's mcp-session-id.
async function sessionContext(t, { issue = true, knownSession = "sess-1" } = {}) {
  const fixture = await makeAssetDir(t);
  const tmpRoot = await mkdtemp(join(tmpdir(), "fill-tmp-"));
  t.after(() => rm(tmpRoot, { recursive: true, force: true }));
  const seen = [];
  let counter = 0;
  const state = { current: knownSession, mode: "ok" };
  const server = createLocalAdapterServer({
    assetDir: fixture.assetDir,
    endpoint: ENDPOINT,
    tmpdir: tmpRoot,
    fetchImpl: async (url, init) => {
      const request = JSON.parse(init.body);
      const sent = init.headers["mcp-session-id"] ?? null;
      seen.push({ method: request.method, sent });
      if (request.method === "initialize") {
        state.current = `sess-${++counter}`;
        return fakeResponse({ jsonrpc: "2.0", id: request.id, result: { protocolVersion: "2024-11-05", capabilities: {}, serverInfo: { name: "x", version: "1" } } }, issue ? { "mcp-session-id": state.current } : {});
      }
      if (request.method === "notifications/initialized") return fakeResponse({});
      if (sent !== null && sent !== state.current) {
        if (state.mode === "404") return { ok: false, status: 404, headers: { get: () => "text/plain" }, text: async () => "unknown session" };
        return fakeResponse({ jsonrpc: "2.0", id: request.id, error: { code: -32001, message: "Unknown session" } });
      }
      return fakeResponse({ jsonrpc: "2.0", id: request.id, result: request.method === "tools/list" ? { tools: [] } : rpcResult({ ok: true, serverNonce: `0x${"1".repeat(32)}` }) });
    },
  });
  return { server, seen, state };
}
const rpc = (server, id, method, params = {}) => server.handleMessage({ jsonrpc: "2.0", id, method, params });

test("2.2.0 receipt session: the initialize mcp-session-id is sent on every later upstream request", async (t) => {
  const { server, seen } = await sessionContext(t);
  await rpc(server, 1, "initialize", { protocolVersion: "2024-11-05", capabilities: {}, clientInfo: { name: "c", version: "1" } });
  await rpc(server, 2, "tools/list");
  await call(server, 3, "agent_handshake_status", { access: "csha_x" });
  const initialize = seen.find((s) => s.method === "initialize");
  assert.equal(initialize.sent, null);
  for (const s of seen.filter((x) => x.method !== "initialize")) assert.equal(s.sent, "sess-1", s.method);
});

test("2.2.0 receipt session: a server that issues no session id is never sent one (old servers)", async (t) => {
  const { server, seen } = await sessionContext(t, { issue: false });
  await rpc(server, 1, "initialize", { protocolVersion: "2024-11-05", capabilities: {}, clientInfo: { name: "c", version: "1" } });
  await rpc(server, 2, "tools/list");
  assert.ok(seen.length >= 2);
  for (const s of seen) assert.equal(s.sent, null);
});

for (const mode of ["404", "rpc-error"]) {
  test(`2.2.0 receipt session: an unknown stored session (${mode}) re-initializes once and the call succeeds`, async (t) => {
    const { server, seen, state } = await sessionContext(t);
    await rpc(server, 1, "initialize", { protocolVersion: "2024-11-05", capabilities: {}, clientInfo: { name: "c", version: "1" } });
    state.mode = mode;
    state.current = "server-restarted"; // the stored sess-1 is no longer known
    const res = await rpc(server, 2, "tools/list");
    assert.ok(res.result, JSON.stringify(res));
    assert.equal(seen.filter((s) => s.method === "initialize").length, 2);
    const after = seen.filter((s) => s.method === "tools/list");
    assert.equal(after.length, 2);
    assert.equal(after[0].sent, "sess-1");
    assert.equal(after[1].sent, "sess-2");
    await rpc(server, 3, "tools/list");
    assert.equal(seen.filter((s) => s.method === "tools/list").at(-1).sent, "sess-2");
  });
}

// --- C-ADP-1 (TB/LLD.md §8.4): local and refused-local lines, per-session
// serialization of fill and submit, the executed-digest set -------------------------------

const ENTRY_KEYS = ["v", "seq", "prevHash", "ts", "hash"];
const keysOf = (line) => Object.keys(line).filter((key) => !ENTRY_KEYS.includes(key)).sort();
const assertChain = (lines) => {
  let prev = null;
  lines.forEach((line, index) => {
    assert.equal(line.seq, index);
    assert.equal(line.prevHash, prev);
    assert.equal(line.hash, forwardEntryHash(line));
    prev = line.hash;
  });
};

test("C-ADP-1 refused-local: every adapter-side refusal of a forwardable tool is one line {kind, tool, modelArgs, code}; nothing is sent", async (t) => {
  const previous = process.env[INVITE_TERMS_ENV];
  t.after(() => { if (previous === undefined) delete process.env[INVITE_TERMS_ENV]; else process.env[INVITE_TERMS_ENV] = previous; });
  delete process.env[INVITE_TERMS_ENV];

  // LOCAL_VALUE_MISMATCH and SESSION_AMBIGUOUS
  const a = await context(t);
  await call(a.server, 1, "agent_handshake_invite", { reference: "r", statement: "s", validForSeconds: "90" });
  await call(a.server, 2, ADAPTER_TOOL);
  await call(a.server, 3, ADAPTER_TOOL);
  const sent = toolCalls(a.calls).length;
  const wrong = { sessionKeyAddress: `0x${"9".repeat(40)}` };
  assert.match(errorText(await call(a.server, 4, "agent_handshake_join", wrong)), /^LOCAL_VALUE_MISMATCH: /);
  a.setSession(SESSION_2);
  await call(a.server, 5, "agent_handshake_invite", { reference: "r", statement: "s", validForSeconds: "90" });
  const afterInvite = toolCalls(a.calls).length;
  assert.equal(afterInvite, sent + 1);
  assert.match(errorText(await call(a.server, 6, "agent_handshake_next", { waitMs: 0 })), /^SESSION_AMBIGUOUS: /);
  assert.equal(toolCalls(a.calls).length, afterInvite);
  const aLines = await journalLines(a.tmpRoot);
  assertChain(aLines);
  const aRefused = aLines.filter((l) => l.kind === "refused-local");
  assert.deepEqual(aRefused.map((l) => [l.tool, l.code]), [
    ["agent_handshake_join", "LOCAL_VALUE_MISMATCH"],
    ["agent_handshake_next", "SESSION_AMBIGUOUS"],
  ]);
  assert.deepEqual(aRefused[0].modelArgs, wrong);
  assert.deepEqual(aRefused[1].modelArgs, { waitMs: 0 });
  for (const line of aRefused) assert.deepEqual(keysOf(line), ["code", "kind", "modelArgs", "tool"]);

  // INVITE_TERMS_PIN_INVALID (the terms pin) and INVITE_BUDGET_EXHAUSTED
  process.env[INVITE_TERMS_ENV] = "{not json";
  const b = await context(t);
  assert.match(errorText(await call(b.server, 1, "agent_handshake_invite", {})), /^INVITE_TERMS_PIN_INVALID: /);
  delete process.env[INVITE_TERMS_ENV];
  const c = await context(t, { serverOptions: { inviteTerms: PINNED_TERMS, inviteBudget: 1 } });
  await call(c.server, 1, "agent_handshake_invite", {});
  assert.match(errorText(await call(c.server, 2, "agent_handshake_invite", { reference: "R-1" })), /^INVITE_BUDGET_EXHAUSTED: /);
  assert.equal(toolCalls(b.calls).length, 0);
  assert.deepEqual((await journalLines(b.tmpRoot)).map((l) => [l.kind, l.code]), [["refused-local", "INVITE_TERMS_PIN_INVALID"]]);
  const cLines = await journalLines(c.tmpRoot);
  assert.deepEqual(cLines.map((l) => [l.kind, outcomeOrCode(l)]), [["forward", "ok"], ["refused-local", "INVITE_BUDGET_EXHAUSTED"]]);
  assert.deepEqual(cLines[1].modelArgs, { reference: "R-1" });

  // DELIVER_INVITATION_FIRST, INVITATION_BY_REFERENCE_REQUIRED, INVITATION_REF_UNKNOWN (refs mode)
  const d = await context(t, { serverOptions: { invitationRefs: true } });
  await call(d.server, 1, "agent_handshake_invite", { reference: "r", statement: "s", validForSeconds: "90" });
  const dSent = toolCalls(d.calls).length;
  assert.match(errorText(await call(d.server, 2, "agent_handshake_submit", {})), /^DELIVER_INVITATION_FIRST: /);
  assert.match(errorText(await call(d.server, 3, "agent_handshake_accept_invitation", { invitation: genuineInvitation() })), /^INVITATION_BY_REFERENCE_REQUIRED: /);
  assert.match(errorText(await call(d.server, 4, "agent_handshake_accept_invitation", { invitationRef: "ir_unknown_00000000000000000000" })), /^INVITATION_REF_(UNKNOWN|INVALID): /);
  assert.equal(toolCalls(d.calls).length, dSent);
  const dLines = await journalLines(d.tmpRoot);
  assertChain(dLines);
  assert.deepEqual(dLines.slice(1).map((l) => [l.kind, l.tool]), [
    ["refused-local", "agent_handshake_submit"],
    ["refused-local", "agent_handshake_accept_invitation"],
    ["refused-local", "agent_handshake_accept_invitation"],
  ]);
  assert.deepEqual(dLines.slice(1, 3).map((l) => l.code), ["DELIVER_INVITATION_FIRST", "INVITATION_BY_REFERENCE_REQUIRED"]);
  assert.match(dLines[3].code, /^INVITATION_REF_(UNKNOWN|INVALID)$/);

  // INVITATION_CORRUPTED (the 2.1.11 shape guard, copy mode)
  const e = await context(t);
  assert.match(errorText(await call(e.server, 1, "agent_handshake_accept_invitation", { invitation: "x".repeat(100) })), /^INVITATION_CORRUPTED: /);
  assert.equal(toolCalls(e.calls).length, 0);
  assert.deepEqual((await journalLines(e.tmpRoot)).map((l) => [l.kind, l.code]), [["refused-local", "INVITATION_CORRUPTED"]]);
  // A refused-local line never carries a server nonce: nothing reached the coordinator.
  for (const line of [...aRefused, ...cLines.slice(1), ...dLines.slice(1)]) assert.equal(Object.hasOwn(line, "serverNonce"), false);
});

test("C-ADP-1 local: every authorize_local_action and sign_agent_contract_bind call is one local line with outcome and result digest", async (t) => {
  const { server, tmpRoot, md } = await context(t);
  // nothing staged yet: refused, no step
  const none = await call(server, 1, ADAPTER_TOOL);
  // arguments to the zero-input tool: refused
  const withArgs = await call(server, 2, ADAPTER_TOOL, { command: "rm -rf /" });
  assert.equal(withArgs.error.code, -32602);
  await call(server, 3, "agent_handshake_invite", { reference: "r", statement: "s", validForSeconds: "90" });
  const init = await call(server, 4, ADAPTER_TOOL);
  // a contract bind with no held session: refused locally, never forwarded
  const bind = await call(server, 5, CONTRACT_BIND_TOOL, { runId: SESSION, side: "initiator" });
  assert.equal(bind.result.isError, true);
  const lines = await journalLines(tmpRoot);
  assertChain(lines);
  const locals = lines.filter((l) => l.kind === "local");
  assert.deepEqual(locals.map((l) => [l.tool, l.operation, l.outcome]), [
    [ADAPTER_TOOL, null, "refused"],
    [ADAPTER_TOOL, null, "refused"],
    [ADAPTER_TOOL, "init", "ok"],
    [CONTRACT_BIND_TOOL, "contract-bind", "refused"],
  ]);
  for (const line of locals) {
    assert.deepEqual(keysOf(line), ["kind", "localActionSource", "operation", "outcome", "resultDigest", "role", "sessionId", "stagedStepDigest", "tool"]);
  }
  assert.equal(locals[0].resultDigest, resultDigest(none.result));
  assert.equal(locals[1].resultDigest, resultDigest(withArgs.error));
  assert.equal(locals[2].resultDigest, resultDigest(init.result));
  assert.equal(locals[3].resultDigest, resultDigest(bind.result));
  assert.equal(locals[0].stagedStepDigest, null);
  assert.equal(locals[2].stagedStepDigest, helperStep({ manifestDigest: md, operation: "init" }).commandSha256);
  assert.equal(locals[2].sessionId, SESSION);
  assert.equal(locals[2].role, "initiator");
  assert.deepEqual(locals[3].sessionId, SESSION);
  assert.equal(locals[3].role, "initiator");
  assert.equal(locals[3].stagedStepDigest, null);
  assert.equal(locals[3].localActionSource, null);
});

test("C-ADP-1 local: a helper that fails is an \"error\" local line, and its step is not staged again in this process", async (t) => {
  let failNext = true;
  const fixture = await context(t, {
    serverOptions: {
      runHelper: async (input) => {
        if (failNext) { failNext = false; return { code: 1, stderr: '{"error":{"code":"AGENT_HANDSHAKE_FAILED","message":"x"}}\n', stdout: "" }; }
        return { code: 0, stderr: "", stdout: cliResult(input.args[6], { address: CHECKSUM_ADDRESS }) };
      },
    },
  });
  const { server, tmpRoot, md } = fixture;
  await call(server, 1, "agent_handshake_invite", { reference: "r", statement: "s", validForSeconds: "90" });
  assert.equal(errorText(await call(server, 2, ADAPTER_TOOL)), "AGENT_HANDSHAKE_FAILED");
  // The coordinator re-issues the same init step on a later poll: it is not staged again.
  const initStep = helperStep({ manifestDigest: md, operation: "init" });
  const before = server.pendingCount();
  // re-issued by a second invite of the same session (the double's steps are deterministic)
  await call(server, 3, "agent_handshake_invite", { reference: "r", statement: "s", validForSeconds: "90" });
  assert.equal(server.pendingCount(), before, "the failed init is not re-staged; the still-queued inspect is not duplicated");
  const lines = await journalLines(tmpRoot);
  const local = lines.find((l) => l.kind === "local");
  assert.equal(local.outcome, "error");
  assert.equal(local.stagedStepDigest, initStep.commandSha256);
  assert.deepEqual(lines.at(-1).skippedExecuted, [initStep.commandSha256]);
});

test("C-ADP-1 executed-digest set: a step executed once is never staged again, in this process or after a restart", async (t) => {
  const first = await context(t);
  await call(first.server, 1, "agent_handshake_invite", { reference: "r", statement: "s", validForSeconds: "90" });
  await call(first.server, 2, ADAPTER_TOOL); // init
  await call(first.server, 3, ADAPTER_TOOL); // inspect
  await call(first.server, 4, "agent_handshake_join", {});
  first.stageSigns(["identity_claim"]);
  await call(first.server, 5, "agent_handshake_next", { waitMs: 0 });
  assert.equal(first.server.pendingCount(), 1);
  await call(first.server, 6, ADAPTER_TOOL); // sign
  assert.equal(first.server.pendingCount(), 0);
  // The coordinator re-issues the same localAction on the next poll.
  first.stageSigns(["identity_claim"]);
  await call(first.server, 7, "agent_handshake_next", { waitMs: 0 });
  assert.equal(first.server.pendingCount(), 0, "an executed step is not staged again");
  assert.equal(errorText(await call(first.server, 8, ADAPTER_TOOL)), "Clockchain local adapter has no staged action to execute.");
  const lines = await journalLines(first.tmpRoot);
  const signLine = lines.filter((l) => l.kind === "local" && l.operation === "sign");
  assert.equal(signLine.length, 1, "the sign step ran exactly once");
  const reissue = lines.filter((l) => l.tool === "agent_handshake_next").at(-1);
  assert.deepEqual(reissue.skippedExecuted, [signLine[0].stagedStepDigest]);
  assert.equal(Object.hasOwn(reissue, "stagedStepDigests"), false);

  // A restart on the same TMPDIR (same epoch): the journal seeds the set.
  const helperRuns = [];
  const second = createLocalAdapterServer({
    assetDir: (await makeAssetDir(t)).assetDir,
    endpoint: ENDPOINT,
    tmpdir: first.tmpRoot,
    fetchImpl: async (url, init) => {
      const request = JSON.parse(init.body);
      const steps = [
        helperStep({ manifestDigest: first.md, operation: "init" }),
        helperStep({ manifestDigest: first.md, operation: "sign", payload: signPayload("identity_claim", { nonce: "0" }) }),
        helperStep({ manifestDigest: first.md, operation: "sign", payload: signPayload("proposal", { nonce: "1" }) }),
      ];
      return fakeResponse({ jsonrpc: "2.0", id: request.id, result: rpcResult({ serverNonce: `0x${"7".repeat(32)}`, localAction: { helperSteps: steps } }) });
    },
    runHelper: async (input) => { helperRuns.push(input.args[6]); return { code: 0, stderr: "", stdout: cliResult(input.args[6], { address: ADDRESS, signatureHex: SIG_3, bytesSha256: "d".repeat(64), checkpoint: null }) }; },
  });
  await call(second, 9, "agent_handshake_next", { access: "csha_11111111_init_xxxxxxxx" });
  assert.equal(second.pendingCount(), 1, "only the never-executed proposal step is staged");
  await call(second, 10, ADAPTER_TOOL);
  assert.deepEqual(helperRuns, ["sign"]);
  const after = await journalLines(first.tmpRoot);
  assertChain(after);
  assert.equal(after.filter((l) => l.kind === "local" && l.operation === "sign" && l.outcome === "ok").length, 2);
});

test("C-ADP-1 serialization: two concurrent submits of one session never forward the same held signature", async (t) => {
  const { server, calls, stageSigns } = await context(t);
  await call(server, 1, "agent_handshake_invite", { reference: "r", statement: "s", validForSeconds: "90" });
  await call(server, 2, ADAPTER_TOOL);
  await call(server, 3, ADAPTER_TOOL);
  await call(server, 4, "agent_handshake_join", {});
  stageSigns(["identity_claim"]);
  await call(server, 5, "agent_handshake_next", { waitMs: 0 });
  await call(server, 6, ADAPTER_TOOL); // holds SIG_1
  const [one, two] = await Promise.all([
    call(server, 7, "agent_handshake_submit", {}),
    call(server, 8, "agent_handshake_submit", {}),
  ]);
  assert.equal(one.result.isError, undefined);
  assert.equal(two.result.isError, undefined);
  const submits = toolCalls(calls).filter((c) => c.params.name === "agent_handshake_submit");
  assert.equal(submits.length, 2);
  assert.equal(submits.filter((c) => c.params.arguments.signatureHex === SIG_1).length, 1, "the signature is forwarded once");
  assert.equal(Object.hasOwn(submits[1].params.arguments, "signatureHex"), false);
});

test("C-ADP-1 serialization: a submit made while the session's sign step is running waits for it and carries its signature", async (t) => {
  let release;
  let running;
  const gate = new Promise((resolve) => { release = resolve; });
  const started = new Promise((resolve) => { running = resolve; });
  const { server, calls, stageSigns } = await context(t, {
    serverOptions: {
      runHelper: async (input) => {
        const operation = input.args[6];
        if (operation === "init") return { code: 0, stderr: "", stdout: cliResult("init", { address: CHECKSUM_ADDRESS }) };
        if (operation === "inspect") return { code: 0, stderr: "", stdout: cliResult("inspect", { address: ADDRESS, policyDigest: POLICY_DIGEST, registration: null }) };
        running();
        await gate;
        return { code: 0, stderr: "", stdout: cliResult("sign", { address: ADDRESS, bytesSha256: "d".repeat(64), signatureHex: SIG_1, checkpoint: null }) };
      },
    },
  });
  await call(server, 1, "agent_handshake_invite", { reference: "r", statement: "s", validForSeconds: "90" });
  await call(server, 2, ADAPTER_TOOL);
  await call(server, 3, ADAPTER_TOOL);
  await call(server, 4, "agent_handshake_join", {});
  stageSigns(["identity_claim"]);
  await call(server, 5, "agent_handshake_next", { waitMs: 0 });
  const signing = call(server, 6, ADAPTER_TOOL);
  await started; // the helper is running the sign step
  const submitting = call(server, 7, "agent_handshake_submit", {});
  for (let i = 0; i < 20; i += 1) await new Promise((resolve) => setImmediate(resolve));
  assert.equal(toolCalls(calls).filter((c) => c.params.name === "agent_handshake_submit").length, 0, "the submit waits for the running sign");
  release();
  await signing;
  const submitted = await submitting;
  assert.equal(submitted.result.isError, undefined);
  assert.equal(lastForwarded(calls).arguments.signatureHex, SIG_1);
});

test("C-ADP-1 invite budget: only forward lines count; refused-local and local lines (and a legacy line without kind) are read correctly", async (t) => {
  const tmpRoot = await mkdtemp(join(tmpdir(), "fill-journal-"));
  t.after(() => rm(tmpRoot, { recursive: true, force: true }));
  const journal = createForwardJournal({ tmpRoot, now: Date.now });
  assert.equal(await journal.append({ tool: "agent_handshake_invite", outcome: "ok" }), true); // legacy (pre-C-ADP-1) forward line
  await journal.append({ kind: "forward", tool: "agent_handshake_invite", outcome: "ok" });
  await journal.append({ kind: "forward", tool: "agent_handshake_invite", outcome: "transient" });
  await journal.append({ kind: "refused-local", tool: "agent_handshake_invite", modelArgs: {}, code: "INVITE_BUDGET_EXHAUSTED" });
  await journal.append({ kind: "local", tool: "agent_handshake_invite", outcome: "ok", stagedStepDigest: "a".repeat(64) });
  await journal.append({ kind: "local", tool: ADAPTER_TOOL, outcome: "error", stagedStepDigest: "b".repeat(64) });
  await journal.append({ kind: "local", tool: ADAPTER_TOOL, outcome: "refused", stagedStepDigest: null });
  assert.equal(await journal.count("agent_handshake_invite"), 2);
  assert.deepEqual([...await journal.executedStepDigests()], ["a".repeat(64)]);

  // End to end: two locally refused invites do not spend a restarted adapter's budget.
  const first = await context(t, { serverOptions: { inviteTerms: PINNED_TERMS, inviteBudget: 2 } });
  await call(first.server, 1, "agent_handshake_invite", {});
  await call(first.server, 2, "agent_handshake_invite", { reference: "R-x" });
  await call(first.server, 3, "agent_handshake_invite", { statement: "other" });
  const fixtureCalls = [];
  const second = createLocalAdapterServer({
    assetDir: (await makeAssetDir(t)).assetDir,
    endpoint: ENDPOINT,
    tmpdir: first.tmpRoot,
    inviteTerms: PINNED_TERMS,
    inviteBudget: 2,
    fetchImpl: async (url, init) => {
      const request = JSON.parse(init.body);
      fixtureCalls.push(request);
      return fakeResponse({ jsonrpc: "2.0", id: request.id, result: rpcResult({ sessionId: SESSION_2, role: "initiator", roleAccess: "csha_22222222_init_xxxxxxxx", serverNonce: `0x${"9".repeat(32)}` }) });
    },
  });
  assert.equal((await call(second, 4, "agent_handshake_invite", {})).result.isError, undefined);
  assert.match(errorText(await call(second, 5, "agent_handshake_invite", {})), /^INVITE_BUDGET_EXHAUSTED: .*2 of its 2/);
  assert.equal(inviteCalls(fixtureCalls).length, 1);
});

test("C-ADP-1 executed-digest set: a step re-issued while its run waits for the session lock is not staged again", async (t) => {
  const { assetDir, pin } = await makeAssetDir(t);
  const md = pin.manifestDigest;
  const tmpRoot = await mkdtemp(join(tmpdir(), "fill-tmp-"));
  t.after(() => rm(tmpRoot, { recursive: true, force: true }));
  const signStep = helperStep({ manifestDigest: md, operation: "sign", payload: signPayload("identity_claim", { nonce: "0" }) });
  let nonce = 0;
  let hold = null;
  const helperRuns = [];
  const server = createLocalAdapterServer({
    assetDir,
    endpoint: ENDPOINT,
    tmpdir: tmpRoot,
    fetchImpl: async (url, init) => {
      const request = JSON.parse(init.body);
      const name = request.params?.name;
      const serverNonce = `0x${String(++nonce).padStart(32, "0")}`;
      let body = { ok: true, serverNonce };
      if (name === "agent_handshake_invite") {
        body = { sessionId: SESSION, role: "initiator", roleAccess: "csha_11111111_init_xxxxxxxx", responderInvitation: "x".repeat(100), serverNonce,
          localAction: { helperSteps: [helperStep({ manifestDigest: md, operation: "init" }), helperStep({ manifestDigest: md, operation: "inspect" })] } };
      } else if (name === "agent_handshake_next") {
        // The coordinator re-issues the unchanged pending step on every poll.
        if (hold !== null) await hold.gate;
        body = { serverNonce, localAction: { helperSteps: [signStep] } };
      }
      return fakeResponse({ jsonrpc: "2.0", id: request.id, result: rpcResult(body) });
    },
    runHelper: async (input) => {
      const operation = input.args[6];
      helperRuns.push(operation);
      if (operation === "init") return { code: 0, stderr: "", stdout: cliResult("init", { address: CHECKSUM_ADDRESS }) };
      if (operation === "inspect") return { code: 0, stderr: "", stdout: cliResult("inspect", { address: ADDRESS, policyDigest: POLICY_DIGEST, registration: null }) };
      return { code: 0, stderr: "", stdout: cliResult("sign", { address: ADDRESS, bytesSha256: "d".repeat(64), signatureHex: SIG_1, checkpoint: null }) };
    },
  });
  await call(server, 1, "agent_handshake_invite", { reference: "r", statement: "s", validForSeconds: "90" });
  await call(server, 2, ADAPTER_TOOL);
  await call(server, 3, ADAPTER_TOOL);
  await call(server, 4, "agent_handshake_next", { waitMs: 0 });
  assert.equal(server.pendingCount(), 1);
  // A poll of the session is in flight (it holds the session lock) when the
  // sign step is taken; the poll's answer re-issues that same step.
  let release;
  hold = { gate: new Promise((resolve) => { release = resolve; }) };
  const polling = call(server, 5, "agent_handshake_next", { waitMs: 0 });
  for (let i = 0; i < 20; i += 1) await new Promise((resolve) => setImmediate(resolve));
  const signing = call(server, 6, ADAPTER_TOOL);
  for (let i = 0; i < 20; i += 1) await new Promise((resolve) => setImmediate(resolve));
  release();
  hold = null;
  await polling;
  assert.equal((await signing).result.isError, undefined);
  assert.equal(server.pendingCount(), 0, "the step taken for execution is not staged again by the poll that re-issued it");
  assert.equal(errorText(await call(server, 7, ADAPTER_TOOL)), "Clockchain local adapter has no staged action to execute.");
  assert.deepEqual(helperRuns, ["init", "inspect", "sign"]);
});
