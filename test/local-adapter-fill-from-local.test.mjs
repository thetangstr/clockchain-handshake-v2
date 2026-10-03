// 2.2.0 handshake by reference: the adapter fills every long handshake value
// (role access, session key address, policy digest, signatures, checkpoint,
// invite terms) from its own staged results, hides the signatures from the
// model, and journals every call whose forwarded args differ from the model's.
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
  forwardEntryHash,
} from "../src/local-adapter/fill-from-local.mjs";

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

function fakeResponse(body) {
  const text = JSON.stringify(body);
  return { ok: true, headers: { get: () => "application/json" }, text: async () => text };
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
  const refuse = new Set();
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
      const name = request.params?.name;
      const serverNonce = `0x${String(++nonce).padStart(32, "0")}`;
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
      return fakeResponse({ jsonrpc: "2.0", id: request.id, result: rpcResult(body) });
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
  return { server, calls, refuse, tmpRoot, stageSigns, setSession, md };
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

test("2.2.0: version is 2.2.0", () => {
  assert.equal(LOCAL_ADAPTER_VERSION, "2.2.0");
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

test("2.2.0 journal: every call whose forwarded args differ from the model's is journaled, hash-chained, 0600", async (t) => {
  const { server, tmpRoot, stageSigns } = await context(t);
  await call(server, 1, "agent_handshake_invite", { reference: "r", statement: "s", validForSeconds: "90" });
  await call(server, 2, ADAPTER_TOOL);
  await call(server, 3, ADAPTER_TOOL);
  await call(server, 4, "agent_handshake_status", { access: "csha_11111111_init_xxxxxxxx" }); // nothing filled: not journaled
  await call(server, 5, "agent_handshake_join", {});
  stageSigns(["identity_claim"]);
  await call(server, 6, "agent_handshake_next", { waitMs: 0 });
  await call(server, 7, ADAPTER_TOOL);
  await call(server, 8, "agent_handshake_submit", { policyDigest: POLICY_DIGEST });
  const path = join(tmpRoot, ADAPTER_FORWARDS_FILE);
  assert.equal((await stat(path)).mode & 0o777, 0o600);
  assert.equal((await stat(join(path, ".."))).mode & 0o777, 0o700);
  const lines = (await readFile(path, "utf8")).trim().split("\n").map((line) => JSON.parse(line));
  assert.deepEqual(lines.map((line) => line.tool), ["agent_handshake_join", "agent_handshake_next", "agent_handshake_submit"]);
  let prev = null;
  lines.forEach((line, index) => {
    assert.equal(line.v, 1);
    assert.equal(line.seq, index);
    assert.equal(line.prevHash, prev);
    assert.equal(line.hash, forwardEntryHash(line));
    assert.match(line.serverNonce, /^0x[0-9a-f]{32}$/);
    assert.equal(line.outcome, "ok");
    prev = line.hash;
  });
  assert.deepEqual(lines[0].modelArgs, {});
  assert.deepEqual(lines[0].filled, ["access", "helperVersion", "sessionKeyAddress", "policyDigest"]);
  assert.deepEqual(lines[0].forwardedArgs, { access: "csha_11111111_init_xxxxxxxx", helperVersion: AGENT_HANDSHAKE_HELPER_VERSION, sessionKeyAddress: ADDRESS, policyDigest: POLICY_DIGEST });
  assert.deepEqual(lines[1].filled, ["access"]);
  assert.deepEqual(lines[1].forwardedArgs, { waitMs: 0, access: "csha_11111111_init_xxxxxxxx" });
  assert.deepEqual(lines[2].modelArgs, { policyDigest: POLICY_DIGEST });
  assert.deepEqual(lines[2].filled, ["access", "signatureHex"]);
  // Every model field equals the same forwarded field (R8 condition 2).
  for (const line of lines) {
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
