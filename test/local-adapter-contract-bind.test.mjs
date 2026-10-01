import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import { contractCanonicalDigest, contractCanonicalJson } from "../src/local-adapter/contract-bind.mjs";

// --- piece 1: canonical JSON parity with the agent-contract server ----------
//
// test/fixtures/agent-contract-canonical-digest-vectors.json is a verbatim
// copy of clockchain-developer-tools packages/mcp-server
// test/fixtures/agent-contract-canonical-digest-vectors.json — the vectors the
// contract server's own canonical.ts is held to. The adapter's port must
// produce the same bytes and digests for every one of them.

const CANONICAL_VECTORS = JSON.parse(readFileSync(
  new URL("./fixtures/agent-contract-canonical-digest-vectors.json", import.meta.url),
  "utf8",
));

test("contract canonical JSON matches the server's committed digest vectors", () => {
  assert.equal(CANONICAL_VECTORS.schema, "agent-contract.canonical-digest-vectors/v1");
  assert.ok(CANONICAL_VECTORS.vectors.length >= 10);
  for (const vector of CANONICAL_VECTORS.vectors) {
    assert.equal(contractCanonicalJson(vector.input), vector.canonical);
    assert.equal(contractCanonicalDigest(vector.input), vector.digest);
  }
});

test("contract canonical JSON drops undefined members and refuses unrepresentable values", () => {
  assert.equal(contractCanonicalJson({ b: 1, skip: undefined, a: 2 }), "{\"a\":2,\"b\":1}");
  assert.throws(() => contractCanonicalJson([undefined]));
  assert.throws(() => contractCanonicalJson(Number.NaN));
  assert.throws(() => contractCanonicalJson(1n));
});

// --- piece 2: the sign_agent_contract_bind tool ------------------------------

import { createHash } from "node:crypto";
import { existsSync } from "node:fs";
import { chmod, mkdir, mkdtemp, rm, symlink } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { recoverMessageAddress } from "viem";
import { privateKeyToAccount } from "viem/accounts";

import { commitAgentPolicy } from "../src/agent-cli/policy.mjs";
import {
  AGENT_HANDSHAKE_HELPER_VERSION,
  AGENT_HANDSHAKE_RELEASE_ASSET_PREFIX,
} from "../src/agent-handshake/v2/constants.mjs";
import { initializeWallet } from "../src/core/wallet-bridge.mjs";
import { recordVerifiedSession } from "../src/local-adapter/contract-bind.mjs";
import {
  CONTRACT_BIND_DOMAIN,
  CONTRACT_BIND_ISSUED_AT_MAX_AGE_MS,
  CONTRACT_BIND_ISSUED_AT_MAX_SKEW_MS,
  CONTRACT_BIND_TOOL,
  CONTRACT_BIND_TOOL_DEFINITION,
} from "../src/local-adapter/contract-bind.mjs";
import { ADAPTER_TOOL, createLocalAdapterServer } from "../src/local-adapter/server.mjs";

const sha256Hex = (value) => createHash("sha256").update(value).digest("hex");
const SESSION = "11111111-2222-4333-8444-555555555555";
const OTHER_SESSION = "66666666-7777-4888-9999-aaaaaaaaaaaa";
// A public, derivable TEST key — never a real wallet. Derived rather than
// written out so no key-shaped literal sits in the repository.
const TEST_KEY = `0x${sha256Hex("clockchain-local-adapter/contract-bind-test-key/v1")}`;
const TEST_KEY_HEX = TEST_KEY.slice(2).toLowerCase();
const TEST_ADDRESS = privateKeyToAccount(TEST_KEY).address.toLowerCase();
const NOW_MS = Date.parse("2026-10-01T17:00:00.000Z");
const CHALLENGE = "c0ffee".padEnd(64, "0");
const SECP256K1_N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;

const POLICY = Object.freeze({
  schema: "clockchain.agent-handshake-policy/v1",
  protocol: "clockchain.agent-handshake/v2",
  role: "initiator",
  mcpOrigin: "https://mcp.clockchain.network",
  reference: "NS-1847",
  statementDigest: "e".repeat(64),
  maxValidForSeconds: "90",
  identityPolicy: Object.freeze({ erc8004: "not_required", chainId: null, registryAddress: null }),
  externalBusinessActionsAllowed: false,
});

function statement(overrides = {}) {
  return {
    domain: CONTRACT_BIND_DOMAIN,
    runId: SESSION,
    side: "initiator",
    tokenKeyId: "klb1",
    serverKeyId: "contract-server",
    challenge: CHALLENGE,
    issuedAt: new Date(NOW_MS - 2_000).toISOString(),
    ...overrides,
  };
}

function fixtureAssets() {
  const helperBytes = Buffer.from("\"use strict\";\n// contract-bind test helper\n");
  const manifestBytes = Buffer.from("{}");
  return {
    helperBytes,
    helperPath: "/nonexistent/clockchain-agent-handshake.cjs",
    helperSha256: sha256Hex(helperBytes),
    manifestBytes,
    manifestPath: "/nonexistent/manifest.json",
    pin: {
      version: AGENT_HANDSHAKE_HELPER_VERSION,
      sourceCommit: "a".repeat(40),
      manifestDigest: sha256Hex(manifestBytes),
      allowedAssetPrefix: AGENT_HANDSHAKE_RELEASE_ASSET_PREFIX,
      hostRoots: [{ kid: "root-2026-08", fingerprint: "c".repeat(64) }],
    },
  };
}

const BIND_CONFIG = Object.freeze({ tokenKeyIds: ["klb1"], serverKeyIds: ["contract-server"] });

async function makeBindContext(t, { now = () => NOW_MS, contractBind = BIND_CONFIG } = {}) {
  const tmpRoot = await mkdtemp(join(tmpdir(), "local-adapter-bind-"));
  t.after(() => rm(tmpRoot, { recursive: true, force: true }));
  const upstreamCalls = [];
  const server = createLocalAdapterServer({
    assets: fixtureAssets(),
    endpoint: "https://upstream.test/handshake/mcp",
    fetchImpl: async (url, init) => {
      upstreamCalls.push(JSON.parse(init.body));
      throw new Error("upstream unreachable in tests");
    },
    runHelper: async () => { throw new Error("the bind tool must never run the helper"); },
    now,
    tmpdir: tmpRoot,
    ...(contractBind === null ? {} : { contractBind }),
  });
  return { server, tmpRoot, upstreamCalls };
}

// Lays down a session exactly as the pinned helper's init + policy steps do:
// a 0700 state dir, wallet.json (0600) and the committed policy.json.
async function holdSession(tmpRoot, {
  sessionId = SESSION, role = "initiator", policyRole = role, wallet = true, policy = true,
  verified = wallet, expiresAtMs = NOW_MS + 5 * 60_000, sessionKeyAddress = TEST_ADDRESS,
  recordSessionId = sessionId, recordRole = role,
} = {}) {
  const stateDir = join(tmpRoot, ".clockchain", "handshakes", sessionId, role);
  await mkdir(stateDir, { recursive: true, mode: 0o700 });
  if (wallet) {
    await initializeWallet({ statePath: join(stateDir, "wallet.json"), generatePrivateKey: () => TEST_KEY });
  }
  if (policy) await commitAgentPolicy({ stateDir, policy: { ...POLICY, role: policyRole } });
  if (verified) {
    assert.equal(await recordVerifiedSession({
      stateDir, sessionId: recordSessionId, role: recordRole, sessionKeyAddress, expiresAtMs,
    }), true);
  }
  return stateDir;
}

let rpcId = 100;
async function callBind(server, args) {
  const response = await server.handleMessage({
    jsonrpc: "2.0", id: ++rpcId, method: "tools/call",
    params: args === undefined ? { name: CONTRACT_BIND_TOOL } : { name: CONTRACT_BIND_TOOL, arguments: args },
  });
  return response;
}

function assertRefused(response, code, label = code) {
  assert.equal(response.error, undefined, label);
  assert.equal(response.result.isError, true, label);
  assert.equal(response.result.content.length, 1);
  assert.equal(
    response.result.content[0].text,
    `Clockchain local adapter refused the bind statement (${code}).`,
  );
  assertNoKey(response);
}

function assertNoKey(value) {
  const text = JSON.stringify(value).toLowerCase();
  assert.equal(text.includes(TEST_KEY_HEX), false, "response must never carry the session private key");
}

test("tools/list advertises sign_agent_contract_bind with the exact seven-key schema", async (t) => {
  const { server } = await makeBindContext(t);
  const listed = await server.handleMessage({ jsonrpc: "2.0", id: 1, method: "tools/list", params: {} });
  const names = listed.result.tools.map((tool) => tool.name);
  assert.deepEqual(names, [ADAPTER_TOOL, CONTRACT_BIND_TOOL]);
  const tool = listed.result.tools.at(-1);
  assert.equal(tool, CONTRACT_BIND_TOOL_DEFINITION);
  assert.deepEqual(tool.inputSchema.required, [
    "domain", "runId", "side", "tokenKeyId", "serverKeyId", "challenge", "issuedAt",
  ]);
  assert.deepEqual(Object.keys(tool.inputSchema.properties), tool.inputSchema.required);
  assert.equal(tool.inputSchema.additionalProperties, false);
  assert.equal(tool.inputSchema.properties.domain.const, "agent-contract.bind/v1");
  assert.deepEqual(tool.inputSchema.properties.side.enum, ["initiator", "responder"]);
  assertNoKey(listed);
});

test("happy path: signs the canonical statement with the held session key", async (t) => {
  const { server, tmpRoot, upstreamCalls } = await makeBindContext(t);
  await holdSession(tmpRoot);
  const input = statement();
  const response = await callBind(server, input);
  assert.equal(response.result.isError, undefined);
  const text = response.result.content[0].text;
  const output = JSON.parse(text);
  assert.deepEqual(Object.keys(output), ["statement", "signature", "sessionKeyAddress"]);
  // Echo is the canonical form: same fields, keys in canonical order.
  assert.deepEqual(output.statement, input);
  assert.equal(JSON.stringify(output.statement), contractCanonicalJson(input));
  assert.equal(output.sessionKeyAddress, TEST_ADDRESS);
  // EIP-191 personal_sign over the raw 32-byte digest, recovering to the
  // session address — exactly what the contract server recovers.
  const digest = contractCanonicalDigest(input);
  const recovered = await recoverMessageAddress({ message: { raw: digest }, signature: output.signature });
  assert.equal(recovered.toLowerCase(), TEST_ADDRESS);
  // Canonical signature form: 65 bytes, v in {27,28}, low-s.
  assert.match(output.signature, /^0x[0-9a-f]{130}$/);
  const v = Number.parseInt(output.signature.slice(130), 16);
  assert.ok(v === 27 || v === 28);
  const s = BigInt(`0x${output.signature.slice(66, 130)}`);
  assert.ok(s > 0n && s <= SECP256K1_N >> 1n);
  // Purely local: nothing went upstream.
  assert.deepEqual(upstreamCalls, []);
  assertNoKey(response);
});

test("happy path: the responder side signs with the responder session", async (t) => {
  const { server, tmpRoot } = await makeBindContext(t);
  await holdSession(tmpRoot, { sessionId: OTHER_SESSION, role: "responder" });
  const response = await callBind(server, statement({ runId: OTHER_SESSION, side: "responder" }));
  const output = JSON.parse(response.result.content[0].text);
  assert.equal(output.sessionKeyAddress, TEST_ADDRESS);
  assert.equal(output.statement.side, "responder");
});

test("issuedAt window: accepted at both inclusive edges, refused just outside", async (t) => {
  const { server, tmpRoot } = await makeBindContext(t);
  await holdSession(tmpRoot);
  for (const offset of [-CONTRACT_BIND_ISSUED_AT_MAX_AGE_MS, CONTRACT_BIND_ISSUED_AT_MAX_SKEW_MS, 0]) {
    const response = await callBind(server, statement({ issuedAt: new Date(NOW_MS + offset).toISOString() }));
    assert.equal(response.result.isError, undefined, `offset ${offset}`);
  }
  for (const offset of [-CONTRACT_BIND_ISSUED_AT_MAX_AGE_MS - 1, CONTRACT_BIND_ISSUED_AT_MAX_SKEW_MS + 1, -3_600_000]) {
    assertRefused(
      await callBind(server, statement({ issuedAt: new Date(NOW_MS + offset).toISOString() })),
      "BIND_ISSUED_AT_OUT_OF_WINDOW",
    );
  }
  // Second-precision and microsecond-precision ISO forms are both well-formed.
  for (const issuedAt of ["2026-10-01T16:59:59Z", "2026-10-01T16:59:59.123456Z"]) {
    assert.equal((await callBind(server, statement({ issuedAt }))).result.isError, undefined, issuedAt);
  }
});

test("refuses malformed statements: shape, extra/missing keys, domain, formats", async (t) => {
  const { server, tmpRoot } = await makeBindContext(t);
  await holdSession(tmpRoot);
  const bad = [
    undefined,
    null,
    [],
    "statement",
    {},
    { ...statement(), extra: "x" },
    { ...statement(), signature: "0x00" },
    { ...statement(), bytesHex: "0xdeadbeef" },
    { statement: statement() },
    statement({ domain: "agent-contract.role-sig/v1" }),
    statement({ domain: "agent-contract.bind/v2" }),
    statement({ domain: "AGENT-CONTRACT.BIND/V1" }),
    statement({ runId: OTHER_SESSION.toUpperCase() }),
    statement({ runId: "../../etc" }),
    statement({ runId: `${SESSION}/initiator` }),
    statement({ runId: "run-1" }),
    statement({ runId: 42 }),
    statement({ side: "buyer" }),
    statement({ side: "Initiator" }),
    statement({ tokenKeyId: "" }),
    statement({ tokenKeyId: "k".repeat(65) }),
    statement({ tokenKeyId: "has space" }),
    statement({ tokenKeyId: "naïve" }),
    statement({ tokenKeyId: 7 }),
    statement({ serverKeyId: "" }),
    statement({ serverKeyId: "s".repeat(65) }),
    statement({ serverKeyId: "tab\tbed" }),
    statement({ challenge: CHALLENGE.toUpperCase() }),
    statement({ challenge: CHALLENGE.slice(1) }),
    statement({ challenge: `${CHALLENGE}00` }),
    statement({ challenge: `0x${CHALLENGE.slice(2)}` }),
    statement({ issuedAt: "yesterday" }),
    statement({ issuedAt: "2026-10-01T17:00:00+00:00" }),
    statement({ issuedAt: "2026-10-01 17:00:00Z" }),
    statement({ issuedAt: "2026-02-30T17:00:00Z" }),
    statement({ issuedAt: "2026-10-01T24:00:00Z" }),
    statement({ issuedAt: NOW_MS }),
  ];
  for (const key of Object.keys(statement())) {
    const missing = statement();
    delete missing[key];
    bad.push(missing);
    bad.push(statement({ [key]: undefined }));
  }
  for (const [index, args] of bad.entries()) {
    const response = await callBind(server, args);
    assertRefused(response, "BIND_ARGUMENTS_INVALID", `case ${index}: ${JSON.stringify(args)}`);
  }
  // Exotic objects: accessor properties, class instances, symbol keys.
  const accessor = statement();
  Object.defineProperty(accessor, "issuedAt", { get: () => new Date(NOW_MS).toISOString(), enumerable: true });
  const withSymbol = { ...statement(), [Symbol("x")]: 1 };
  class Statement { constructor() { Object.assign(this, statement()); } }
  for (const args of [accessor, withSymbol, new Statement()]) {
    assertRefused(await callBind(server, args), "BIND_ARGUMENTS_INVALID");
  }
});

test("refuses statements for sessions this adapter does not hold, without creating state", async (t) => {
  const { server, tmpRoot } = await makeBindContext(t);
  await holdSession(tmpRoot);
  const handshakes = join(tmpRoot, ".clockchain", "handshakes");
  // Unknown session.
  assertRefused(await callBind(server, statement({ runId: OTHER_SESSION })), "BIND_SESSION_NOT_HELD");
  assert.equal(existsSync(join(handshakes, OTHER_SESSION)), false);
  // Held session, other side: the side must match the session's role.
  assertRefused(await callBind(server, statement({ side: "responder" })), "BIND_SESSION_NOT_HELD");
  assert.equal(existsSync(join(handshakes, SESSION, "responder")), false);
});

test("refuses when the session wallet or committed policy is missing or mismatched", async (t) => {
  const { server, tmpRoot } = await makeBindContext(t);
  const sessions = [
    ["aaaaaaaa-0000-4000-8000-000000000001", { wallet: false }],
    ["aaaaaaaa-0000-4000-8000-000000000002", { policy: false }],
    ["aaaaaaaa-0000-4000-8000-000000000003", { policyRole: "responder" }],
  ];
  for (const [sessionId, options] of sessions) {
    await holdSession(tmpRoot, { sessionId, ...options });
    assertRefused(await callBind(server, statement({ runId: sessionId })), "BIND_SESSION_NOT_HELD");
  }
  // No wallet file was created by the refusal.
  assert.equal(
    existsSync(join(tmpRoot, ".clockchain", "handshakes", sessions[0][0], "initiator", "wallet.json")),
    false,
  );
});

test("refuses symlinked or non-private session directories", async (t) => {
  const { server, tmpRoot } = await makeBindContext(t);
  const realDir = await holdSession(tmpRoot);
  // A symlinked role dir pointing at a real held session.
  const linked = "bbbbbbbb-0000-4000-8000-000000000001";
  await mkdir(join(tmpRoot, ".clockchain", "handshakes", linked), { mode: 0o700 });
  await symlink(realDir, join(tmpRoot, ".clockchain", "handshakes", linked, "initiator"));
  assertRefused(await callBind(server, statement({ runId: linked })), "BIND_SESSION_NOT_HELD");
  // A symlinked session dir.
  const linkedSession = "bbbbbbbb-0000-4000-8000-000000000002";
  await symlink(join(tmpRoot, ".clockchain", "handshakes", SESSION),
    join(tmpRoot, ".clockchain", "handshakes", linkedSession));
  assertRefused(await callBind(server, statement({ runId: linkedSession })), "BIND_SESSION_NOT_HELD");
  // A group-readable role dir.
  await chmod(realDir, 0o750);
  assertRefused(await callBind(server, statement()), "BIND_SESSION_NOT_HELD");
  await chmod(realDir, 0o700);
  assert.equal((await callBind(server, statement())).result.isError, undefined);
});

test("not a signing oracle: only the bind statement is ever signed", async (t) => {
  const { server, tmpRoot } = await makeBindContext(t);
  await holdSession(tmpRoot);
  // Arbitrary payload shapes an attacker would use to reach the key.
  for (const args of [
    { message: "hello" },
    { bytesHex: `0x${"11".repeat(32)}` },
    { digest: `0x${"22".repeat(32)}` },
    { raw: `0x${"33".repeat(32)}` },
    { ...statement(), message: "hello" },
  ]) {
    assertRefused(await callBind(server, args), "BIND_ARGUMENTS_INVALID");
  }
  // The signature commits to every field: changing any field invalidates it.
  const signed = JSON.parse((await callBind(server, statement())).result.content[0].text);
  for (const [key, value] of Object.entries({
    runId: OTHER_SESSION, side: "responder", tokenKeyId: "klb2",
    serverKeyId: "other-server", challenge: "d".repeat(64),
    issuedAt: new Date(NOW_MS).toISOString(),
  })) {
    const tampered = { ...signed.statement, [key]: value };
    const recovered = await recoverMessageAddress({
      message: { raw: contractCanonicalDigest(tampered) }, signature: signed.signature,
    });
    assert.notEqual(recovered.toLowerCase(), TEST_ADDRESS, key);
  }
  // The zero-input authorize_local_action contract is unchanged.
  const execution = await server.handleMessage({
    jsonrpc: "2.0", id: 9, method: "tools/call",
    params: { name: ADAPTER_TOOL, arguments: statement() },
  });
  assert.equal(execution.error.code, -32602);
});

test("no key leak across every response the tool can produce", async (t) => {
  const { server, tmpRoot } = await makeBindContext(t);
  await holdSession(tmpRoot);
  const responses = [
    await callBind(server, statement()),
    await callBind(server, statement({ side: "responder" })),
    await callBind(server, statement({ runId: OTHER_SESSION })),
    await callBind(server, { ...statement(), extra: 1 }),
    await server.handleMessage({ jsonrpc: "2.0", id: 3, method: "tools/list", params: {} }),
  ];
  for (const response of responses) assertNoKey(response);
  const output = JSON.parse(responses[0].result.content[0].text);
  assert.deepEqual(Object.keys(output).sort(), ["sessionKeyAddress", "signature", "statement"]);
  // The wallet on disk still holds the key — it was read, never echoed.
  const walletText = readFileSync(
    join(tmpRoot, ".clockchain", "handshakes", SESSION, "initiator", "wallet.json"), "utf8",
  );
  assert.ok(walletText.toLowerCase().includes(TEST_KEY_HEX));
});

// --- L1: per-company tokenKeyId / serverKeyId pins ------------------------------

test("L1: refuses every statement when no key-id pins are configured", async (t) => {
  const saved = [process.env.CLOCKCHAIN_LOCAL_ADAPTER_BIND_TOKEN_KEY_IDS, process.env.CLOCKCHAIN_LOCAL_ADAPTER_BIND_SERVER_KEY_IDS];
  delete process.env.CLOCKCHAIN_LOCAL_ADAPTER_BIND_TOKEN_KEY_IDS;
  delete process.env.CLOCKCHAIN_LOCAL_ADAPTER_BIND_SERVER_KEY_IDS;
  t.after(() => {
    for (const [name, value] of [["CLOCKCHAIN_LOCAL_ADAPTER_BIND_TOKEN_KEY_IDS", saved[0]], ["CLOCKCHAIN_LOCAL_ADAPTER_BIND_SERVER_KEY_IDS", saved[1]]]) {
      if (value === undefined) delete process.env[name]; else process.env[name] = value;
    }
  });
  const { server, tmpRoot } = await makeBindContext(t, { contractBind: null });
  await holdSession(tmpRoot);
  assertRefused(await callBind(server, statement()), "BIND_NOT_CONFIGURED");
  // Only one of the two pins set is still unconfigured.
  process.env.CLOCKCHAIN_LOCAL_ADAPTER_BIND_TOKEN_KEY_IDS = "klb1";
  const half = (await makeBindContext(t, { contractBind: null }));
  await holdSession(half.tmpRoot);
  assertRefused(await callBind(half.server, statement()), "BIND_NOT_CONFIGURED");
});

test("L1: pins come from the launchd environment when no option is passed", async (t) => {
  const saved = [process.env.CLOCKCHAIN_LOCAL_ADAPTER_BIND_TOKEN_KEY_IDS, process.env.CLOCKCHAIN_LOCAL_ADAPTER_BIND_SERVER_KEY_IDS];
  t.after(() => {
    for (const [name, value] of [["CLOCKCHAIN_LOCAL_ADAPTER_BIND_TOKEN_KEY_IDS", saved[0]], ["CLOCKCHAIN_LOCAL_ADAPTER_BIND_SERVER_KEY_IDS", saved[1]]]) {
      if (value === undefined) delete process.env[name]; else process.env[name] = value;
    }
  });
  process.env.CLOCKCHAIN_LOCAL_ADAPTER_BIND_TOKEN_KEY_IDS = "kb-old, klb1";
  process.env.CLOCKCHAIN_LOCAL_ADAPTER_BIND_SERVER_KEY_IDS = "contract-server";
  const { server, tmpRoot } = await makeBindContext(t, { contractBind: null });
  await holdSession(tmpRoot);
  assert.equal((await callBind(server, statement())).result.isError, undefined);
  assertRefused(await callBind(server, statement({ tokenKeyId: "klb2" })), "BIND_KEY_ID_NOT_ALLOWED");
  // A malformed pin list fails closed for every call, never partially.
  process.env.CLOCKCHAIN_LOCAL_ADAPTER_BIND_TOKEN_KEY_IDS = "klb1,has space";
  const bad = await makeBindContext(t, { contractBind: null });
  await holdSession(bad.tmpRoot);
  assertRefused(await callBind(bad.server, statement()), "BIND_NOT_CONFIGURED");
});

test("L1: refuses tokenKeyId / serverKeyId values outside the company pins", async (t) => {
  const { server, tmpRoot } = await makeBindContext(t, {
    contractBind: { tokenKeyIds: ["klb1", "klb9"], serverKeyIds: ["contract-server", "contract-server-next"] },
  });
  await holdSession(tmpRoot);
  for (const args of [
    statement({ tokenKeyId: "klb2" }),
    statement({ tokenKeyId: "KLB1" }),
    statement({ serverKeyId: "contract-server-test" }),
    statement({ serverKeyId: "evil-server" }),
  ]) {
    assertRefused(await callBind(server, args), "BIND_KEY_ID_NOT_ALLOWED");
  }
  for (const args of [
    statement({ tokenKeyId: "klb9" }),
    statement({ serverKeyId: "contract-server-next" }),
  ]) {
    assert.equal((await callBind(server, args)).result.isError, undefined);
  }
});

test("L1: malformed pin options fail closed", async (t) => {
  for (const contractBind of [
    { tokenKeyIds: [], serverKeyIds: ["contract-server"] },
    { tokenKeyIds: ["klb1"], serverKeyIds: [""] },
    { tokenKeyIds: "klb1", serverKeyIds: ["contract-server"] },
    { tokenKeyIds: ["klb1"], serverKeyIds: ["contract-server"], extra: true },
  ]) {
    const { server, tmpRoot } = await makeBindContext(t, { contractBind });
    await holdSession(tmpRoot);
    assertRefused(await callBind(server, statement()), "BIND_NOT_CONFIGURED");
  }
});

// --- L3: the session's own deadline ------------------------------------------

test("L3: refuses once the verified session's deadline has passed", async (t) => {
  let nowMs = NOW_MS;
  const { server, tmpRoot } = await makeBindContext(t, { now: () => nowMs });
  const expiresAtMs = NOW_MS + 60_000;
  await holdSession(tmpRoot, { expiresAtMs });
  nowMs = expiresAtMs - 1;
  assert.equal(
    (await callBind(server, statement({ issuedAt: new Date(nowMs).toISOString() }))).result.isError,
    undefined,
  );
  nowMs = expiresAtMs;
  assertRefused(
    await callBind(server, statement({ issuedAt: new Date(nowMs).toISOString() })),
    "BIND_SESSION_EXPIRED",
  );
  nowMs = expiresAtMs + 3_600_000;
  assertRefused(
    await callBind(server, statement({ issuedAt: new Date(nowMs).toISOString() })),
    "BIND_SESSION_EXPIRED",
  );
});

test("L3: refuses a session whose certificate the adapter never verified", async (t) => {
  const { server, tmpRoot } = await makeBindContext(t);
  await holdSession(tmpRoot, { verified: false });
  assertRefused(await callBind(server, statement()), "BIND_SESSION_NOT_VERIFIED");
});

test("L3: refuses a verified-session record that does not match the session", async (t) => {
  const { server, tmpRoot } = await makeBindContext(t);
  const cases = [
    ["cccccccc-0000-4000-8000-000000000001", { recordSessionId: OTHER_SESSION }],
    ["cccccccc-0000-4000-8000-000000000002", { recordRole: "responder" }],
    ["cccccccc-0000-4000-8000-000000000003", { sessionKeyAddress: `0x${"ab".repeat(20)}` }],
  ];
  for (const [sessionId, options] of cases) {
    await holdSession(tmpRoot, { sessionId, ...options });
    const response = await callBind(server, statement({ runId: sessionId }));
    assert.equal(response.result.isError, true, sessionId);
    assert.match(response.result.content[0].text, /\((BIND_SESSION_NOT_VERIFIED|BIND_SIGNING_FAILED)\)\.$/);
    assertNoKey(response);
  }
});

test("L3: the verified-session record is write-once and shape-checked", async (t) => {
  const tmpRoot = await mkdtemp(join(tmpdir(), "local-adapter-record-"));
  t.after(() => rm(tmpRoot, { recursive: true, force: true }));
  const stateDir = join(tmpRoot, "s");
  await mkdir(stateDir, { mode: 0o700 });
  const good = { stateDir, sessionId: SESSION, role: "initiator", sessionKeyAddress: TEST_ADDRESS, expiresAtMs: NOW_MS };
  for (const bad of [
    { ...good, sessionId: "x" },
    { ...good, role: "buyer" },
    { ...good, sessionKeyAddress: TEST_ADDRESS.toUpperCase() },
    { ...good, expiresAtMs: -1 },
    { ...good, expiresAtMs: 1.5 },
  ]) assert.equal(await recordVerifiedSession(bad), false);
  assert.equal(await recordVerifiedSession(good), true);
  assert.equal(await recordVerifiedSession({ ...good, expiresAtMs: NOW_MS + 1 }), false);
});
