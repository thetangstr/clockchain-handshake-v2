import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { gzipSync } from "node:zlib";

import { privateKeyToAccount } from "viem/accounts";

import { AGENT_HANDSHAKE_HELPER_VERSION } from "../src/agent-handshake/v2/constants.mjs";
import {
  createCheckpointCompletionHandler,
  createCommitmentCheckpoint,
  commitmentCheckpointDigest,
  commitmentCheckpointSigningBytes,
  extractSigningRequestFromArgv,
  roleAccessBinding,
} from "../src/harness/checkpoint-completion.mjs";

const SESSION = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";
const POLICY_DIGEST = "c".repeat(64);
const PRIVATE_KEY = `0x${"1".repeat(64)}`;
const ACCOUNT = privateKeyToAccount(PRIVATE_KEY);
const HANDLE = `ccra_${"h".repeat(22)}`;
const HELPER_RESULT_SCHEMA = "clockchain.agent-handshake-cli-result/v1";

function payloadBytes(payload) {
  return Buffer.from(JSON.stringify(payload), "utf8");
}

function signingRequest({ operation = "proposal", role = "initiator", payload, sessionId = SESSION } = {}) {
  const bytes = payloadBytes(payload ?? { marker: `${operation}-payload` });
  return {
    schema: "clockchain.agent-handshake-signing-request/v1",
    helperVersion: AGENT_HANDSHAKE_HELPER_VERSION,
    operation,
    role,
    sessionId,
    policyDigest: POLICY_DIGEST,
    bytesGzipBase64Url: gzipSync(bytes).toString("base64url"),
    bytesSha256: createHash("sha256").update(bytes).digest("hex"),
  };
}

function signingArgv(request, stateDir = "/tmp/state") {
  return [
    "node", "--input-type=commonjs", "--eval", "BOOTSTRAP", "f".repeat(64),
    "./manifest.json", "./clockchain-agent-handshake.cjs",
    "sign", "--state-dir", stateDir,
    "--payload-base64url", Buffer.from(JSON.stringify(request), "utf8").toString("base64url"),
  ];
}

async function signResult(request, stateDir) {
  const signatureHex = await ACCOUNT.signMessage({ message: { raw: `0x${"ab".repeat(32)}` } });
  await writeFile(join(stateDir, "wallet.json"), JSON.stringify({ privateKey: PRIVATE_KEY, address: ACCOUNT.address }), { mode: 0o600 });
  return {
    schema: HELPER_RESULT_SCHEMA,
    helperVersion: AGENT_HANDSHAKE_HELPER_VERSION,
    operation: "sign",
    bytesSha256: request.bytesSha256,
    signatureHex,
    address: ACCOUNT.address,
  };
}

function fakeCheckpointClient({ digestOverride, joinResult, nextResult, role = "initiator", submitResult, submitError } = {}) {
  const calls = [];
  const client = {
    calls,
    connect: async () => {},
    callTool: async (name, args) => {
      calls.push({ name, args });
      if (name === "agent_handshake_submit_checkpoint") {
        return { checkpointDigest: digestOverride ?? commitmentCheckpointDigest(args.checkpoint) };
      }
      if (name === "agent_handshake_join") {
        return joinResult ?? { role, sessionId: SESSION, stage: "sign_identity" };
      }
      if (name === "agent_handshake_next") {
        return nextResult ?? { role, sessionId: SESSION, stage: "party_ready" };
      }
      if (name === "agent_handshake_submit") {
        if (submitError !== undefined) throw submitError;
        return submitResult ?? { role, sessionId: SESSION, stage: "proposal_submitted" };
      }
      throw new Error(`unexpected tool ${name}`);
    },
  };
  return client;
}

function completionFor({ operation = "sign", request, argv, stateDir, role = "initiator", result, sessionId = SESSION } = {}) {
  return Object.freeze({
    actionId: "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeee01",
    argv,
    commandSha256: "9".repeat(64),
    operation,
    requestDigest: "8".repeat(64),
    result,
    role,
    sessionId,
    stateDir,
  });
}

test("extractSigningRequestFromArgv validates the payload flag and request shape", () => {
  const request = signingRequest();
  const argv = signingArgv(request);
  assert.deepEqual(extractSigningRequestFromArgv(argv), request);
  for (const bad of [
    argv.slice(0, -1),
    [...argv.slice(0, -2), "not-base64url!"],
    signingArgv({ ...request, helperVersion: "2.1.3" }),
    signingArgv({ ...request, operation: "launch_missiles" }),
    signingArgv({ ...request, role: "mediator" }),
    signingArgv({ ...request, sessionId: "not-a-uuid" }),
    signingArgv({ ...request, bytesSha256: "zz" }),
    ["node", "--payload-base64url", "extra", "tail"],
  ]) {
    assert.throws(() => extractSigningRequestFromArgv(bad), /failed safely/);
  }
});

test("createCommitmentCheckpoint chains proposal then acceptance with digests", async () => {
  const nowMs = 1_800_000_000_000;
  const proposalPayload = { initiator: { sessionKeyAddress: ACCOUNT.address.toLowerCase() } };
  const artifactSignatureHex = await ACCOUNT.signMessage({ message: { raw: `0x${"cd".repeat(32)}` } });
  const proposal = await createCommitmentCheckpoint({
    artifactPayload: proposalPayload,
    artifactSignatureHex,
    artifactType: "proposal",
    nowMs,
    previousCheckpoint: null,
    role: "initiator",
    sessionId: SESSION,
    signerAddress: ACCOUNT.address.toLowerCase(),
    signMessage: ({ raw }) => ACCOUNT.signMessage({ message: { raw } }),
  });
  assert.equal(proposal.schema, "clockchain.agent-handshake-commitment-checkpoint/v1");
  assert.equal(proposal.sequence, "1");
  assert.equal(proposal.previousCheckpointDigest, null);
  assert.equal(proposal.artifactType, "proposal");
  assert.equal(proposal.signerAddress, ACCOUNT.address.toLowerCase());
  assert.match(proposal.signature.value, /^0x[0-9a-f]{130}$/);
  assert.match(commitmentCheckpointDigest(proposal), /^[0-9a-f]{64}$/);
  assert.equal(commitmentCheckpointSigningBytes(proposal).length > 0, true);

  const acceptance = await createCommitmentCheckpoint({
    artifactPayload: { responder: { sessionKeyAddress: ACCOUNT.address.toLowerCase() } },
    artifactSignatureHex,
    artifactType: "acceptance",
    nowMs,
    previousCheckpoint: proposal,
    role: "responder",
    sessionId: SESSION,
    signerAddress: ACCOUNT.address.toLowerCase(),
    signMessage: ({ raw }) => ACCOUNT.signMessage({ message: { raw } }),
  });
  assert.equal(acceptance.sequence, "2");
  assert.equal(acceptance.previousCheckpointDigest, commitmentCheckpointDigest(proposal));

  for (const bad of [
    { artifactType: "proposal", role: "responder", previousCheckpoint: null },
    { artifactType: "acceptance", role: "initiator", previousCheckpoint: proposal },
    { artifactType: "acceptance", role: "responder", previousCheckpoint: null },
    { artifactType: "proposal", role: "initiator", previousCheckpoint: proposal },
    { artifactType: "proposal", role: "initiator", previousCheckpoint: null, signerAddress: "0xBAD" },
  ]) {
    await assert.rejects(() => createCommitmentCheckpoint({
      artifactPayload: proposalPayload,
      artifactSignatureHex,
      nowMs,
      sessionId: SESSION,
      signerAddress: ACCOUNT.address.toLowerCase(),
      signMessage: ({ raw }) => ACCOUNT.signMessage({ message: { raw } }),
      ...bad,
    }), /failed safely/);
  }
});

test("roleAccessBinding accepts handle and token formats, rejects mismatches", () => {
  const token = `${Buffer.from(JSON.stringify({ role: "initiator", sessionId: SESSION })).toString("base64url")}.${"s".repeat(20)}`;
  assert.deepEqual(roleAccessBinding(token), { access: token, role: "initiator", sessionId: SESSION });
  assert.equal(roleAccessBinding(HANDLE), HANDLE);
  assert.deepEqual(
    roleAccessBinding({ access: HANDLE, role: "responder", sessionId: SESSION }),
    { access: HANDLE, role: "responder", sessionId: SESSION },
  );
  for (const bad of [
    `${Buffer.from(JSON.stringify({ role: "responder", sessionId: "bad" })).toString("base64url")}.sig`,
    { access: HANDLE, role: "responder", sessionId: "bad" },
    { access: "not-a-handle", role: "responder", sessionId: SESSION },
    "not-a-token",
  ]) {
    assert.throws(() => roleAccessBinding(bad), /failed safely/);
  }
});

test("completion handler accepts continuation-free operations without a client", async (t) => {
  const stateDir = await mkdtemp(join(tmpdir(), "cc-state-"));
  t.after(() => rm(stateDir, { recursive: true, force: true }));
  const client = fakeCheckpointClient();
  const { handler } = createCheckpointCompletionHandler({
    checkpointState: {},
    getCheckpointClient: async () => client,
  });
  for (const operation of ["init", "policy", "verify-certificate"]) {
    const accepted = await handler(completionFor({ operation, result: { ok: true }, argv: ["node"], stateDir }));
    assert.deepEqual(accepted, { accepted: true });
  }
  assert.equal(client.calls.length, 0);
});

test("completion handler fails closed on malformed results", async (t) => {
  const stateDir = await mkdtemp(join(tmpdir(), "cc-state-"));
  t.after(() => rm(stateDir, { recursive: true, force: true }));
  const { handler } = createCheckpointCompletionHandler({
    checkpointState: {},
    getCheckpointClient: async () => { throw new Error("unreachable"); },
  });
  for (const completion of [null, "x", [], { operation: "init", result: null }, { operation: "init", result: "x" }]) {
    await assert.rejects(() => handler(completion), /failed safely/);
  }
});

test("proposal sign submits a verified private checkpoint bound to role access", async (t) => {
  const stateDir = await mkdtemp(join(tmpdir(), "cc-state-"));
  t.after(() => rm(stateDir, { recursive: true, force: true }));
  const request = signingRequest({ operation: "proposal", role: "initiator" });
  const result = await signResult(request, stateDir);
  const checkpointState = {};
  const client = fakeCheckpointClient();
  const { bindRoleAccess, handler } = createCheckpointCompletionHandler({
    checkpointState,
    getCheckpointClient: async () => client,
  });
  bindRoleAccess({ access: HANDLE, role: "initiator", sessionId: SESSION });
  const accepted = await handler(completionFor({
    argv: signingArgv(request, stateDir),
    result,
    role: "initiator",
    stateDir,
  }));
  assert.deepEqual(accepted, { accepted: true });
  assert.equal(client.calls.length, 2);
  const { name, args } = client.calls[0];
  assert.equal(name, "agent_handshake_submit_checkpoint");
  assert.equal(args.access, HANDLE);
  assert.equal(args.artifactSignatureHex, result.signatureHex);
  const checkpoint = args.checkpoint;
  assert.equal(checkpoint.artifactType, "proposal");
  assert.equal(checkpoint.sequence, "1");
  assert.equal(checkpoint.sessionId, SESSION);
  assert.equal(checkpoint.role, "initiator");
  assert.equal(checkpoint.previousCheckpointDigest, null);
  assert.equal(checkpointState.proposal, checkpoint);
  assert.equal(JSON.stringify(checkpoint).includes(PRIVATE_KEY.slice(2)), false);
});

test("acceptance sign requires the retained proposal checkpoint and chains it", async (t) => {
  const stateDir = await mkdtemp(join(tmpdir(), "cc-state-"));
  t.after(() => rm(stateDir, { recursive: true, force: true }));
  const checkpointState = {};
  const client = fakeCheckpointClient({
    submitResult: { role: "responder", sessionId: SESSION, stage: "acceptance_submitted" },
  });
  const { bindRoleAccess, handler } = createCheckpointCompletionHandler({
    checkpointState,
    getCheckpointClient: async () => client,
  });
  const request = signingRequest({ operation: "acceptance", role: "responder" });
  const result = await signResult(request, stateDir);
  bindRoleAccess({ access: HANDLE, role: "responder", sessionId: SESSION });
  await assert.rejects(() => handler(completionFor({
    argv: signingArgv(request, stateDir),
    result,
    role: "responder",
    stateDir,
  })), /failed safely/);
  assert.equal(client.calls.length, 0);

  const proposalPayload = { initiator: { sessionKeyAddress: ACCOUNT.address.toLowerCase() } };
  const proposalCheckpoint = await createCommitmentCheckpoint({
    artifactPayload: proposalPayload,
    artifactSignatureHex: result.signatureHex,
    artifactType: "proposal",
    nowMs: Date.now(),
    previousCheckpoint: null,
    role: "initiator",
    sessionId: SESSION,
    signerAddress: ACCOUNT.address.toLowerCase(),
    signMessage: ({ raw }) => ACCOUNT.signMessage({ message: { raw } }),
  });
  checkpointState.proposal = proposalCheckpoint;
  const accepted = await handler(completionFor({
    argv: signingArgv(request, stateDir),
    result,
    role: "responder",
    stateDir,
  }));
  assert.equal(accepted.accepted, true);
  assert.equal(client.calls.length, 2);
  const checkpoint = client.calls[0].args.checkpoint;
  assert.equal(checkpoint.artifactType, "acceptance");
  assert.equal(checkpoint.sequence, "2");
  assert.equal(checkpoint.previousCheckpointDigest, commitmentCheckpointDigest(proposalCheckpoint));
  assert.equal(checkpointState.acceptance, checkpoint);
});

test("checkpoint submission fails closed without bound or matching role access", async (t) => {
  const stateDir = await mkdtemp(join(tmpdir(), "cc-state-"));
  t.after(() => rm(stateDir, { recursive: true, force: true }));
  const request = signingRequest({ operation: "proposal", role: "initiator" });
  const result = await signResult(request, stateDir);
  const completion = () => completionFor({
    argv: signingArgv(request, stateDir),
    result,
    role: "initiator",
    stateDir,
  });
  // No role access bound at all.
  {
    const { handler } = createCheckpointCompletionHandler({
      checkpointState: {},
      getCheckpointClient: async () => fakeCheckpointClient(),
    });
    await assert.rejects(() => handler(completion()), /failed safely/);
  }
  // Bound to a different role.
  {
    const { bindRoleAccess, handler } = createCheckpointCompletionHandler({
      checkpointState: {},
      getCheckpointClient: async () => fakeCheckpointClient(),
    });
    bindRoleAccess({ access: HANDLE, role: "responder", sessionId: SESSION });
    await assert.rejects(() => handler(completion()), /failed safely/);
  }
  // Bound to a different session.
  {
    const { bindRoleAccess, handler } = createCheckpointCompletionHandler({
      checkpointState: {},
      getCheckpointClient: async () => fakeCheckpointClient(),
    });
    bindRoleAccess({ access: HANDLE, role: "initiator", sessionId: "bbbbbbbb-cccc-4ddd-8eee-ffffffffffff" });
    await assert.rejects(() => handler(completion()), /failed safely/);
  }
});

test("bindRoleAccess pins the first object binding and rejects later divergence", () => {
  const { bindRoleAccess } = createCheckpointCompletionHandler({
    checkpointState: {},
    getCheckpointClient: async () => { throw new Error("unreachable"); },
  });
  bindRoleAccess({ access: HANDLE, role: "initiator", sessionId: SESSION });
  bindRoleAccess({ access: HANDLE, role: "initiator", sessionId: SESSION });
  bindRoleAccess(HANDLE);
  assert.throws(() => bindRoleAccess({ access: HANDLE, role: "initiator", sessionId: "bbbbbbbb-cccc-4ddd-8eee-ffffffffffff" }), /failed safely/);
  assert.throws(() => bindRoleAccess(`ccra_${"z".repeat(22)}`), /failed safely/);

  const fresh = createCheckpointCompletionHandler({
    checkpointState: {},
    getCheckpointClient: async () => { throw new Error("unreachable"); },
  });
  assert.throws(() => fresh.bindRoleAccess(HANDLE), /failed safely/);
});

test("checkpoint submission fails on digest mismatch, wallet mismatch, and bad results", async (t) => {
  const stateDir = await mkdtemp(join(tmpdir(), "cc-state-"));
  t.after(() => rm(stateDir, { recursive: true, force: true }));
  const request = signingRequest({ operation: "proposal", role: "initiator" });
  const result = await signResult(request, stateDir);
  const completion = (overrides = {}) => completionFor({
    argv: signingArgv(request, stateDir),
    result: { ...result, ...overrides.result },
    role: "initiator",
    stateDir,
    ...overrides,
  });
  // Returned checkpointDigest must equal the locally computed digest.
  {
    const { bindRoleAccess, handler } = createCheckpointCompletionHandler({
      checkpointState: {},
      getCheckpointClient: async () => fakeCheckpointClient({ digestOverride: "0".repeat(64) }),
    });
    bindRoleAccess({ access: HANDLE, role: "initiator", sessionId: SESSION });
    await assert.rejects(() => handler(completion()), /failed safely/);
  }
  // Helper result fields must match the signing request.
  for (const mutate of [
    { schema: "wrong" },
    { helperVersion: "2.1.3" },
    { operation: "inspect" },
    { bytesSha256: "0".repeat(64) },
    { signatureHex: "0xzz" },
    { address: `0x${"9".repeat(40)}` },
  ]) {
    const { bindRoleAccess, handler } = createCheckpointCompletionHandler({
      checkpointState: {},
      getCheckpointClient: async () => fakeCheckpointClient(),
    });
    bindRoleAccess({ access: HANDLE, role: "initiator", sessionId: SESSION });
    await assert.rejects(() => handler(completion({ result: mutate })), /failed safely/, JSON.stringify(mutate));
  }
  // Wallet address must match the helper-reported address.
  {
    const foreign = await mkdtemp(join(tmpdir(), "cc-state-foreign-"));
    t.after(() => rm(foreign, { recursive: true, force: true }));
    const otherKey = `0x${"2".repeat(64)}`;
    await writeFile(join(foreign, "wallet.json"), JSON.stringify({
      privateKey: otherKey,
      address: privateKeyToAccount(otherKey).address,
    }), { mode: 0o600 });
    const { bindRoleAccess, handler } = createCheckpointCompletionHandler({
      checkpointState: {},
      getCheckpointClient: async () => fakeCheckpointClient(),
    });
    bindRoleAccess({ access: HANDLE, role: "initiator", sessionId: SESSION });
    await assert.rejects(() => handler(completion({ stateDir: foreign })), /failed safely/);
  }
});

function inspectResult({ address = ACCOUNT.address, policyDigest = POLICY_DIGEST } = {}) {
  return {
    schema: HELPER_RESULT_SCHEMA,
    helperVersion: AGENT_HANDSHAKE_HELPER_VERSION,
    operation: "inspect",
    address,
    policyDigest,
    registration: null,
  };
}

function registerResult({ address = ACCOUNT.address } = {}) {
  return {
    schema: HELPER_RESULT_SCHEMA,
    helperVersion: AGENT_HANDSHAKE_HELPER_VERSION,
    operation: "register",
    address,
    registration: { agentId: "1", registrationTx: `0x${"a".repeat(64)}` },
  };
}

test("inspect completion performs the join continuation with exact helper fields", async (t) => {
  const stateDir = await mkdtemp(join(tmpdir(), "cc-state-"));
  t.after(() => rm(stateDir, { recursive: true, force: true }));
  const recorded = [];
  const joinStep = { operation: "sign", role: "initiator", sessionId: SESSION };
  const client = fakeCheckpointClient({
    joinResult: { role: "initiator", sessionId: SESSION, localAction: { helperStep: joinStep } },
  });
  const { bindRoleAccess, handler } = createCheckpointCompletionHandler({
    checkpointState: {},
    getCheckpointClient: async () => client,
    recordSteps: (result) => recorded.push(result),
  });
  bindRoleAccess({ access: HANDLE, role: "initiator", sessionId: SESSION });
  const accepted = await handler(completionFor({
    operation: "inspect",
    argv: ["node"],
    result: inspectResult(),
    stateDir,
  }));
  assert.deepEqual(accepted, { accepted: true });
  assert.deepEqual(client.calls.map((entry) => entry.name), ["agent_handshake_join"]);
  assert.deepEqual(client.calls[0].args, {
    access: HANDLE,
    helperVersion: AGENT_HANDSHAKE_HELPER_VERSION,
    sessionKeyAddress: ACCOUNT.address,
    policyDigest: POLICY_DIGEST,
  });
  // The trusted join result is handed to the recorder so newly issued local
  // actions queue; the model never sees it.
  assert.equal(recorded.length, 1);
  assert.equal(recorded[0].localAction.helperStep, joinStep);
});

test("register completion performs a bounded next continuation and requeues steps", async (t) => {
  const stateDir = await mkdtemp(join(tmpdir(), "cc-state-"));
  t.after(() => rm(stateDir, { recursive: true, force: true }));
  const recorded = [];
  const nextStep = { operation: "sign", role: "responder", sessionId: SESSION };
  const client = fakeCheckpointClient({
    nextResult: { role: "responder", sessionId: SESSION, stage: "sign_acceptance", localAction: { helperStep: nextStep } },
  });
  const { bindRoleAccess, handler } = createCheckpointCompletionHandler({
    checkpointState: {},
    getCheckpointClient: async () => client,
    recordSteps: (result) => recorded.push(result),
  });
  bindRoleAccess({ access: HANDLE, role: "responder", sessionId: SESSION });
  const accepted = await handler(completionFor({
    operation: "register",
    argv: ["node"],
    result: registerResult(),
    role: "responder",
    stateDir,
  }));
  assert.deepEqual(accepted, { accepted: true });
  assert.deepEqual(client.calls.map((entry) => entry.name), ["agent_handshake_next"]);
  assert.deepEqual(client.calls[0].args, { access: HANDLE, waitMs: 0 });
  assert.equal(recorded.length, 1);
  assert.equal(recorded[0].localAction.helperStep, nextStep);
});

test("identity_claim sign submits the exact signature with the unchanged policy digest", async (t) => {
  const stateDir = await mkdtemp(join(tmpdir(), "cc-state-"));
  t.after(() => rm(stateDir, { recursive: true, force: true }));
  const request = signingRequest({ operation: "identity_claim" });
  const result = await signResult(request, stateDir);
  const client = fakeCheckpointClient({
    submitResult: { role: "initiator", sessionId: SESSION, stage: "identity_claimed" },
  });
  const { bindRoleAccess, handler } = createCheckpointCompletionHandler({
    checkpointState: {},
    getCheckpointClient: async () => client,
  });
  bindRoleAccess({ access: HANDLE, role: "initiator", sessionId: SESSION });
  const accepted = await handler(completionFor({
    argv: signingArgv(request, stateDir),
    result,
    role: "initiator",
    stateDir,
  }));
  assert.deepEqual(accepted, { accepted: true });
  // identity_claim carries no private checkpoint: submit is the only call.
  assert.deepEqual(client.calls.map((entry) => entry.name), ["agent_handshake_submit"]);
  assert.deepEqual(client.calls[0].args, {
    access: HANDLE,
    policyDigest: POLICY_DIGEST,
    signatureHex: result.signatureHex,
  });
});

test("proposal sign keeps checkpoint-before-submit ordering", async (t) => {
  const stateDir = await mkdtemp(join(tmpdir(), "cc-state-"));
  t.after(() => rm(stateDir, { recursive: true, force: true }));
  const request = signingRequest({ operation: "proposal", role: "initiator" });
  const result = await signResult(request, stateDir);
  const client = fakeCheckpointClient();
  const { bindRoleAccess, handler } = createCheckpointCompletionHandler({
    checkpointState: {},
    getCheckpointClient: async () => client,
  });
  bindRoleAccess({ access: HANDLE, role: "initiator", sessionId: SESSION });
  const accepted = await handler(completionFor({
    argv: signingArgv(request, stateDir),
    result,
    role: "initiator",
    stateDir,
  }));
  assert.deepEqual(accepted, { accepted: true });
  assert.deepEqual(
    client.calls.map((entry) => entry.name),
    ["agent_handshake_submit_checkpoint", "agent_handshake_submit"],
  );
  assert.deepEqual(client.calls[1].args, {
    access: HANDLE,
    policyDigest: POLICY_DIGEST,
    signatureHex: result.signatureHex,
  });
});

test("continuation fails closed on tool errors, mismatches, and malformed results", async (t) => {
  const stateDir = await mkdtemp(join(tmpdir(), "cc-state-"));
  t.after(() => rm(stateDir, { recursive: true, force: true }));
  const request = signingRequest({ operation: "identity_claim" });
  const result = await signResult(request, stateDir);
  const signCompletion = () => completionFor({
    argv: signingArgv(request, stateDir),
    result,
    role: "initiator",
    stateDir,
  });
  const inspectCompletion = () => completionFor({
    operation: "inspect",
    argv: ["node"],
    result: inspectResult(),
    stateDir,
  });
  const make = (client, recordSteps) => {
    const { bindRoleAccess, handler } = createCheckpointCompletionHandler({
      checkpointState: {},
      getCheckpointClient: async () => client,
      recordSteps,
    });
    bindRoleAccess({ access: HANDLE, role: "initiator", sessionId: SESSION });
    return handler;
  };
  // Remote tool error rejects the completion.
  await assert.rejects(() => make(fakeCheckpointClient({ submitError: new Error("down") }))(signCompletion()), /failed safely/);
  // Submit stage/role/session must match the retained action exactly.
  for (const submitResult of [
    { role: "initiator", sessionId: SESSION, stage: "proposal_submitted" },
    { role: "responder", sessionId: SESSION, stage: "identity_claimed" },
    { role: "initiator", sessionId: "bbbbbbbb-cccc-4ddd-8eee-ffffffffffff", stage: "identity_claimed" },
    { role: "initiator", sessionId: SESSION },
    "not-an-object",
  ]) {
    await assert.rejects(
      () => make(fakeCheckpointClient({ submitResult }))(signCompletion()),
      /failed safely/,
      JSON.stringify(submitResult),
    );
  }
  // Join must return the same role/sessionId as the retained action.
  for (const joinResult of [
    { role: "responder", sessionId: SESSION },
    { role: "initiator", sessionId: "bbbbbbbb-cccc-4ddd-8eee-ffffffffffff" },
    "not-an-object",
  ]) {
    await assert.rejects(
      () => make(fakeCheckpointClient({ joinResult }))(inspectCompletion()),
      /failed safely/,
      JSON.stringify(joinResult),
    );
  }
  // Malformed inspect results never reach join.
  for (const mutate of [
    { policyDigest: null },
    { policyDigest: "zz" },
    { address: "0xzz" },
    { operation: "init" },
    { schema: "wrong" },
  ]) {
    const client = fakeCheckpointClient();
    const { bindRoleAccess, handler } = createCheckpointCompletionHandler({
      checkpointState: {},
      getCheckpointClient: async () => client,
    });
    bindRoleAccess({ access: HANDLE, role: "initiator", sessionId: SESSION });
    await assert.rejects(() => handler(completionFor({
      operation: "inspect",
      argv: ["node"],
      result: { ...inspectResult(), ...mutate },
      stateDir,
    })), /failed safely/, JSON.stringify(mutate));
    assert.equal(client.calls.length, 0);
  }
  // Unbound role access rejects continuation-driving operations.
  for (const completion of [inspectCompletion(), signCompletion()]) {
    const { handler } = createCheckpointCompletionHandler({
      checkpointState: {},
      getCheckpointClient: async () => fakeCheckpointClient(),
    });
    await assert.rejects(() => handler(completion), /failed safely/);
  }
  // A recorder failure rejects the completion rather than dropping the result.
  await assert.rejects(
    () => make(fakeCheckpointClient(), () => { throw new Error("queue failed"); })(inspectCompletion()),
    /failed safely/,
  );
});
