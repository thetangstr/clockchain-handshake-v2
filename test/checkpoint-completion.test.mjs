import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { gzipSync } from "node:zlib";

import { privateKeyToAccount } from "viem/accounts";

import { AGENT_HANDSHAKE_HELPER_VERSION } from "../src/agent-handshake/v2/constants.mjs";
import { digestHex } from "../src/core/canonical.mjs";
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

function fakeCheckpointClient({ digestOverride, joinResult, nextResult, nextResults, role = "initiator", submitResult, submitError } = {}) {
  const calls = [];
  const queue = nextResults === undefined ? null : [...nextResults];
  // The deployed certificateResponse is stage-less: top-level role,
  // sessionId, certificateSummary, and localAction only.
  const terminalAction = {
    role,
    sessionId: SESSION,
    certificateSummary: {
      schema: "clockchain.agent-handshake-certificate-summary/v1",
      outcome: "VERIFIED",
      resultDigest: "a".repeat(64),
      role,
      sessionId: SESSION,
    },
    localAction: {
      executor: "pinned_helper",
      operation: "verify-certificate",
      helperStep: { operation: "verify-certificate", role, sessionId: SESSION },
      stateDir: "reuse_exact_absolute_state_dir",
      terminalProof: "use_verified_helper_output_only",
    },
  };
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
        if (queue !== null) return queue.length > 1 ? queue.shift() : queue[0];
        return nextResult ?? terminalAction;
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

const COUNTERPART_ADDRESS = `0x${"2".repeat(40)}`;
const REGISTRY_ADDRESS = `0x${"3".repeat(40)}`;

function erc8004Record(agentId) {
  return {
    agentId,
    chainId: "11155111",
    registryAddress: REGISTRY_ADDRESS,
    reference: `11155111:${REGISTRY_ADDRESS}:${agentId}`,
    registrationTx: `0x${"f".repeat(64)}`,
    registrationBlock: "1234",
  };
}

// A coordinator-shaped certificate verification: the helper's flattened
// result plus the verify-certificate payload carried in the step argv.
function verifyFixture({ role = "initiator", sessionId = SESSION } = {}) {
  const certResult = {
    anchors: [
      { blockHeight: "10", blockTimeRaw: "t1", digest: "a".repeat(64), kind: "proposal", ledgerId: "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeee10" },
      { blockHeight: "11", blockTimeRaw: "t2", digest: "b".repeat(64), kind: "acceptance", ledgerId: "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeee11" },
      { blockHeight: "12", blockTimeRaw: "t3", digest: "d".repeat(64), kind: "acknowledgment", ledgerId: "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeee12" },
    ],
    externalBusinessActionPerformed: false,
    hostSessionKeyCertificateDigest: "1".repeat(64),
    identityPolicy: { chainId: "11155111", erc8004: "required", registryAddress: REGISTRY_ADDRESS },
    issuedAtMs: "1800000000000",
    outcome: "VERIFIED",
    parties: {
      initiator: {
        sessionKeyAddress: ACCOUNT.address.toLowerCase(),
        policyDigest: POLICY_DIGEST,
        erc8004: erc8004Record("42"),
      },
      responder: {
        sessionKeyAddress: COUNTERPART_ADDRESS,
        policyDigest: "e".repeat(64),
        erc8004: erc8004Record("43"),
      },
    },
    policyDigests: { initiator: POLICY_DIGEST, responder: "e".repeat(64) },
    reference: "run-ref",
    schema: "clockchain.agent-handshake-result/v2",
    sessionDigest: "2".repeat(64),
    sessionId,
    statementDigest: "3".repeat(64),
    subjectRun: "stakeholder",
  };
  const payload = {
    schema: "clockchain.agent-handshake-certificate-verification/v1",
    helperVersion: AGENT_HANDSHAKE_HELPER_VERSION,
    role,
    sessionId,
    repositorySha: "0".repeat(40),
    sessionDeadlineMs: "1800003600000",
    certificate: { result: certResult, hostSessionKeyCertificate: { digest: "4".repeat(64) }, signer: { address: `0x${"5".repeat(40)}` } },
    externalBusinessActionPerformed: false,
  };
  const argv = [
    "node", "--input-type=commonjs", "--eval", "BOOTSTRAP", "f".repeat(64),
    "./manifest.json", "./clockchain-agent-handshake.cjs",
    "verify-certificate", "--state-dir", "/tmp/state",
    "--payload-base64url", Buffer.from(JSON.stringify(payload), "utf8").toString("base64url"),
  ];
  const party = certResult.parties[role];
  const result = {
    schema: HELPER_RESULT_SCHEMA,
    helperVersion: AGENT_HANDSHAKE_HELPER_VERSION,
    operation: "verify-certificate",
    certificateVerified: true,
    externalBusinessActionPerformed: false,
    identity: party,
    outcome: "VERIFIED",
    policyDigest: party.policyDigest,
    role,
    sessionId,
    statementDigest: certResult.statementDigest,
  };
  return { argv, certResult, payload, result };
}

// Builds a verify-certificate completion; mutate(fixture) may alter
// result/payload/certResult fields before the argv payload is re-encoded.
function verifyCompletion(mutate, { role = "initiator", sessionId = SESSION } = {}) {
  const fixture = verifyFixture({ role, sessionId });
  mutate?.(fixture);
  const argv = [...fixture.argv];
  argv[argv.length - 1] = Buffer.from(JSON.stringify(fixture.payload), "utf8").toString("base64url");
  return {
    fixture,
    completion: completionFor({
      operation: "verify-certificate", argv, result: fixture.result, role, sessionId, stateDir: "/tmp/state",
    }),
  };
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
  for (const operation of ["init", "policy"]) {
    const accepted = await handler(completionFor({ operation, result: { ok: true }, argv: ["node"], stateDir }));
    assert.deepEqual(accepted, { accepted: true });
  }
  assert.equal(client.calls.length, 0);
});

test("verify-certificate completion emits the trusted terminal proof from the helper result", async (t) => {
  const stateDir = await mkdtemp(join(tmpdir(), "cc-state-"));
  t.after(() => rm(stateDir, { recursive: true, force: true }));
  const client = fakeCheckpointClient();
  const terminals = [];
  const { bindRoleAccess, handler } = createCheckpointCompletionHandler({
    checkpointState: {},
    getCheckpointClient: async () => client,
    onTerminal: (proof) => terminals.push(proof),
  });
  bindRoleAccess({ access: HANDLE, role: "initiator", sessionId: SESSION });
  const { fixture, completion } = verifyCompletion();
  const accepted = await handler(completion);
  assert.deepEqual(accepted, { accepted: true });
  assert.equal(terminals.length, 1);
  const proof = terminals[0];
  assert.equal(proof.schema, "clockchain.fresh-agent-terminal-proof/v1");
  assert.equal(proof.role, "initiator");
  assert.equal(proof.sessionId, SESSION);
  assert.equal(proof.policyDigest, POLICY_DIGEST);
  assert.equal(proof.address, ACCOUNT.address.toLowerCase());
  assert.deepEqual(proof.erc8004, {
    agentId: "42",
    reference: `11155111:${REGISTRY_ADDRESS}:42`,
    registrationTx: `0x${"f".repeat(64)}`,
    registrationBlock: "1234",
  });
  assert.deepEqual(proof.receiptIds, ["a".repeat(64), "b".repeat(64), "d".repeat(64)]);
  assert.equal(proof.certificateDigest, digestHex(fixture.certResult));
  assert.equal(proof.certificateVerified, true);
  assert.equal(proof.externalBusinessActionPerformed, false);
  // The trusted path consumes no coordinator calls and never asks the client.
  assert.equal(client.calls.length, 0);
});

test("verify-certificate completion fails closed on mismatched or malformed results", async (t) => {
  const stateDir = await mkdtemp(join(tmpdir(), "cc-state-"));
  t.after(() => rm(stateDir, { recursive: true, force: true }));
  const terminals = [];
  const { bindRoleAccess, handler } = createCheckpointCompletionHandler({
    checkpointState: {},
    getCheckpointClient: async () => { throw new Error("unreachable"); },
    onTerminal: (proof) => terminals.push(proof),
  });
  bindRoleAccess({ access: HANDLE, role: "initiator", sessionId: SESSION });
  const mutations = [
    // Result envelope and semantics.
    (f) => { f.result.schema = "clockchain.agent-handshake-cli-result/v2"; },
    (f) => { f.result.helperVersion = "2.1.3"; },
    (f) => { f.result.operation = "sign"; },
    (f) => { f.result.role = "responder"; },
    (f) => { f.result.sessionId = "bbbbbbbb-cccc-4ddd-8eee-ffffffffffff"; },
    (f) => { f.result.certificateVerified = false; },
    (f) => { f.result.outcome = "FAILED"; },
    (f) => { f.result.externalBusinessActionPerformed = true; },
    (f) => { f.result.policyDigest = "zz"; },
    (f) => { f.result.statementDigest = "4".repeat(64); },
    (f) => { delete f.result.identity; },
    (f) => { f.result.identity = { ...f.result.identity, sessionKeyAddress: COUNTERPART_ADDRESS }; },
    (f) => { f.result.identity = { ...f.result.identity, policyDigest: "5".repeat(64) }; },
    (f) => { f.result.identity = { ...f.result.identity, erc8004: null }; },
    (f) => { f.result.identity = { ...f.result.identity, erc8004: { ...f.result.identity.erc8004, agentId: "99" } }; },
    (f) => { f.result.identity = { ...f.result.identity, erc8004: { ...f.result.identity.erc8004, registrationTx: "0x1234" } }; },
    (f) => { f.result.identity = { ...f.result.identity, erc8004: { ...f.result.identity.erc8004, reference: "eip155:1:wrong" } }; },
    // Payload binding.
    (f) => { f.payload.schema = "clockchain.agent-handshake-signing-request/v1"; },
    (f) => { f.payload.helperVersion = "2.1.3"; },
    (f) => { f.payload.role = "responder"; },
    (f) => { f.payload.sessionId = "bbbbbbbb-cccc-4ddd-8eee-ffffffffffff"; },
    (f) => { f.payload.externalBusinessActionPerformed = true; },
    (f) => { delete f.payload.certificate; },
    // Canonical result inside the certificate.
    (f) => { f.certResult.schema = "clockchain.agent-handshake-result/v3"; },
    (f) => { f.certResult.outcome = "FAILED"; },
    (f) => { f.certResult.sessionId = "bbbbbbbb-cccc-4ddd-8eee-ffffffffffff"; },
    (f) => { f.certResult.statementDigest = "6".repeat(64); },
    (f) => { f.certResult.externalBusinessActionPerformed = true; },
    (f) => { f.certResult.policyDigests.initiator = "7".repeat(64); },
    (f) => { f.certResult.parties.initiator = { ...f.certResult.parties.initiator, sessionKeyAddress: COUNTERPART_ADDRESS }; },
    (f) => { f.certResult.parties.initiator = { ...f.certResult.parties.initiator, policyDigest: "7".repeat(64) }; },
    (f) => { f.certResult.parties.initiator = { ...f.certResult.parties.initiator, erc8004: { ...f.certResult.parties.initiator.erc8004, agentId: "77" } }; },
    // Anchors become the receiptIds.
    (f) => { f.certResult.anchors = f.certResult.anchors.slice(0, 2); },
    (f) => { f.certResult.anchors = [f.certResult.anchors[1], f.certResult.anchors[0], f.certResult.anchors[2]]; },
    (f) => { f.certResult.anchors = f.certResult.anchors.map((a) => ({ ...a, digest: "a".repeat(64) })); },
    (f) => { f.certResult.anchors = [...f.certResult.anchors.slice(0, 2), { ...f.certResult.anchors[2], digest: "not-hex" }]; },
  ];
  for (const mutate of mutations) {
    const { completion } = verifyCompletion(mutate);
    await assert.rejects(() => handler(completion), /failed safely/);
    assert.equal(terminals.length, 0);
  }
  // A verify-certificate completion with no bound role access also fails.
  const { handler: unbound } = createCheckpointCompletionHandler({
    checkpointState: {},
    getCheckpointClient: async () => { throw new Error("unreachable"); },
    onTerminal: (proof) => terminals.push(proof),
  });
  const { completion } = verifyCompletion();
  await assert.rejects(() => unbound(completion), /failed safely/);
  // The responder's own proof binds to the responder party fields.
  const responderTerminals = [];
  const responderBinding = createCheckpointCompletionHandler({
    checkpointState: {},
    getCheckpointClient: async () => { throw new Error("unreachable"); },
    onTerminal: (proof) => responderTerminals.push(proof),
  });
  responderBinding.bindRoleAccess({ access: HANDLE, role: "responder", sessionId: SESSION });
  const responder = verifyCompletion(undefined, { role: "responder" });
  assert.deepEqual(await responderBinding.handler(responder.completion), { accepted: true });
  assert.equal(responderTerminals.length, 1);
  assert.equal(responderTerminals[0].role, "responder");
  assert.equal(responderTerminals[0].address, COUNTERPART_ADDRESS);
  assert.equal(responderTerminals[0].policyDigest, "e".repeat(64));
  assert.equal(responderTerminals[0].erc8004.agentId, "43");
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
    recordSteps: countingSteps([]),
  });
  bindRoleAccess({ access: HANDLE, role: "initiator", sessionId: SESSION });
  const accepted = await handler(completionFor({
    argv: signingArgv(request, stateDir),
    result,
    role: "initiator",
    stateDir,
  }));
  assert.deepEqual(accepted, { accepted: true });
  // Checkpoint, submit, then the trusted next advancement to the queued action.
  assert.equal(client.calls.length, 3);
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
    role: "responder",
    submitResult: { role: "responder", sessionId: SESSION, stage: "acceptance_submitted" },
  });
  const { bindRoleAccess, handler } = createCheckpointCompletionHandler({
    checkpointState,
    getCheckpointClient: async () => client,
    recordSteps: countingSteps([], "responder"),
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
  assert.equal(client.calls.length, 3);
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

// Mirrors the production recordSteps contract: extracts same-role helper
// steps from the trusted result, enqueues them, and returns the count.
function countingSteps(recorded, role = "initiator") {
  return (result) => {
    const steps = [];
    const action = result?.localAction;
    if (action?.helperStep) steps.push(action.helperStep);
    if (Array.isArray(action?.helperSteps)) steps.push(...action.helperSteps);
    for (const step of steps) {
      if (["initiator", "responder"].includes(step?.role) && step.role !== role) {
        throw new Error("cross-role step");
      }
    }
    recorded.push(...steps);
    return steps.length;
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
    recordSteps: countingSteps(recorded),
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
  assert.deepEqual(recorded, [joinStep]);
});

test("register completion advances through next until an action queues", async (t) => {
  const stateDir = await mkdtemp(join(tmpdir(), "cc-state-"));
  t.after(() => rm(stateDir, { recursive: true, force: true }));
  const recorded = [];
  const nextStep = { operation: "sign", role: "responder", sessionId: SESSION };
  const client = fakeCheckpointClient({
    role: "responder",
    nextResults: [
      { needed: null, nextAction: "call_agent_handshake_next_with_unchanged_role_access", role: "responder", sessionId: SESSION, stage: "party_ready" },
      { role: "responder", sessionId: SESSION, stage: "sign_acceptance", localAction: { helperStep: nextStep } },
    ],
  });
  const { bindRoleAccess, handler } = createCheckpointCompletionHandler({
    checkpointState: {},
    getCheckpointClient: async () => client,
    recordSteps: countingSteps(recorded, "responder"),
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
  assert.deepEqual(client.calls.map((entry) => entry.name), ["agent_handshake_next", "agent_handshake_next"]);
  assert.equal(client.calls[0].args.access, HANDLE);
  assert.equal(client.calls[0].args.waitMs, 15_000);
  assert.deepEqual(recorded, [nextStep]);
});

test("identity_claim submit advances next through waits until an action queues", async (t) => {
  const stateDir = await mkdtemp(join(tmpdir(), "cc-state-"));
  t.after(() => rm(stateDir, { recursive: true, force: true }));
  const request = signingRequest({ operation: "identity_claim" });
  const result = await signResult(request, stateDir);
  const recorded = [];
  const proposalStep = { operation: "sign", role: "initiator", sessionId: SESSION };
  const client = fakeCheckpointClient({
    submitResult: { role: "initiator", sessionId: SESSION, stage: "identity_claimed" },
    nextResults: [
      { needed: "counterpart_identity", nextAction: "call_agent_handshake_next_with_unchanged_role_access", retryAfterMs: 3000, role: "initiator", sessionId: SESSION, stage: "awaiting_counterpart" },
      { role: "initiator", sessionId: SESSION, stage: "sign_proposal", localAction: { helperStep: proposalStep } },
    ],
  });
  const { bindRoleAccess, handler } = createCheckpointCompletionHandler({
    checkpointState: {},
    getCheckpointClient: async () => client,
    recordSteps: countingSteps(recorded),
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
    ["agent_handshake_submit", "agent_handshake_next", "agent_handshake_next"],
  );
  assert.equal(client.calls[1].args.waitMs, 15_000);
  assert.deepEqual(recorded, [proposalStep]);
});

test("next advancement requeues the certificate verify local action", async (t) => {
  const stateDir = await mkdtemp(join(tmpdir(), "cc-state-"));
  t.after(() => rm(stateDir, { recursive: true, force: true }));
  const request = signingRequest({ operation: "evidence" });
  const result = await signResult(request, stateDir);
  const recorded = [];
  const verifyStep = { operation: "verify-certificate", role: "initiator", sessionId: SESSION };
  const client = fakeCheckpointClient({
    submitResult: { role: "initiator", sessionId: SESSION, stage: "evidence_submitted" },
    nextResults: [
      { needed: "certificate", nextAction: "call_agent_handshake_next_with_unchanged_role_access", retryAfterMs: 5000, sessionId: SESSION, stage: "awaiting_certificate" },
      // The deployed certificateResponse is stage-less with the exact
      // summary and pinned_helper envelope.
      {
        role: "initiator",
        sessionId: SESSION,
        certificateSummary: {
          schema: "clockchain.agent-handshake-certificate-summary/v1",
          outcome: "VERIFIED",
          resultDigest: "b".repeat(64),
          role: "initiator",
          sessionId: SESSION,
        },
        localAction: {
          executor: "pinned_helper",
          operation: "verify-certificate",
          helperStep: verifyStep,
          stateDir: "reuse_exact_absolute_state_dir",
          terminalProof: "use_verified_helper_output_only",
        },
      },
    ],
  });
  const { bindRoleAccess, handler } = createCheckpointCompletionHandler({
    checkpointState: {},
    getCheckpointClient: async () => client,
    recordSteps: countingSteps(recorded),
  });
  bindRoleAccess({ access: HANDLE, role: "initiator", sessionId: SESSION });
  const accepted = await handler(completionFor({
    argv: signingArgv(request, stateDir),
    result,
    role: "initiator",
    stateDir,
  }));
  assert.deepEqual(accepted, { accepted: true });
  assert.deepEqual(recorded, [verifyStep]);
});

test("next advancement fails closed on budget exhaustion and the call bound", async (t) => {
  const stateDir = await mkdtemp(join(tmpdir(), "cc-state-"));
  t.after(() => rm(stateDir, { recursive: true, force: true }));
  // A perpetual dependency wait consumes the time budget.
  {
    let clock = 1_000_000;
    const waiting = {
      needed: "counterpart_identity",
      nextAction: "call_agent_handshake_next_with_unchanged_role_access",
      retryAfterMs: 3000,
      role: "initiator",
      sessionId: SESSION,
      stage: "awaiting_counterpart",
    };
    const calls = [];
    const client = {
      calls,
      connect: async () => {},
      callTool: async (name, args) => {
        calls.push({ name, args });
        if (name === "agent_handshake_submit") return { role: "initiator", sessionId: SESSION, stage: "identity_claimed" };
        if (name === "agent_handshake_next") { clock += args.waitMs; return waiting; }
        throw new Error("unexpected");
      },
    };
    const request = signingRequest({ operation: "identity_claim" });
    const result = await signResult(request, stateDir);
    const advances = [];
    const { bindRoleAccess, handler } = createCheckpointCompletionHandler({
      advanceBudgetMs: 45_000,
      checkpointState: {},
      getCheckpointClient: async () => client,
      now: () => clock,
      onAdvance: (advance) => advances.push(advance),
      recordSteps: countingSteps([]),
    });
    bindRoleAccess({ access: HANDLE, role: "initiator", sessionId: SESSION });
    await assert.rejects(() => handler(completionFor({
      argv: signingArgv(request, stateDir),
      result,
      role: "initiator",
      stateDir,
    })), /failed safely/);
    const waits = calls.filter((entry) => entry.name === "agent_handshake_next");
    assert.ok(waits.length >= 1 && waits.length <= 16);
    for (const entry of waits) assert.ok(entry.args.waitMs >= 0 && entry.args.waitMs <= 15_000);
    assert.equal(advances.length, 1);
    assert.equal(advances[0].error, "budget");
    assert.equal(advances[0].calls, waits.length);
    assert.equal(advances[0].stage, null);
  }
  // A perpetual immediate continue is bounded by the call cap, not the clock.
  {
    const calls = [];
    const client = {
      calls,
      connect: async () => {},
      callTool: async (name, args) => {
        calls.push({ name, args });
        if (name === "agent_handshake_submit") return { role: "initiator", sessionId: SESSION, stage: "identity_claimed" };
        if (name === "agent_handshake_next") {
          return { needed: null, nextAction: "call_agent_handshake_next_with_unchanged_role_access", role: "initiator", sessionId: SESSION, stage: "party_ready" };
        }
        throw new Error("unexpected");
      },
    };
    const request = signingRequest({ operation: "identity_claim" });
    const result = await signResult(request, stateDir);
    const advances = [];
    const { bindRoleAccess, handler } = createCheckpointCompletionHandler({
      checkpointState: {},
      getCheckpointClient: async () => client,
      onAdvance: (advance) => advances.push(advance),
      recordSteps: countingSteps([]),
    });
    bindRoleAccess({ access: HANDLE, role: "initiator", sessionId: SESSION });
    await assert.rejects(() => handler(completionFor({
      argv: signingArgv(request, stateDir),
      result,
      role: "initiator",
      stateDir,
    })), /failed safely/);
    assert.equal(calls.filter((entry) => entry.name === "agent_handshake_next").length, 16);
    assert.equal(advances.length, 1);
    assert.equal(advances[0].error, "bound");
    assert.equal(advances[0].calls, 16);
  }
});

test("next advancement reports bounded failure categories", async (t) => {
  const stateDir = await mkdtemp(join(tmpdir(), "cc-state-"));
  t.after(() => rm(stateDir, { recursive: true, force: true }));
  const run = async ({ nextResults, recordSteps }) => {
    const client = {
      calls: [],
      connect: async () => {},
      callTool: async (name) => {
        client.calls.push(name);
        if (name === "agent_handshake_submit") return { role: "initiator", sessionId: SESSION, stage: "identity_claimed" };
        if (name === "agent_handshake_next") {
          const next = nextResults.shift();
          if (next instanceof Error) throw next;
          return next ?? { needed: null, nextAction: "call_agent_handshake_next_with_unchanged_role_access", role: "initiator", sessionId: SESSION, stage: "party_ready" };
        }
        throw new Error("unexpected");
      },
    };
    const request = signingRequest({ operation: "identity_claim" });
    const result = await signResult(request, stateDir);
    const advances = [];
    const { bindRoleAccess, handler } = createCheckpointCompletionHandler({
      checkpointState: {},
      getCheckpointClient: async () => client,
      onAdvance: (advance) => advances.push(advance),
      recordSteps,
    });
    bindRoleAccess({ access: HANDLE, role: "initiator", sessionId: SESSION });
    await assert.rejects(() => handler(completionFor({
      argv: signingArgv(request, stateDir),
      result,
      role: "initiator",
      stateDir,
    })), /failed safely/);
    return advances.at(-1);
  };
  // A rejected next call reports "call" with zero completed calls.
  {
    const advance = await run({ nextResults: [new Error("socket closed")], recordSteps: countingSteps([]) });
    assert.equal(advance.error, "call");
    assert.equal(advance.calls, 0);
    assert.equal(advance.stage, null);
    assert.ok(Number.isSafeInteger(advance.elapsedMs) && advance.elapsedMs >= 0);
  }
  // A malformed next result reports "classify" and the bounded stage label.
  {
    const advance = await run({
      nextResults: [{ needed: null, nextAction: null, role: "initiator", sessionId: SESSION, stage: "imposter_stage" }],
      recordSteps: countingSteps([]),
    });
    assert.equal(advance.error, "classify");
    assert.equal(advance.calls, 1);
    assert.equal(advance.stage, "imposter_stage");
  }
  // A requeue rejection reports "requeue".
  {
    const advance = await run({
      nextResults: [{
        localAction: { helperStep: { operation: "register", role: "initiator", sessionId: SESSION } },
        role: "initiator",
        sessionId: SESSION,
        stage: "sign_identity",
      }],
      recordSteps: (result) => {
        if (result?.localAction !== undefined && result.localAction !== null) throw new Error("rejected");
        return 0;
      },
    });
    assert.equal(advance.error, "requeue");
    assert.equal(advance.calls, 1);
    assert.equal(advance.stage, "sign_identity");
  }
});

test("next advancement fails closed on malformed, mismatched, and unexpected results", async (t) => {
  const stateDir = await mkdtemp(join(tmpdir(), "cc-state-"));
  t.after(() => rm(stateDir, { recursive: true, force: true }));
  const request = signingRequest({ operation: "identity_claim" });
  const result = await signResult(request, stateDir);
  const completion = () => completionFor({
    argv: signingArgv(request, stateDir),
    result,
    role: "initiator",
    stateDir,
  });
  for (const nextResult of [
    "not-an-object",
    { role: "responder", sessionId: SESSION, stage: "sign_proposal", localAction: {} },
    { role: "initiator", sessionId: "bbbbbbbb-cccc-4ddd-8eee-ffffffffffff", stage: "sign_proposal", localAction: {} },
    { role: "initiator", sessionId: SESSION, stage: "bogus_stage", localAction: {} },
    { role: "initiator", sessionId: SESSION, stage: "awaiting_counterpart", needed: "counterpart_identity", nextAction: "do_something_else", retryAfterMs: 3000 },
    { needed: "agent_handshake_join", nextAction: "call_agent_handshake_join_now_with_access_and_exact_init_policy_inspect_outputs", role: "initiator", sessionId: SESSION, stage: "invited" },
    { role: "initiator", sessionId: SESSION, stage: "awaiting_counterpart", needed: "counterpart_identity" },
    { role: "initiator", sessionId: SESSION, stage: "sign_proposal" },
    { role: "initiator", sessionId: SESSION, stage: "sign_proposal", localAction: "not-an-object" },
    // Bare and partial waits: a retryAfterMs alone is not a valid dependency
    // wait — it needs an allowed stage, a non-null needed, and the exact
    // continue directive.
    { role: "initiator", sessionId: SESSION, retryAfterMs: 2000 },
    { role: "initiator", sessionId: SESSION, stage: "awaiting_proposal", retryAfterMs: 2000 },
    { role: "initiator", sessionId: SESSION, stage: "awaiting_proposal", nextAction: "call_agent_handshake_next_with_unchanged_role_access", retryAfterMs: 2000 },
    { role: "initiator", sessionId: SESSION, stage: "awaiting_proposal", needed: null, nextAction: "call_agent_handshake_next_with_unchanged_role_access", retryAfterMs: 2000 },
    { role: "initiator", sessionId: SESSION, stage: "awaiting_proposal", needed: "bogus_needed", nextAction: "call_agent_handshake_next_with_unchanged_role_access", retryAfterMs: 2000 },
    { role: "initiator", sessionId: SESSION, stage: "awaiting_proposal", needed: "proposal", nextAction: "call_agent_handshake_next_with_unchanged_role_access", retryAfterMs: -1 },
    { role: "initiator", sessionId: SESSION, stage: "awaiting_proposal", needed: "proposal", nextAction: "call_agent_handshake_next_with_unchanged_role_access", retryAfterMs: 10 ** 12 },
    { role: "initiator", sessionId: SESSION, stage: "awaiting_proposal", needed: "proposal", nextAction: "call_agent_handshake_next_with_unchanged_role_access", retryAfterMs: 0 },
    // Funding directives are bound to their stages: the funding literal on
    // another wait, the continue literal on a funding wait, or a mismatched
    // needed are all malformed.
    { role: "initiator", sessionId: SESSION, stage: "awaiting_proposal", needed: "proposal", nextAction: "wait_for_clockchain_host_funding_then_call_agent_handshake_next_with_unchanged_role_access", retryAfterMs: 3000 },
    { role: "initiator", sessionId: SESSION, stage: "awaiting_funding", needed: "funding_record", nextAction: "call_agent_handshake_next_with_unchanged_role_access", retryAfterMs: 3000 },
    { role: "initiator", sessionId: SESSION, stage: "awaiting_funding", needed: "proposal", nextAction: "wait_for_clockchain_host_funding_then_call_agent_handshake_next_with_unchanged_role_access", retryAfterMs: 3000 },
    { role: "initiator", sessionId: SESSION, stage: "awaiting_funding_visibility", needed: "funding_visibility", nextAction: "wait_for_clockchain_host_funding_then_call_agent_handshake_next_with_unchanged_role_access", retryAfterMs: 3000 },
    { role: "initiator", sessionId: SESSION, stage: "awaiting_counterpart", needed: "counterpart_identity", nextAction: "wait_for_clockchain_host_funding_visibility_then_call_agent_handshake_next_with_unchanged_role_access", retryAfterMs: 3000 },
    // An action must carry an allowed stage; requeue alone is not enough.
    { role: "initiator", sessionId: SESSION, localAction: { helperStep: { operation: "sign", role: "initiator", sessionId: SESSION } } },
    // A result cannot be both an action and a wait.
    { role: "initiator", sessionId: SESSION, stage: "sign_proposal", localAction: {}, retryAfterMs: 2000 },
  ]) {
    const client = fakeCheckpointClient({
      submitResult: { role: "initiator", sessionId: SESSION, stage: "identity_claimed" },
      nextResult,
    });
    const { bindRoleAccess, handler } = createCheckpointCompletionHandler({
      checkpointState: {},
      getCheckpointClient: async () => client,
      recordSteps: countingSteps([]),
    });
    bindRoleAccess({ access: HANDLE, role: "initiator", sessionId: SESSION });
    await assert.rejects(() => handler(completion()), /failed safely/, JSON.stringify(nextResult));
  }
  // A trusted next result carrying only a counterpart-role step rejects.
  {
    const client = fakeCheckpointClient({
      submitResult: { role: "initiator", sessionId: SESSION, stage: "identity_claimed" },
      nextResult: {
        role: "initiator",
        sessionId: SESSION,
        stage: "sign_proposal",
        localAction: { helperStep: { operation: "sign", role: "responder", sessionId: SESSION } },
      },
    });
    const { bindRoleAccess, handler } = createCheckpointCompletionHandler({
      checkpointState: {},
      getCheckpointClient: async () => client,
      recordSteps: countingSteps([]),
    });
    bindRoleAccess({ access: HANDLE, role: "initiator", sessionId: SESSION });
    await assert.rejects(() => handler(completion()), /failed safely/);
  }
});

test("stage-less certificate action requires the exact summary contract", async (t) => {
  const stateDir = await mkdtemp(join(tmpdir(), "cc-state-"));
  t.after(() => rm(stateDir, { recursive: true, force: true }));
  const request = signingRequest({ operation: "identity_claim" });
  const result = await signResult(request, stateDir);
  const completion = () => completionFor({
    argv: signingArgv(request, stateDir),
    result,
    role: "initiator",
    stateDir,
  });
  const certificateResult = (mutate) => {
    const value = {
      role: "initiator",
      sessionId: SESSION,
      certificateSummary: {
        schema: "clockchain.agent-handshake-certificate-summary/v1",
        outcome: "VERIFIED",
        resultDigest: "a".repeat(64),
        role: "initiator",
        sessionId: SESSION,
      },
      localAction: {
        executor: "pinned_helper",
        operation: "verify-certificate",
        helperStep: { operation: "verify-certificate", role: "initiator", sessionId: SESSION },
        stateDir: "reuse_exact_absolute_state_dir",
        terminalProof: "use_verified_helper_output_only",
      },
    };
    return mutate === undefined ? value : mutate(value);
  };
  const negatives = [
    // Summary contract: schema, outcome, digest, role, session all exact.
    certificateResult((v) => { v.certificateSummary.schema = "bogus"; return v; }),
    certificateResult((v) => { v.certificateSummary.outcome = "FAILED"; return v; }),
    certificateResult((v) => { v.certificateSummary.resultDigest = "zz"; return v; }),
    certificateResult((v) => { v.certificateSummary.role = "responder"; return v; }),
    certificateResult((v) => { v.certificateSummary.sessionId = "bbbbbbbb-cccc-4ddd-8eee-ffffffffffff"; return v; }),
    certificateResult((v) => { delete v.certificateSummary; return v; }),
    // Top-level binding and wait/directive fields must be exact/absent.
    certificateResult((v) => { v.role = "responder"; return v; }),
    certificateResult((v) => { delete v.sessionId; return v; }),
    certificateResult((v) => { v.needed = "certificate"; return v; }),
    certificateResult((v) => { v.nextAction = "call_agent_handshake_next_with_unchanged_role_access"; return v; }),
    // The helper step must be this role/session's verify-certificate.
    certificateResult((v) => { v.localAction.helperStep.operation = "sign"; return v; }),
    certificateResult((v) => { v.localAction.helperStep.role = "responder"; return v; }),
    certificateResult((v) => { v.localAction = {}; return v; }),
    // The envelope itself is the exact certificate contract, not a generic
    // wrapper around a certificate-looking summary.
    certificateResult((v) => { v.localAction.executor = "model"; return v; }),
    certificateResult((v) => { v.localAction.operation = "sign"; return v; }),
    certificateResult((v) => { v.localAction.stateDir = "/tmp/arbitrary"; return v; }),
    certificateResult((v) => { v.localAction.terminalProof = "summarize_it_yourself"; return v; }),
    // A stage-less action that is not the certificate response fails.
    { role: "initiator", sessionId: SESSION, localAction: { helperStep: { operation: "sign", role: "initiator", sessionId: SESSION } } },
  ];
  for (const nextResult of negatives) {
    const client = fakeCheckpointClient({
      submitResult: { role: "initiator", sessionId: SESSION, stage: "identity_claimed" },
      nextResult,
    });
    const { bindRoleAccess, handler } = createCheckpointCompletionHandler({
      checkpointState: {},
      getCheckpointClient: async () => client,
      recordSteps: countingSteps([]),
    });
    bindRoleAccess({ access: HANDLE, role: "initiator", sessionId: SESSION });
    await assert.rejects(() => handler(completion()), /failed safely/, JSON.stringify(nextResult));
  }
  // The exact stage-less certificate shape requeues verify-certificate.
  const recorded = [];
  const client = fakeCheckpointClient({
    submitResult: { role: "initiator", sessionId: SESSION, stage: "identity_claimed" },
    nextResult: certificateResult(),
  });
  const { bindRoleAccess, handler } = createCheckpointCompletionHandler({
    checkpointState: {},
    getCheckpointClient: async () => client,
    recordSteps: countingSteps(recorded),
  });
  bindRoleAccess({ access: HANDLE, role: "initiator", sessionId: SESSION });
  assert.deepEqual(await handler(completion()), { accepted: true });
  assert.equal(recorded.length, 1);
  assert.equal(recorded[0].operation, "verify-certificate");
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
    recordSteps: countingSteps([]),
  });
  bindRoleAccess({ access: HANDLE, role: "initiator", sessionId: SESSION });
  const accepted = await handler(completionFor({
    argv: signingArgv(request, stateDir),
    result,
    role: "initiator",
    stateDir,
  }));
  assert.deepEqual(accepted, { accepted: true });
  // identity_claim carries no private checkpoint: submit then the trusted
  // next advancement to the queued action.
  assert.deepEqual(client.calls.map((entry) => entry.name), ["agent_handshake_submit", "agent_handshake_next"]);
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
    recordSteps: countingSteps([]),
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
    ["agent_handshake_submit_checkpoint", "agent_handshake_submit", "agent_handshake_next"],
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
  // Join must enqueue at least one same-role helper step: a result with no
  // localAction (or a recorder reporting zero) rejects the completion.
  for (const joinResult of [
    { role: "initiator", sessionId: SESSION },
    { role: "initiator", sessionId: SESSION, localAction: {} },
  ]) {
    await assert.rejects(
      () => make(fakeCheckpointClient({ joinResult }), countingSteps([]))(inspectCompletion()),
      /failed safely/,
      JSON.stringify(joinResult),
    );
  }
  await assert.rejects(
    () => make(fakeCheckpointClient(), () => 0)(inspectCompletion()),
    /failed safely/,
  );
  // A join result whose only step belongs to the counterpart role rejects.
  await assert.rejects(
    () => make(
      fakeCheckpointClient({
        joinResult: {
          role: "initiator",
          sessionId: SESSION,
          localAction: { helperStep: { operation: "sign", role: "responder", sessionId: SESSION } },
        },
      }),
      countingSteps([]),
    )(inspectCompletion()),
    /failed safely/,
  );
  // Client acquisition failure is the same generic completion error.
  for (const completion of [inspectCompletion(), signCompletion()]) {
    const { bindRoleAccess, handler } = createCheckpointCompletionHandler({
      checkpointState: {},
      getCheckpointClient: async () => { throw new Error("no client"); },
      recordSteps: countingSteps([]),
    });
    bindRoleAccess({ access: HANDLE, role: "initiator", sessionId: SESSION });
    await assert.rejects(() => handler(completion), /failed safely/);
  }
});

test("register completion follows a wait response until an action queues", async (t) => {
  const stateDir = await mkdtemp(join(tmpdir(), "cc-state-"));
  t.after(() => rm(stateDir, { recursive: true, force: true }));
  const recorded = [];
  const signStep = { operation: "sign", role: "responder", sessionId: SESSION };
  const client = fakeCheckpointClient({
    role: "responder",
    nextResults: [
      { needed: "proposal", nextAction: "call_agent_handshake_next_with_unchanged_role_access", retryAfterMs: 5000, role: "responder", sessionId: SESSION, stage: "awaiting_proposal" },
      { role: "responder", sessionId: SESSION, stage: "sign_acceptance", localAction: { helperStep: signStep } },
    ],
  });
  const { bindRoleAccess, handler } = createCheckpointCompletionHandler({
    checkpointState: {},
    getCheckpointClient: async () => client,
    recordSteps: countingSteps(recorded, "responder"),
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
  assert.equal(client.calls.filter((entry) => entry.name === "agent_handshake_next").length, 2);
  assert.deepEqual(recorded, [signStep]);
});

test("next advancement follows both clockchain-host funding waits", async (t) => {
  const stateDir = await mkdtemp(join(tmpdir(), "cc-state-"));
  t.after(() => rm(stateDir, { recursive: true, force: true }));
  const fundingWaits = [
    { needed: "funding_record", nextAction: "wait_for_clockchain_host_funding_then_call_agent_handshake_next_with_unchanged_role_access", retryAfterMs: 3000, role: "responder", sessionId: SESSION, stage: "awaiting_funding" },
    { needed: "funding_visibility", nextAction: "wait_for_clockchain_host_funding_visibility_then_call_agent_handshake_next_with_unchanged_role_access", retryAfterMs: 3000, role: "responder", sessionId: SESSION, stage: "awaiting_funding_visibility" },
  ];
  for (const wait of fundingWaits) {
    const recorded = [];
    const registerStep = { operation: "register", role: "responder", sessionId: SESSION };
    const client = fakeCheckpointClient({
      role: "responder",
      nextResults: [
        wait,
        { role: "responder", sessionId: SESSION, stage: "awaiting_identity_registration", localAction: { helperStep: registerStep } },
      ],
    });
    const { bindRoleAccess, handler } = createCheckpointCompletionHandler({
      checkpointState: {},
      getCheckpointClient: async () => client,
      recordSteps: countingSteps(recorded, "responder"),
    });
    bindRoleAccess({ access: HANDLE, role: "responder", sessionId: SESSION });
    const accepted = await handler(completionFor({
      operation: "register",
      argv: ["node"],
      result: registerResult(),
      role: "responder",
      stateDir,
    }));
    assert.deepEqual(accepted, { accepted: true }, wait.stage);
    assert.equal(client.calls.filter((entry) => entry.name === "agent_handshake_next").length, 2);
    assert.deepEqual(recorded, [registerStep]);
  }
});
