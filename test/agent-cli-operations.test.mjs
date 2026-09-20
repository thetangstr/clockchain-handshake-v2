import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { createAgentCliOperations } from "../src/agent-cli/operations.mjs";
import { buildAgentCliFixture } from "./support/agent-cli-fixture.mjs";

test("dispatcher exposes exactly init, policy, inspect, register, sign, and verify-certificate", async (t) => {
  const stateDir = await mkdtemp(join(tmpdir(), "clockchain-agent-ops-"));
  await rm(stateDir, { recursive: true });
  t.after(() => rm(stateDir, { force: true, recursive: true }));
  const fixture = await buildAgentCliFixture();
  const address = fixture.parties.initiator.sessionKeyAddress;
  const registration = fixture.parties.initiator.erc8004;
  const calls = [];
  const bridge = {
    initializeWallet: async () => ({ address }),
    inspectWallet: async () => ({
      address,
      registration: {
        schema: "clockchain.handshake-registration-recovery/v1",
        agentId: registration.agentId,
        address,
        identityReference: registration.reference,
        registerTx: registration.registrationTx,
        registerBlock: registration.registrationBlock,
      },
    }),
    registerWalletIdentity: async () => ({
      agentId: registration.agentId,
      address,
      transaction: { register: registration.registrationTx, metadata: null },
      block: { register: registration.registrationBlock, metadata: null },
      identity: { identityReference: registration.reference },
    }),
    signExactBytes: async (input) => {
      calls.push(input);
      return { address, bytesSha256: fixture.request.bytesSha256, signatureHex: "0x" + "1".repeat(130) };
    },
  };
  const operations = createAgentCliOperations({ bridge, now: () => fixture.nowMs, rootKeyRing: fixture.rootKeyRing });
  assert.deepEqual(operations.names, ["init", "policy", "inspect", "register", "sign", "verify-certificate"]);
  assert.equal((await operations.dispatch({ operation: "init", stateDir })).address, address);
  assert.match((await operations.dispatch({ operation: "policy", stateDir, payload: fixture.policy })).policyDigest, /^[0-9a-f]{64}$/);
  assert.equal((await operations.dispatch({ operation: "inspect", stateDir })).address, address);
  assert.equal((await operations.dispatch({ operation: "register", stateDir })).registration.agentId, registration.agentId);
  assert.equal((await operations.dispatch({ operation: "sign", stateDir, payload: fixture.request })).signatureHex.length, 132);
  const verified = await operations.dispatch({
    operation: "verify-certificate",
    stateDir,
    payload: {
      schema: "clockchain.agent-handshake-certificate-verification/v1",
      helperVersion: "2.1.7",
      role: "initiator",
      sessionId: fixture.request.sessionId,
      repositorySha: fixture.request.repositorySha,
      sessionDeadlineMs: fixture.request.sessionDeadlineMs,
      certificate: fixture.resultEnvelope,
      externalBusinessActionPerformed: false,
    },
  });
  assert.equal(verified.certificateVerified, true);
  await assert.rejects(() => operations.dispatch({ operation: "shell", stateDir }));
  assert.equal(calls.length, 1);
});

test("dispatch normalizes redundant separators in stateDir before the private-path guard", async (t) => {
  // Real-world macOS shape: $TMPDIR is exported with a trailing slash, so a
  // caller-built "$TMPDIR/.clockchain/..." arrives with a redundant "//" that
  // the private-path self-check would otherwise reject byte-for-byte.
  const name = `clockchain-agent-ops-${process.pid}-norm`;
  const canonical = join(tmpdir(), name);
  const stateDir = `${tmpdir()}/${name}`;
  t.after(() => rm(canonical, { force: true, recursive: true }));
  const fixture = await buildAgentCliFixture();
  const address = fixture.parties.initiator.sessionKeyAddress;
  const bridge = {
    initializeWallet: async () => ({ address }),
    inspectWallet: async () => ({ address, registration: null }),
    registerWalletIdentity: async () => { throw new Error("unreachable"); },
    signExactBytes: async () => { throw new Error("unreachable"); },
  };
  const operations = createAgentCliOperations({ bridge, now: () => fixture.nowMs, rootKeyRing: fixture.rootKeyRing });
  await operations.dispatch({ operation: "init", stateDir });
  const committed = await operations.dispatch({ operation: "policy", stateDir, payload: fixture.policy });
  const inspected = await operations.dispatch({ operation: "inspect", stateDir });
  assert.match(committed.policyDigest, /^[0-9a-f]{64}$/);
  assert.equal(inspected.policyDigest, committed.policyDigest);
});

test("inspect reports a null registration before register under a required_fresh policy", async (t) => {
  const stateDir = await mkdtemp(join(tmpdir(), "clockchain-agent-ops-inspect-"));
  await rm(stateDir, { recursive: true });
  t.after(() => rm(stateDir, { force: true, recursive: true }));
  const fixture = await buildAgentCliFixture();
  const address = fixture.parties.initiator.sessionKeyAddress;
  const bridge = {
    initializeWallet: async () => ({ address }),
    inspectWallet: async () => ({ address, registration: null }),
    registerWalletIdentity: async () => { throw new Error("unreachable"); },
    signExactBytes: async () => { throw new Error("unreachable"); },
  };
  const operations = createAgentCliOperations({ bridge, now: () => fixture.nowMs, rootKeyRing: fixture.rootKeyRing });
  await operations.dispatch({ operation: "init", stateDir });
  const committed = await operations.dispatch({ operation: "policy", stateDir, payload: fixture.policy });
  const inspected = await operations.dispatch({ operation: "inspect", stateDir });
  assert.equal(inspected.address, address);
  assert.equal(inspected.policyDigest, committed.policyDigest);
  assert.equal(inspected.registration, null);
});
