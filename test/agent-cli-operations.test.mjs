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
      helperVersion: "2.1.3",
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

test("inspect reports a committed required-fresh policy before registration", async (t) => {
  const stateDir = await mkdtemp(join(tmpdir(), "clockchain-agent-preregister-"));
  await rm(stateDir, { recursive: true });
  t.after(() => rm(stateDir, { force: true, recursive: true }));
  const fixture = await buildAgentCliFixture();
  const address = fixture.parties.initiator.sessionKeyAddress;
  const operations = createAgentCliOperations({
    bridge: {
      initializeWallet: async () => ({ address }),
      inspectWallet: async () => ({ address, registration: null }),
    },
  });

  await operations.dispatch({ operation: "init", stateDir });
  const committed = await operations.dispatch({ operation: "policy", stateDir, payload: fixture.policy });
  assert.deepEqual(await operations.dispatch({ operation: "inspect", stateDir }), {
    schema: "clockchain.agent-handshake-cli-result/v1",
    helperVersion: "2.1.3",
    operation: "inspect",
    address: address.toLowerCase(),
    policyDigest: committed.policyDigest,
    registration: null,
  });
});
