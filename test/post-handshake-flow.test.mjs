import assert from "node:assert/strict";
import test from "node:test";

import {
  createPostHandshakeContinueRole,
  runPostHandshakeFlow,
} from "../src/testing/post-handshake-flow.mjs";

const PUBLIC_EVIDENCE = Object.freeze({
  schema: "clockchain.fresh-agent-canary-evidence/v1",
  certificateVerified: true,
});

test("does nothing when no post-handshake flow is configured", async () => {
  const result = await runPostHandshakeFlow({
    flow: null,
    evidence: PUBLIC_EVIDENCE,
    continueRole: async () => assert.fail("continuation must not run"),
    secretCanaries: [],
  });

  assert.equal(result, null);
});

test("continues only a known role with namespaced nonempty environment", async () => {
  const calls = [];
  const continueRole = createPostHandshakeContinueRole({
    roles: {
      initiator: Object.freeze({ client: "codex", workspace: "/tmp/init" }),
      responder: Object.freeze({ client: "claude", workspace: "/tmp/respond" }),
    },
    invoke: async (request) => {
      calls.push(request);
      return Object.freeze({ ok: true });
    },
  });

  await continueRole("initiator", {
    prompt: "Send the stored proposal.",
    environment: { AGENT_CONTRACT_A2A_ROLE_TOKEN: "initiator-only" },
  });

  assert.deepEqual(calls, [{
    role: "initiator",
    client: "codex",
    workspace: "/tmp/init",
    prompt: "Send the stored proposal.",
    environment: { AGENT_CONTRACT_A2A_ROLE_TOKEN: "initiator-only" },
  }]);
  await assert.rejects(
    continueRole("responder", { prompt: "x", environment: { ROLE_TOKEN: "wrong-prefix" } }),
    /AGENT_CONTRACT_A2A_/,
  );
  await assert.rejects(
    continueRole("provider", { prompt: "x", environment: {} }),
    /role/i,
  );
  await assert.rejects(
    continueRole("responder", { prompt: "x", environment: { AGENT_CONTRACT_A2A_TOKEN: "" } }),
    /nonempty/i,
  );
});

test("passes frozen public evidence and accepts a valid secret-free result", async () => {
  const result = await runPostHandshakeFlow({
    flow: async ({ evidence, continueRole }) => {
      assert.equal(Object.isFrozen(evidence), true);
      assert.equal(continueRole.name.length > 0, true);
      return Object.freeze({
        schema: "agent-contract.facilitated-a2a-result/v1",
        sessionId: "public-session",
      });
    },
    evidence: PUBLIC_EVIDENCE,
    continueRole: async function continueRole() {},
    secretCanaries: ["role-capability-canary"],
  });

  assert.deepEqual(result, {
    schema: "agent-contract.facilitated-a2a-result/v1",
    sessionId: "public-session",
  });
  assert.equal(Object.isFrozen(result), true);
});

test("rejects malformed or secret-bearing flow results", async () => {
  await assert.rejects(
    runPostHandshakeFlow({
      flow: async () => ({ schema: "wrong/v1" }),
      evidence: PUBLIC_EVIDENCE,
      continueRole: async () => {},
      secretCanaries: [],
    }),
    /schema/i,
  );
  await assert.rejects(
    runPostHandshakeFlow({
      flow: async () => ({
        schema: "agent-contract.facilitated-a2a-result/v1",
        detail: "role-capability-canary",
      }),
      evidence: PUBLIC_EVIDENCE,
      continueRole: async () => {},
      secretCanaries: ["role-capability-canary"],
    }),
    /secret material/i,
  );
});
