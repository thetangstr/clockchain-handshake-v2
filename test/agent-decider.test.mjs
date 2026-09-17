import assert from "node:assert/strict";
import test from "node:test";

import {
  buildAgentDecisionPrompt,
  makeAgentDecider,
  parseAgentDecision,
  resolveDeciderModel,
} from "../scripts/agent-decider.mjs";

const context = {
  amount: { currency: "USD", value: "100" },
  amountOptions: [{ currency: "USD", value: "100" }],
  windowMs: 1_800_000,
  payer: { agentId: "buyer", address: "0xabc" },
  payee: { agentId: "provider" },
  protocol: "clockchain-handshake/2",
  sessionId: "session-1",
};

test("resolves known aliases and leaves raw model names on the default provider", () => {
  assert.deepEqual(resolveDeciderModel("glm-5.3-flash"), { provider: "zai", model: "glm-5.3-flash" });
  assert.deepEqual(resolveDeciderModel("kimi-k3"), { provider: "zai", model: "kimi-k3" });
  assert.deepEqual(resolveDeciderModel("custom-model"), { provider: "zai", model: "custom-model" });
});

test("parses exact compact decisions only", () => {
  assert.deepEqual(parseAgentDecision('{"accept":true,"reason":"terms look ordinary"}'), {
    accept: true,
    reason: "terms look ordinary",
  });
  assert.deepEqual(parseAgentDecision('{"accept":false,"reason":"amount is too large"}'), {
    accept: false,
    reason: "amount is too large",
  });
  assert.deepEqual(parseAgentDecision('{"accept":true,"reason":"ok"}\n'), {
    accept: true,
    reason: "ok",
  });

  for (const raw of [
    '```json\n{"accept":true,"reason":"ok"}\n```',
    'yes {"accept":true,"reason":"ok"}',
    '{"accept":true,"reason":"ok","extra":1}',
    '{"accept":"true","reason":"ok"}',
    '{"accept":true,"reason":""}',
    '{"accept":true,"reason":" has spaces "}',
    '{"accept":true,"reason":"two\\nlines"}',
    `{"accept":true,"reason":"${"x".repeat(141)}"}`,
    "x".repeat(4097),
  ]) {
    assert.equal(parseAgentDecision(raw), null, raw);
  }
});

test("agent decider sends bounded hermes call, accepts and declines exact replies", async () => {
  const calls = [];
  const logs = [];
  const decide = makeAgentDecider({
    provider: "zai",
    model: "glm-5.3-flash",
    timeoutMs: 123,
    log: (line) => logs.push(line),
    runHermes: async (...args) => {
      calls.push(args);
      return { stdout: '{"accept":true,"reason":"ordinary invoice"}' };
    },
  });
  assert.deepEqual(await decide(context), { accept: true, reason: "ordinary invoice" });
  assert.equal(calls[0][0], "hermes");
  assert.equal(calls[0][2].timeout, 123);
  assert.equal(calls[0][2].maxBuffer, 4096);
  assert.ok(calls[0][1].includes("--ignore-rules"));
  assert.match(calls[0][1][1], /USD 100/);
  assert.match(calls[0][1][1], /Reply with exactly this compact JSON shape/);
  assert.match(logs.at(-1), /ACCEPT - ordinary invoice/);

  const decline = makeAgentDecider({
    provider: "zai",
    model: "kimi-k3",
    runHermes: async () => ({ stdout: '{"accept":false,"reason":"amount is implausible"}' }),
  });
  assert.deepEqual(await decline(context), { accept: false, reason: "amount is implausible" });
});

test("agent decider fails closed without logging raw malformed output", async () => {
  const logs = [];
  const decide = makeAgentDecider({
    provider: "zai",
    model: "glm-5.3-flash",
    log: (line) => logs.push(line),
    runHermes: async () => ({ stdout: "RAW SECRET {not json}" }),
  });
  await assert.rejects(decide(context), /AGENT_DECISION_UNPARSEABLE/);
  assert.equal(logs.some((line) => line.includes("RAW SECRET")), false);
});

test("agent decider reports runner failures and timeouts as unavailable", async () => {
  const failure = makeAgentDecider({
    provider: "zai",
    model: "glm-5.3-flash",
    runHermes: async () => {
      const error = new Error("boom");
      error.code = 127;
      throw error;
    },
  });
  await assert.rejects(failure(context), /AGENT_DECISION_UNAVAILABLE/);

  const timeout = makeAgentDecider({
    provider: "zai",
    model: "glm-5.3-flash",
    runHermes: async () => {
      const error = new Error("slow");
      error.killed = true;
      throw error;
    },
  });
  await assert.rejects(timeout(context), /AGENT_DECISION_UNAVAILABLE/);
});

test("prompt contains the decision terms and selected payee name", () => {
  const prompt = buildAgentDecisionPrompt(context, "Agent Ada");
  assert.match(prompt, /Agent Ada/);
  assert.match(prompt, /USD 100/);
  assert.match(prompt, /buyer/);
  assert.match(prompt, /provider/);
  assert.match(prompt, /clockchain-handshake\/2/);
});
