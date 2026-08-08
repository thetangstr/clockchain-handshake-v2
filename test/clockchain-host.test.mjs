import assert from "node:assert/strict";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { transitionToAnchor, anchorToWireReport } from "../src/monitor/anchor.mjs";
import {
  SessionEnded,
  applyAnchorReport,
  awaitRoleMessages,
  downloadEvidencePackages,
  evidenceDeadlineAfterAnchorReport,
  fundIdentitySeats,
  remainingWaitMinutes,
  runHostLoop,
} from "../src/roles/host.mjs";

function transition(kind, blockHeight) {
  const ledgerIds = {
    acceptance: "aaaaaaaa-1111-4111-8111-111111111111",
    acknowledgment: "bbbbbbbb-2222-4222-8222-222222222222",
    proposal: "cccccccc-3333-4333-8333-333333333333",
  };
  return {
    blockTimeMs: 1_700_000_000_000,
    blockTimeRaw: "1700000000000",
    digest: `${kind[0]}`.repeat(64),
    message: {
      amount: { currency: "USD", value: "100" },
      expirySeconds: "600",
      payee: { address: "0x" + "a".repeat(40), agentId: "11" },
      payer: { address: "0x" + "b".repeat(40), agentId: "22" },
      predecessor: kind === "proposal" ? null : { blockHeight: "100" },
      sequence: kind === "proposal" ? "1" : kind === "acceptance" ? "2" : "3",
      sessionDigest: "c".repeat(64),
    },
    onChain: {
      anchoredHash: `${kind.at(-1)}`.repeat(64),
      blockHeight: String(blockHeight),
      ledgerId: ledgerIds[kind],
    },
  };
}

test("host intake captures payer and requestor from one poll without resetting the cursor", async () => {
  const polls = [];
  const relayClient = {
    async pollMessages({ after }) {
      polls.push(after);
      return {
        messages: [
          { seq: "1", role: "payer", kind: "identity_ready", body: { address: "0x" + "1".repeat(40) } },
          { seq: "2", role: "requestor", kind: "identity_ready", body: { address: "0x" + "2".repeat(40) } },
        ],
      };
    },
  };

  const result = await awaitRoleMessages({
    relayClient,
    relayUrl: "http://relay.test",
    sessionId: "s1",
    kind: "identity_ready",
    roles: ["payer", "requestor"],
    budgetMs: 1_000,
    waitMs: 0,
    now: () => 0,
    sleep: async () => {},
  });

  assert.deepEqual(polls, ["0"]);
  assert.equal(result.after, "2");
  assert.equal(result.messages.payer.body.address, "0x" + "1".repeat(40));
  assert.equal(result.messages.requestor.body.address, "0x" + "2".repeat(40));
});

test("host intake buffers later same-poll messages for the next role wait", async () => {
  let polls = 0;
  const relayClient = {
    async pollMessages() {
      polls += 1;
      return {
        messages: [
          { seq: "1", role: "payer", kind: "identity_ready", body: { address: "0x" + "1".repeat(40) } },
          { seq: "2", role: "requestor", kind: "identity_ready", body: { address: "0x" + "2".repeat(40) } },
          { seq: "3", role: "payer", kind: "party_ready", body: { agentId: "11" } },
          { seq: "4", role: "requestor", kind: "party_ready", body: { agentId: "22" } },
        ],
      };
    },
  };

  const identity = await awaitRoleMessages({
    relayClient,
    relayUrl: "http://relay.test",
    sessionId: "s1",
    kind: "identity_ready",
    roles: ["payer", "requestor"],
    budgetMs: 1_000,
    waitMs: 0,
    now: () => 0,
    sleep: async () => {},
  });
  const ready = await awaitRoleMessages({
    relayClient,
    relayUrl: "http://relay.test",
    sessionId: "s1",
    kind: "party_ready",
    roles: ["payer", "requestor"],
    budgetMs: 1_000,
    waitMs: 0,
    after: identity.after,
    buffer: identity.buffer,
    now: () => 0,
    sleep: async () => {},
  });

  assert.equal(polls, 1);
  assert.equal(ready.after, "4");
  assert.equal(ready.messages.payer.body.agentId, "11");
  assert.equal(ready.messages.requestor.body.agentId, "22");
});

test("host intake keeps the cursor across either-order role arrivals", async () => {
  let nowMs = 0;
  const polls = [];
  const batches = [
    [{ seq: "4", role: "requestor", kind: "party_ready", body: { agentId: "9" } }],
    [{ seq: "5", role: "payer", kind: "party_ready", body: { agentId: "8" } }],
  ];
  const relayClient = {
    async pollMessages({ after }) {
      polls.push(after);
      return { messages: batches.shift() ?? [] };
    },
  };

  const result = await awaitRoleMessages({
    relayClient,
    relayUrl: "http://relay.test",
    sessionId: "s1",
    kind: "party_ready",
    roles: ["payer", "requestor"],
    budgetMs: 1_000,
    waitMs: 0,
    now: () => nowMs,
    sleep: async (ms) => { nowMs += ms; },
  });

  assert.deepEqual(polls, ["0", "4"]);
  assert.equal(result.after, "5");
  assert.equal(result.messages.payer.body.agentId, "8");
  assert.equal(result.messages.requestor.body.agentId, "9");
});

test("host funds each identity as soon as that role appears without losing messages posted during funding", async () => {
  let nowMs = 0;
  const events = [];
  const batches = [
    [{ seq: "1", role: "payer", kind: "identity_ready", body: { address: "0x" + "1".repeat(40) } }],
    [
      { seq: "2", role: "requestor", kind: "identity_ready", body: { address: "0x" + "2".repeat(40) } },
      { seq: "3", role: "payer", kind: "party_ready", body: { agentId: "11" } },
    ],
    [{ seq: "4", role: "requestor", kind: "party_ready", body: { agentId: "22" } }],
  ];
  const relayClient = {
    async pollMessages({ after }) {
      events.push(`poll:${after}`);
      return { messages: batches.shift() ?? [] };
    },
  };

  const result = await fundIdentitySeats({
    relayClient,
    relayUrl: "http://relay.test",
    sessionId: "s1",
    roles: ["payer", "requestor"],
    budgetMs: 1_000,
    waitMs: 0,
    now: () => nowMs,
    sleep: async (ms) => { nowMs += ms; },
    fundSeat: async ({ role }) => events.push(`fund:${role}`),
  });

  assert.deepEqual(events, [
    "poll:0",
    "fund:payer",
    "poll:1",
    "fund:requestor",
  ]);
  assert.equal(result.after, "3");
  assert.equal(result.messages.payer.body.address, "0x" + "1".repeat(40));
  assert.equal(result.messages.requestor.body.address, "0x" + "2".repeat(40));

  const ready = await awaitRoleMessages({
    relayClient,
    relayUrl: "http://relay.test",
    sessionId: "s1",
    kind: "party_ready",
    roles: ["payer", "requestor"],
    budgetMs: 1_000,
    waitMs: 0,
    after: result.after,
    buffer: result.buffer,
    now: () => nowMs,
    sleep: async (ms) => { nowMs += ms; },
  });
  assert.equal(ready.messages.payer.body.agentId, "11");
  assert.equal(ready.messages.requestor.body.agentId, "22");
});

test("host loop opens a fresh session after recoverable session endings", async () => {
  const events = [];
  await runHostLoop({
    boot: async () => events.push("boot"),
    cooldownMs: 5,
    maxSessions: 3,
    onError: (error) => events.push(`caught:${error.code}`),
    runOneSession: async ({ sessionNumber }) => {
      events.push(`run:${sessionNumber}`);
      if (sessionNumber < 3) throw new SessionEnded("EXPIRED", "window closed");
    },
    sleep: async (ms) => events.push(`sleep:${ms}`),
  });

  assert.deepEqual(events, [
    "boot",
    "run:1",
    "caught:EXPIRED",
    "sleep:5",
    "run:2",
    "caught:EXPIRED",
    "sleep:5",
    "run:3",
  ]);
});

test("anchor report mapping is best effort and narrates only when report is usable", async () => {
  const monitorState = {
    anchors: { acceptance: null, acknowledgment: null, proposal: null },
  };
  const said = [];
  const ok = await applyAnchorReport({
    message: {
      role: "payer",
      kind: "anchor_report",
      body: {
        transitions: {
          acceptance: transition("acceptance", 200),
          acknowledgment: transition("acknowledgment", 300),
          proposal: transition("proposal", 100),
        },
      },
    },
    monitorState,
    relayUrl: "http://relay.test",
    say: async (stage, sentence) => said.push([stage, sentence]),
    transitionToAnchor,
  });

  assert.equal(ok, true);
  assert.equal(monitorState.anchors.proposal.blockHeight, "100");
  assert.equal(monitorState.anchors.acceptance.blockHeight, "200");
  assert.equal(monitorState.anchors.acknowledgment.blockHeight, "300");
  assert.deepEqual(said.map(([stage]) => stage), ["ACCEPTED", "ACKNOWLEDGED"]);

  const before = structuredClone(monitorState.anchors);
  const bad = await applyAnchorReport({
    message: { role: "payer", kind: "anchor_report", body: { transitions: { proposal: {} } } },
    monitorState,
    relayUrl: "http://relay.test",
    say: async () => assert.fail("malformed anchor reports must not narrate"),
    transitionToAnchor,
  });

  assert.equal(bad, false);
  assert.deepEqual(monitorState.anchors, before);
});

test("anchor report mapping normalizes wire anchors back to board-shaped anchors", async () => {
  const monitorState = {
    anchors: { acceptance: null, acknowledgment: null, proposal: null },
  };
  const anchors = {
    acceptance: anchorToWireReport(transitionToAnchor("acceptance", transition("acceptance", 200), { relayUrl: "http://relay.test" })),
    acknowledgment: anchorToWireReport(transitionToAnchor("acknowledgment", transition("acknowledgment", 300), { relayUrl: "http://relay.test" })),
    proposal: anchorToWireReport(transitionToAnchor("proposal", transition("proposal", 100), { relayUrl: "http://relay.test" })),
  };

  const ok = await applyAnchorReport({
    message: { role: "payer", kind: "anchor_report", body: { anchors } },
    monitorState,
    relayUrl: "http://relay.test",
    say: async () => {},
    transitionToAnchor,
  });

  assert.equal(ok, true);
  assert.equal(monitorState.anchors.proposal.blockTime, 1_700_000_000_000);
  assert.equal(typeof monitorState.anchors.proposal.blockTime, "number");
  assert.equal(monitorState.anchors.proposal.blockHeight, "100");
  assert.equal(monitorState.anchors.acceptance.blockHeight, "200");
  assert.equal(monitorState.anchors.acknowledgment.blockHeight, "300");
});

test("anchor report mapping rejects numeric blockTime on the wire", async () => {
  const monitorState = {
    anchors: { acceptance: null, acknowledgment: null, proposal: null },
  };
  const anchors = {
    acceptance: transitionToAnchor("acceptance", transition("acceptance", 200), { relayUrl: "http://relay.test" }),
    acknowledgment: transitionToAnchor("acknowledgment", transition("acknowledgment", 300), { relayUrl: "http://relay.test" }),
    proposal: transitionToAnchor("proposal", transition("proposal", 100), { relayUrl: "http://relay.test" }),
  };

  const ok = await applyAnchorReport({
    message: { role: "payer", kind: "anchor_report", body: { anchors } },
    monitorState,
    relayUrl: "http://relay.test",
    say: async () => assert.fail("malformed anchor reports must not narrate"),
    transitionToAnchor,
  });

  assert.equal(ok, false);
  assert.deepEqual(monitorState.anchors, { acceptance: null, acknowledgment: null, proposal: null });
});

test("anchor report mapping rejects board-invalid wire anchors before mutation or narration", async () => {
  const baseAnchors = {
    acceptance: anchorToWireReport(transitionToAnchor("acceptance", transition("acceptance", 200), { relayUrl: "http://relay.test" })),
    acknowledgment: anchorToWireReport(transitionToAnchor("acknowledgment", transition("acknowledgment", 300), { relayUrl: "http://relay.test" })),
    proposal: anchorToWireReport(transitionToAnchor("proposal", transition("proposal", 100), { relayUrl: "http://relay.test" })),
  };
  const cases = [
    { ...baseAnchors, proposal: { ...baseAnchors.proposal, blockHeight: "001" } },
    { ...baseAnchors, proposal: { ...baseAnchors.proposal, ledgerId: "not-a-uuid" } },
    { ...baseAnchors, proposal: { ...baseAnchors.proposal, extra: "nope" } },
  ];

  for (const anchors of cases) {
    const monitorState = {
      anchors: { acceptance: null, acknowledgment: null, proposal: null },
    };
    const ok = await applyAnchorReport({
      message: { role: "payer", kind: "anchor_report", body: { anchors } },
      monitorState,
      relayUrl: "http://relay.test",
      say: async () => assert.fail("malformed anchor reports must not narrate"),
      transitionToAnchor,
    });

    assert.equal(ok, false);
    assert.deepEqual(monitorState.anchors, { acceptance: null, acknowledgment: null, proposal: null });
  }
});

test("rejected anchor reports preserve the original no-report evidence deadline", () => {
  assert.equal(evidenceDeadlineAfterAnchorReport({
    mapped: false,
    originalDeadlineMs: 12 * 60_000,
    nowMs: 4 * 60_000,
    evidenceAfterReportMs: 5 * 60_000,
  }), 12 * 60_000);
  assert.equal(evidenceDeadlineAfterAnchorReport({
    mapped: true,
    originalDeadlineMs: 12 * 60_000,
    nowMs: 4 * 60_000,
    evidenceAfterReportMs: 5 * 60_000,
  }), 9 * 60_000);
});

test("dual evidence download polls payer and payee together and writes separate private packages", async () => {
  const root = await mkdtemp(join(tmpdir(), "host-evidence-test-"));
  const calls = [];
  let round = 0;
  const relayClient = {
    async getEvidence({ role }) {
      calls.push(`${round}:${role}`);
      if (role === "payee" && round === 0) {
        throw Object.assign(new Error("missing"), { code: "EVIDENCE_NOT_FOUND" });
      }
      return {
        json: Buffer.from(`${role}-json`),
        markdown: Buffer.from(`${role}-markdown`),
        marker: Buffer.from(`${role}-marker`),
      };
    },
  };
  let nowMs = 0;

  try {
    const result = await downloadEvidencePackages({
      relayClient,
      relayUrl: "http://relay.test",
      sessionId: "s1",
      root,
      deadlineMs: 10_000,
      now: () => nowMs,
      sleep: async (ms) => {
        round += 1;
        nowMs += ms;
      },
      retryPauseMs: 5,
    });

    assert.deepEqual(calls, ["0:payer", "0:payee", "1:payee"]);
    assert.equal(await readFile(join(result.payerDirectory, "party-result.json"), "utf8"), "payer-json");
    assert.equal(await readFile(join(result.payeeDirectory, "PARTY-RESULT.md"), "utf8"), "payee-markdown");
  } finally {
    await rm(root, { force: true, recursive: true });
  }
});

test("dual evidence download stops missing when either side never arrives", async () => {
  const root = await mkdtemp(join(tmpdir(), "host-evidence-missing-test-"));
  let nowMs = 0;
  try {
    await assert.rejects(
      () => downloadEvidencePackages({
        relayClient: {
          async getEvidence({ role }) {
            if (role === "payee") throw Object.assign(new Error("missing"), { code: "EVIDENCE_NOT_FOUND" });
            return {
              json: Buffer.from(`${role}-json`),
              markdown: Buffer.from(`${role}-markdown`),
              marker: Buffer.from(`${role}-marker`),
            };
          },
        },
        relayUrl: "http://relay.test",
        sessionId: "s1",
        root,
        deadlineMs: 10,
        now: () => nowMs,
        sleep: async (ms) => { nowMs += ms; },
        retryPauseMs: 5,
      }),
      (error) => error instanceof SessionEnded && error.code === "MISSING",
    );
  } finally {
    await rm(root, { force: true, recursive: true });
  }
});

test("dual evidence download fetches immediately when called exactly at the deadline", async () => {
  const root = await mkdtemp(join(tmpdir(), "host-evidence-deadline-test-"));
  const calls = [];
  const relayClient = {
    async getEvidence({ role }) {
      calls.push(role);
      return {
        json: Buffer.from(`${role}-json`),
        markdown: Buffer.from(`${role}-markdown`),
        marker: Buffer.from(`${role}-marker`),
      };
    },
  };

  try {
    const result = await downloadEvidencePackages({
      relayClient,
      relayUrl: "http://relay.test",
      sessionId: "s1",
      root,
      deadlineMs: 10_000,
      now: () => 10_000,
      sleep: async () => assert.fail("already-present evidence must not sleep at the deadline"),
      retryPauseMs: 5,
    });

    assert.deepEqual(calls, ["payer", "payee"]);
    assert.equal(await readFile(join(result.payerDirectory, "party-result.json"), "utf8"), "payer-json");
    assert.equal(await readFile(join(result.payeeDirectory, "PARTY-RESULT.md"), "utf8"), "payee-markdown");
  } finally {
    await rm(root, { force: true, recursive: true });
  }
});

test("dual evidence download still reports MISSING at the deadline after one immediate fetch round", async () => {
  const root = await mkdtemp(join(tmpdir(), "host-evidence-deadline-missing-test-"));
  const calls = [];
  try {
    await assert.rejects(
      () => downloadEvidencePackages({
        relayClient: {
          async getEvidence({ role }) {
            calls.push(role);
            if (role === "payee") throw Object.assign(new Error("missing"), { code: "EVIDENCE_NOT_FOUND" });
            return {
              json: Buffer.from(`${role}-json`),
              markdown: Buffer.from(`${role}-markdown`),
              marker: Buffer.from(`${role}-marker`),
            };
          },
        },
        relayUrl: "http://relay.test",
        sessionId: "s1",
        root,
        deadlineMs: 10_000,
        now: () => 10_000,
        sleep: async () => assert.fail("missing evidence must not sleep past the deadline"),
        retryPauseMs: 5,
      }),
      (error) => error instanceof SessionEnded && error.code === "MISSING",
    );
    assert.deepEqual(calls, ["payer", "payee"]);
  } finally {
    await rm(root, { force: true, recursive: true });
  }
});

test("dual evidence download rejects malformed evidence parts instead of waiting until MISSING", async () => {
  const root = await mkdtemp(join(tmpdir(), "host-evidence-malformed-test-"));
  let nowMs = 0;
  try {
    await assert.rejects(
      () => downloadEvidencePackages({
        relayClient: {
          async getEvidence({ role }) {
            return {
              json: Buffer.from(`${role}-json`),
              markdown: `${role}-markdown`,
              marker: Buffer.from(`${role}-marker`),
            };
          },
        },
        relayUrl: "http://relay.test",
        sessionId: "s1",
        root,
        deadlineMs: 10,
        now: () => nowMs,
        sleep: async (ms) => { nowMs += ms; },
        retryPauseMs: 5,
      }),
      (error) => error instanceof SessionEnded && error.code === "MALFORMED",
    );
  } finally {
    await rm(root, { force: true, recursive: true });
  }
});

test("dual evidence download rejects local persistence failures instead of waiting until MISSING", async () => {
  const root = await mkdtemp(join(tmpdir(), "host-evidence-write-failure-test-"));
  let nowMs = 0;
  try {
    await assert.rejects(
      () => downloadEvidencePackages({
        fileSystem: {
          chmod: async () => {},
          mkdir: async () => {},
          writeFile: async () => {
            throw Object.assign(new Error("disk full"), { code: "ENOSPC" });
          },
        },
        relayClient: {
          async getEvidence({ role }) {
            return {
              json: Buffer.from(`${role}-json`),
              markdown: Buffer.from(`${role}-markdown`),
              marker: Buffer.from(`${role}-marker`),
            };
          },
        },
        relayUrl: "http://relay.test",
        sessionId: "s1",
        root,
        deadlineMs: 10,
        now: () => nowMs,
        sleep: async (ms) => { nowMs += ms; },
        retryPauseMs: 5,
      }),
      (error) => error instanceof SessionEnded && error.code === "FAILED",
    );
  } finally {
    await rm(root, { force: true, recursive: true });
  }
});

test("remaining wait minutes come from the heartbeat callback deadline and now", () => {
  assert.equal(remainingWaitMinutes({ deadline: 10 * 60_000, now: 4 * 60_000 }), 6);
});
