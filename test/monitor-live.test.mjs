// End-to-end wiring check for G3: does the monitor actually render a real
// run? This starts a real relay on an ephemeral port, PUBLISHES a sequence of
// synthetic snapshots covering every stage (including a failure), and then
// exercises the exact code path a browser would run against the live
// endpoints: fetch GET /v1/sessions/{sid}/snapshot, fetch GET /monitor/{sid}
// and its assets, and feed the fetched snapshot through the same pure view
// builder the stakeholder page uses (src/monitor/stakeholder/messages.mjs).
// There is no headless browser in this repo's dependency budget (viem +
// builtins only), so "renders" is verified at the seam a browser would
// actually hit: real HTTP, real stored snapshot, real view-model output.
import assert from "node:assert/strict";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

import { createRelayServer } from "../src/relay/server.mjs";
import {
  buildSnapshot,
  FAILED_STAGE,
  REASON_CODES,
  STATUSES,
  validateSnapshot,
} from "../src/monitor/snapshot.mjs";
import {
  buildFailureView,
  buildStakeholderView,
  NO_MONEY_MOVED_SENTENCE,
} from "../src/monitor/stakeholder/messages.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const STAKEHOLDER_DIR = join(HERE, "..", "src", "monitor", "stakeholder");
const SNAPSHOT_MODULE_FILE = join(HERE, "..", "src", "monitor", "snapshot.mjs");

const LEDGER_ID_1 = "11111111-1111-4111-8111-111111111111";
const LEDGER_ID_2 = "22222222-2222-4222-8222-222222222222";
const LEDGER_ID_3 = "33333333-3333-4333-8333-333333333333";

async function temporaryDirectory(t) {
  const directory = await mkdtemp(join(tmpdir(), "handshake-monitor-live-"));
  t.after(async () => {
    await rm(directory, { force: true, recursive: true });
  });
  return directory;
}

async function listen(server) {
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  return server.address().port;
}

async function startServer(t) {
  const dir = await temporaryDirectory(t);
  const server = await createRelayServer({ stateDir: dir });
  const port = await listen(server);
  t.after(() => new Promise((resolve) => server.close(resolve)));
  return `http://127.0.0.1:${port}`;
}

async function postJson(url, body) {
  const response = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body ?? {}),
  });
  return { status: response.status, body: await response.json() };
}

async function putJson(url, body) {
  const response = await fetch(url, {
    method: "PUT",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  return { status: response.status, body: await response.json() };
}

async function getJson(url) {
  const response = await fetch(url);
  return { status: response.status, body: await response.json() };
}

function anchor(kind, ledgerId, blockHeight) {
  return {
    blockHeight,
    blockTime: 1_700_000_000_000,
    explorerUrl: `https://mcp.clockchain.network/explorer/${kind}/${ledgerId}`,
    kind,
    ledgerId,
    receipt: { anchoredHash: "a".repeat(64), digest: "a".repeat(64), kind },
    signedBy: { address: "0x" + "b".repeat(40), agentId: "9001" },
    terms: {
      currency: "USD",
      expirySeconds: "600",
      predecessor: kind === "proposal" ? null : "2731906",
      sequence: kind === "proposal" ? "1" : kind === "acceptance" ? "2" : "3",
      sessionDigest: "d".repeat(64),
      value: "100",
    },
  };
}

function heartbeatAt(ms) {
  return {
    payee: { lastSeenMs: ms },
    payer: { lastSeenMs: ms },
    verifier: null,
  };
}

/** Build the same shape bin/operator.mjs's publishSnapshot() sends, for a
 * given stage, folding in a running stageHistory / anchors / verdict. */
function snapshotFor(sessionId, stageHistory, { currentStage, anchors, verdict, reasonCode = null }) {
  const atMs = 1_700_000_000_000 + stageHistory.length * 1_000;
  const nextHistory = [...stageHistory, { atMs, status: currentStage }];
  return {
    snapshot: buildSnapshot({
      anchors: anchors ?? { acceptance: null, acknowledgment: null, proposal: null },
      currentStage,
      funding: { atMs, funded: true },
      heartbeat: heartbeatAt(atMs),
      reasonCode,
      sessionId,
      stageHistory: nextHistory,
      subjectRun: "stakeholder",
      updatedAtMs: atMs,
      verdict: verdict ?? null,
    }),
    stageHistory: nextHistory,
  };
}

test("every stage publishes and renders a plain-English sentence, never a raw code, over a live relay", async (t) => {
  const baseUrl = await startServer(t);
  const created = await postJson(`${baseUrl}/v1/sessions`, {});
  assert.equal(created.status, 201);
  const sessionId = created.body.sessionId;

  let stageHistory = [];
  const anchors = { acceptance: null, acknowledgment: null, proposal: null };

  for (const stage of STATUSES) {
    if (stage === "PROPOSED") {
      anchors.proposal = anchor("proposal", LEDGER_ID_1, "1001");
    }
    if (stage === "ACCEPTED") {
      anchors.acceptance = anchor("acceptance", LEDGER_ID_2, "1002");
    }
    if (stage === "ACKNOWLEDGED") {
      anchors.acknowledgment = anchor("acknowledgment", LEDGER_ID_3, "1003");
    }
    const verdict =
      stage === "VERIFYING" ? { outcome: "AUTHORIZED", paymentMoved: false } : null;
    const built = snapshotFor(sessionId, stageHistory, {
      anchors: { ...anchors },
      currentStage: stage,
      verdict,
    });
    stageHistory = built.stageHistory;

    const put = await putJson(`${baseUrl}/v1/sessions/${sessionId}/snapshot`, built.snapshot);
    assert.equal(put.status, 200, `PUT snapshot for ${stage} failed`);

    const fetched = await getJson(`${baseUrl}/v1/sessions/${sessionId}/snapshot`);
    assert.equal(fetched.status, 200);
    assert.equal(validateSnapshot(fetched.body), true);
    assert.equal(fetched.body.currentStage, stage);
    assert.equal(fetched.body.paymentMoved, false);

    const view = buildStakeholderView(fetched.body, fetched.body.updatedAtMs);
    assert.ok(view.noMoneyMoved.length > 0);
    assert.equal(view.noMoneyMoved, NO_MONEY_MOVED_SENTENCE);
    assert.ok(view.currentStatusSentence.length > 0);
    // Never the raw internal status code as the headline sentence.
    assert.notEqual(view.currentStatusSentence, stage);

    if (stage === "VERIFYING") {
      // This is the one stage where the verdict has actually been
      // published; only here may the rendered verdict sentence say the
      // literal word.
      assert.equal(view.verdict.state, "published");
      assert.ok(view.verdict.sentence.includes("AUTHORIZED"));
    } else {
      assert.equal(view.verdict.state, "pending");
      assert.ok(!view.verdict.sentence.includes("AUTHORIZED"));
    }
  }

  // The technical section is allowed (expected) to carry the raw codes and
  // full JSON -- that is the one place they belong. Confirm the final fetch
  // still round-trips the raw currentStage there, so we know we tested the
  // real thing and not an already-scrubbed shape.
  const last = await getJson(`${baseUrl}/v1/sessions/${sessionId}/snapshot`);
  assert.equal(last.body.currentStage, "VERIFYING");
  assert.equal(JSON.stringify(last.body).includes('"VERIFYING"'), true);
});

test("a failure state renders its named reason as a plain sentence, never the code, and never AUTHORIZED", async (t) => {
  const baseUrl = await startServer(t);
  const created = await postJson(`${baseUrl}/v1/sessions`, {});
  const sessionId = created.body.sessionId;

  let stageHistory = snapshotFor(sessionId, [], { currentStage: "SESSION_STARTED" }).stageHistory;
  await putJson(
    `${baseUrl}/v1/sessions/${sessionId}/snapshot`,
    buildSnapshot({
      anchors: { acceptance: null, acknowledgment: null, proposal: null },
      currentStage: "SESSION_STARTED",
      funding: null,
      heartbeat: heartbeatAt(1_700_000_000_000),
      reasonCode: null,
      sessionId,
      stageHistory,
      subjectRun: "stakeholder",
      updatedAtMs: 1_700_000_000_000,
      verdict: null,
    }),
  );

  for (const reasonCode of REASON_CODES) {
    const atMs = 1_700_000_010_000;
    const nextHistory = [...stageHistory, { atMs, status: FAILED_STAGE }];
    const failed = buildSnapshot({
      anchors: { acceptance: null, acknowledgment: null, proposal: null },
      currentStage: FAILED_STAGE,
      funding: null,
      heartbeat: heartbeatAt(atMs),
      reasonCode,
      sessionId,
      stageHistory: nextHistory,
      subjectRun: "stakeholder",
      updatedAtMs: atMs,
      verdict: null,
    });

    const put = await putJson(`${baseUrl}/v1/sessions/${sessionId}/snapshot`, failed);
    assert.equal(put.status, 200, `PUT failure snapshot for ${reasonCode} failed`);

    const fetched = await getJson(`${baseUrl}/v1/sessions/${sessionId}/snapshot`);
    assert.equal(fetched.status, 200);
    assert.equal(fetched.body.currentStage, FAILED_STAGE);
    assert.equal(fetched.body.reasonCode, reasonCode);
    assert.equal(fetched.body.verdict, null);

    const view = buildStakeholderView(fetched.body, fetched.body.updatedAtMs);
    const failure = buildFailureView(fetched.body);
    assert.ok(failure !== null);
    assert.equal(failure.noMoneyMoved, NO_MONEY_MOVED_SENTENCE);
    assert.ok(failure.sentence.length > 0);
    // Never the raw reason code as the sentence.
    assert.ok(!failure.sentence.includes(reasonCode));
    // Never the verdict word on a failed, unverified run.
    assert.ok(!failure.sentence.includes("AUTHORIZED"));
    assert.equal(view.verdict.state, "pending");
    assert.ok(!view.verdict.sentence.includes("AUTHORIZED"));
    assert.equal(view.noMoneyMoved, NO_MONEY_MOVED_SENTENCE);
  }
});

test("the verdict stays null (rendered as pending) right up until it is explicitly published", async (t) => {
  const baseUrl = await startServer(t);
  const created = await postJson(`${baseUrl}/v1/sessions`, {});
  const sessionId = created.body.sessionId;

  const verifying = buildSnapshot({
    anchors: {
      acceptance: anchor("acceptance", LEDGER_ID_2, "1002"),
      acknowledgment: anchor("acknowledgment", LEDGER_ID_3, "1003"),
      proposal: anchor("proposal", LEDGER_ID_1, "1001"),
    },
    currentStage: "VERIFYING",
    funding: { atMs: 1_700_000_000_000, funded: true },
    heartbeat: heartbeatAt(1_700_000_000_000),
    reasonCode: null,
    sessionId,
    stageHistory: [{ atMs: 1_700_000_000_000, status: "VERIFYING" }],
    subjectRun: "stakeholder",
    updatedAtMs: 1_700_000_000_000,
    verdict: null,
  });
  await putJson(`${baseUrl}/v1/sessions/${sessionId}/snapshot`, verifying);

  const beforeVerdict = await getJson(`${baseUrl}/v1/sessions/${sessionId}/snapshot`);
  const beforeView = buildStakeholderView(beforeVerdict.body, beforeVerdict.body.updatedAtMs);
  assert.equal(beforeView.verdict.state, "pending");
  assert.ok(!beforeView.verdict.sentence.includes("AUTHORIZED"));

  const published = buildSnapshot({
    ...verifying,
    updatedAtMs: 1_700_000_001_000,
    verdict: { outcome: "AUTHORIZED", paymentMoved: false },
  });
  await putJson(`${baseUrl}/v1/sessions/${sessionId}/snapshot`, published);

  const afterVerdict = await getJson(`${baseUrl}/v1/sessions/${sessionId}/snapshot`);
  const afterView = buildStakeholderView(afterVerdict.body, afterVerdict.body.updatedAtMs);
  assert.equal(afterView.verdict.state, "published");
  assert.ok(afterView.verdict.sentence.includes("AUTHORIZED"));
});

test("PUT rejects a snapshot for the wrong session id or an invalid shape", async (t) => {
  const baseUrl = await startServer(t);
  const created = await postJson(`${baseUrl}/v1/sessions`, {});
  const sessionId = created.body.sessionId;

  const valid = buildSnapshot({
    anchors: { acceptance: null, acknowledgment: null, proposal: null },
    currentStage: "SESSION_STARTED",
    funding: null,
    heartbeat: heartbeatAt(1_700_000_000_000),
    reasonCode: null,
    sessionId,
    stageHistory: [{ atMs: 1_700_000_000_000, status: "SESSION_STARTED" }],
    subjectRun: "stakeholder",
    updatedAtMs: 1_700_000_000_000,
    verdict: null,
  });

  const wrongSession = await putJson(
    `${baseUrl}/v1/sessions/${sessionId}/snapshot`,
    { ...valid, sessionId: "not-this-session" },
  );
  assert.equal(wrongSession.status, 400);
  assert.equal(wrongSession.body.error, "MALFORMED_SNAPSHOT");

  const malformed = await putJson(`${baseUrl}/v1/sessions/${sessionId}/snapshot`, {
    sessionId,
    junk: true,
  });
  assert.equal(malformed.status, 400);
  assert.equal(malformed.body.error, "MALFORMED_SNAPSHOT");

  const unknownSession = await putJson(`${baseUrl}/v1/sessions/does-not-exist/snapshot`, valid);
  assert.equal(unknownSession.status, 404);

  const ok = await putJson(`${baseUrl}/v1/sessions/${sessionId}/snapshot`, valid);
  assert.equal(ok.status, 200);
});

test("a published snapshot survives a relay restart (journal replay)", async (t) => {
  const dir = await temporaryDirectory(t);
  const server1 = await createRelayServer({ stateDir: dir });
  const port1 = await listen(server1);
  const baseUrl1 = `http://127.0.0.1:${port1}`;

  const created = await postJson(`${baseUrl1}/v1/sessions`, {});
  const sessionId = created.body.sessionId;
  const snapshot = buildSnapshot({
    anchors: { acceptance: null, acknowledgment: null, proposal: null },
    currentStage: "TERMS_PUBLISHED",
    funding: null,
    heartbeat: heartbeatAt(1_700_000_000_000),
    reasonCode: null,
    sessionId,
    stageHistory: [{ atMs: 1_700_000_000_000, status: "TERMS_PUBLISHED" }],
    subjectRun: "stakeholder",
    updatedAtMs: 1_700_000_000_000,
    verdict: null,
  });
  await putJson(`${baseUrl1}/v1/sessions/${sessionId}/snapshot`, snapshot);
  await new Promise((resolve) => server1.close(resolve));

  const server2 = await createRelayServer({ stateDir: dir });
  const port2 = await listen(server2);
  t.after(() => new Promise((resolve) => server2.close(resolve)));
  const baseUrl2 = `http://127.0.0.1:${port2}`;

  const fetched = await getJson(`${baseUrl2}/v1/sessions/${sessionId}/snapshot`);
  assert.equal(fetched.status, 200);
  assert.deepEqual(fetched.body, snapshot);
});

test("GET /monitor/{sid} serves the stakeholder page shell and its assets byte-for-byte", async (t) => {
  const baseUrl = await startServer(t);
  const created = await postJson(`${baseUrl}/v1/sessions`, {});
  const sessionId = created.body.sessionId;

  const page = await fetch(`${baseUrl}/monitor/${sessionId}`);
  assert.equal(page.status, 200);
  assert.match(page.headers.get("content-type") ?? "", /text\/html/);
  const html = await page.text();
  assert.ok(html.includes(NO_MONEY_MOVED_SENTENCE) || html.includes("No money has moved"));
  assert.ok(html.includes('id="technical-json"'));
  assert.ok(!html.includes("AUTHORIZED"));
  const onDiskHtml = await readFile(join(STAKEHOLDER_DIR, "index.html"), "utf8");
  assert.equal(html, onDiskHtml);

  const assets = [
    ["app.mjs", "app.mjs", "text/javascript"],
    ["messages.mjs", "messages.mjs", "text/javascript"],
    ["styles.css", "styles.css", "text/css"],
  ];
  for (const [urlName, fileName, expectedType] of assets) {
    const response = await fetch(`${baseUrl}/monitor/${urlName}`);
    assert.equal(response.status, 200, `GET /monitor/${urlName}`);
    assert.match(response.headers.get("content-type") ?? "", new RegExp(expectedType));
    const served = await response.text();
    const onDisk = await readFile(join(STAKEHOLDER_DIR, fileName), "utf8");
    assert.equal(served, onDisk);
  }

  const snapshotModule = await fetch(`${baseUrl}/snapshot.mjs`);
  assert.equal(snapshotModule.status, 200);
  const servedModule = await snapshotModule.text();
  const onDiskModule = await readFile(SNAPSHOT_MODULE_FILE, "utf8");
  assert.equal(servedModule, onDiskModule);

  // The relative ES-module imports actually used by the served files must
  // resolve to routes this relay serves, or a browser's module graph would
  // 404 the moment it tried to load them.
  assert.ok(onDiskModule.length > 0);
  const appSource = await readFile(join(STAKEHOLDER_DIR, "app.mjs"), "utf8");
  assert.ok(appSource.includes('from "../snapshot.mjs"'));
  assert.ok(appSource.includes('from "./messages.mjs"'));
});

test("a session with no published monitor snapshot yet falls back to relay bookkeeping, not a fabricated monitor shape", async (t) => {
  const baseUrl = await startServer(t);
  const created = await postJson(`${baseUrl}/v1/sessions`, {});
  const sessionId = created.body.sessionId;

  const fetched = await getJson(`${baseUrl}/v1/sessions/${sessionId}/snapshot`);
  assert.equal(fetched.status, 200);
  assert.equal(fetched.body.paymentMoved, false);
  assert.throws(() => validateSnapshot(fetched.body));

  // The page itself must still be servable even before any snapshot exists
  // -- it is what polls and shows the "cannot reach" / stale state.
  const page = await fetch(`${baseUrl}/monitor/${sessionId}`);
  assert.equal(page.status, 200);
});
