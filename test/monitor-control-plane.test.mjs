import assert from "node:assert/strict";
import { createServer } from "node:http";
import test from "node:test";

import { McpRateLimitedError } from "../src/core/clockchain.mjs";
import { createControlPlaneRoutes } from "../src/monitor/control-plane/routes.mjs";
import {
  REASON_CODES,
  REASON_MESSAGES,
  STATUS_CODES,
  STATUS_MESSAGES,
  reasonMessage,
  renderVerdict,
  statusMessage,
} from "../src/monitor/control-plane/messages.mjs";

const ANCHORS = Object.freeze([
  Object.freeze({
    anchoredHash: "hash-proposal",
    blockHeight: "100",
    blockTime: "2026-08-03T00:00:00Z",
    kind: "proposal",
    ledgerId: "ledger-proposal",
    receipt: { status: "anchored" },
  }),
  Object.freeze({
    anchoredHash: "hash-acceptance",
    blockHeight: "101",
    blockTime: "2026-08-03T00:01:00Z",
    kind: "acceptance",
    ledgerId: "ledger-acceptance",
    receipt: { status: "anchored" },
  }),
  Object.freeze({
    anchoredHash: "hash-acknowledgment",
    blockHeight: "102",
    blockTime: "2026-08-03T00:02:00Z",
    kind: "acknowledgment",
    ledgerId: "ledger-acknowledgment",
    receipt: { status: "anchored" },
  }),
]);

function baseSnapshot(overrides = {}) {
  return {
    anchors: ANCHORS,
    funding: {
      addresses: [
        { address: "0xaaa", balanceWei: "0", nonce: "0" },
      ],
      journal: { state: "FUNDED" },
    },
    paymentMoved: false,
    preflight: { checkedAt: "2026-08-03T00:00:00Z", ok: true },
    roles: {
      payer: { lastSeenMs: Date.now(), status: "ACTIVE" },
    },
    sessionId: "session-1",
    stageHistory: [{ at: 1, status: "SESSION_STARTED" }],
    subjectRun: "stakeholder",
    verdict: null,
    ...overrides,
  };
}

function matchingReverifyResult(anchor) {
  return {
    onChain: {
      anchoredHash: anchor.anchoredHash,
      blockHeight: anchor.blockHeight,
      keyless: true,
      ledgerId: anchor.ledgerId,
      verifiedAgainst: "on-chain block",
    },
  };
}

function mismatchedReverifyResult(anchor) {
  return {
    onChain: {
      anchoredHash: "some-other-hash",
      blockHeight: anchor.blockHeight,
      keyless: true,
      ledgerId: anchor.ledgerId,
      verifiedAgainst: "on-chain block",
    },
  };
}

// A minimal harness: a real node:http server mounting the handler under test,
// so this exercises exactly the (req, res) contract the operator process
// will mount, not a hand-rolled stand-in for it.
async function withServer(handler, run) {
  const server = createServer(async (req, res) => {
    const handled = await handler(req, res);
    if (!handled) {
      res.writeHead(404, { "content-type": "application/json" });
      res.end(JSON.stringify({ error: "NOT_FOUND" }));
    }
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address();
  const base = `http://127.0.0.1:${port}`;
  try {
    await run(base);
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
}

function buildDependencies(overrides = {}) {
  const calls = {
    onAbort: 0,
    onStart: 0,
    verifyCrossParty: [],
  };
  let snapshot = baseSnapshot();
  const dependencies = {
    clockchain: {
      verifyCrossParty: async (args) => {
        calls.verifyCrossParty.push(args);
        return matchingReverifyResult(
          ANCHORS.find((anchor) => anchor.ledgerId === args.ledgerId),
        );
      },
    },
    getSnapshot: () => snapshot,
    now: () => "2026-08-03T00:05:00.000Z",
    onAbort: async () => {
      calls.onAbort += 1;
    },
    onStart: async () => {
      calls.onStart += 1;
    },
    ...overrides,
  };
  return {
    calls,
    dependencies,
    setSnapshot: (next) => {
      snapshot = next;
    },
  };
}

test("GET /control/snapshot returns the injected snapshot verbatim", async () => {
  const { dependencies } = buildDependencies();
  const handler = createControlPlaneRoutes(dependencies);

  await withServer(handler, async (base) => {
    const response = await fetch(`${base}/control/snapshot`);
    assert.equal(response.status, 200);
    const body = await response.json();
    assert.deepEqual(body, dependencies.getSnapshot());
  });
});

test("POST /control/reverify calls the injected clockchain client and returns its fresh result", async () => {
  const { calls, dependencies } = buildDependencies();
  const handler = createControlPlaneRoutes(dependencies);

  await withServer(handler, async (base) => {
    const response = await fetch(`${base}/control/reverify`, {
      body: JSON.stringify({ anchorKind: "acceptance" }),
      headers: { "content-type": "application/json" },
      method: "POST",
    });
    assert.equal(response.status, 200);
    const body = await response.json();

    assert.equal(calls.verifyCrossParty.length, 1);
    assert.deepEqual(calls.verifyCrossParty[0], {
      blockHeight: "101",
      hash: "hash-acceptance",
      ledgerId: "ledger-acceptance",
    });
    assert.equal(body.anchorKind, "acceptance");
    assert.equal(body.match, true);
    assert.equal(body.verifiedAt, "2026-08-03T00:05:00.000Z");
    assert.deepEqual(
      body.onChain,
      matchingReverifyResult(ANCHORS[1]).onChain,
    );
  });
});

test("POST /control/reverify surfaces a mismatch as a plain business reason, never a raw error code", async () => {
  const { dependencies } = buildDependencies({
    clockchain: {
      verifyCrossParty: async (args) => mismatchedReverifyResult(
        ANCHORS.find((anchor) => anchor.ledgerId === args.ledgerId),
      ),
    },
  });
  const handler = createControlPlaneRoutes(dependencies);

  await withServer(handler, async (base) => {
    const response = await fetch(`${base}/control/reverify`, {
      body: JSON.stringify({ anchorKind: "proposal" }),
      headers: { "content-type": "application/json" },
      method: "POST",
    });
    assert.equal(response.status, 200);
    const body = await response.json();
    assert.equal(body.match, false);
    assert.equal(body.reason, reasonMessage("BINDING_MISMATCH"));
    assert.equal(body.reason.includes("MCP_"), false);
  });
});

test("POST /control/reverify maps a rate-limit error to RATE_BLOCKED wording", async () => {
  const { dependencies } = buildDependencies({
    clockchain: {
      verifyCrossParty: async () => {
        throw new McpRateLimitedError("throttled");
      },
    },
  });
  const handler = createControlPlaneRoutes(dependencies);

  await withServer(handler, async (base) => {
    const response = await fetch(`${base}/control/reverify`, {
      body: JSON.stringify({ anchorKind: "proposal" }),
      headers: { "content-type": "application/json" },
      method: "POST",
    });
    const body = await response.json();
    assert.equal(body.match, false);
    assert.equal(body.reason, reasonMessage("RATE_BLOCKED"));
  });
});

test("POST /control/reverify rejects an unknown anchor kind without calling the client", async () => {
  const { calls, dependencies } = buildDependencies();
  const handler = createControlPlaneRoutes(dependencies);

  await withServer(handler, async (base) => {
    const response = await fetch(`${base}/control/reverify`, {
      body: JSON.stringify({ anchorKind: "settlement" }),
      headers: { "content-type": "application/json" },
      method: "POST",
    });
    assert.equal(response.status, 400);
    assert.equal(calls.verifyCrossParty.length, 0);
  });
});

test("start and abort are the only mutating routes", async () => {
  const { calls, dependencies } = buildDependencies();
  const handler = createControlPlaneRoutes(dependencies);

  await withServer(handler, async (base) => {
    // Reading the snapshot and re-verifying a receipt must never start or
    // abort a run.
    await fetch(`${base}/control/snapshot`);
    await fetch(`${base}/control/reverify`, {
      body: JSON.stringify({ anchorKind: "proposal" }),
      headers: { "content-type": "application/json" },
      method: "POST",
    });
    assert.equal(calls.onStart, 0);
    assert.equal(calls.onAbort, 0);

    // The wrong HTTP method on a mutating path must not invoke it either.
    const wrongMethod = await fetch(`${base}/control/start`, { method: "GET" });
    assert.equal(wrongMethod.status, 405);
    assert.equal(calls.onStart, 0);

    const startResponse = await fetch(`${base}/control/start`, { method: "POST" });
    assert.equal(startResponse.status, 200);
    assert.equal(calls.onStart, 1);
    assert.equal(calls.onAbort, 0);

    const abortResponse = await fetch(`${base}/control/abort`, { method: "POST" });
    assert.equal(abortResponse.status, 200);
    assert.equal(calls.onStart, 1);
    assert.equal(calls.onAbort, 1);
  });
});

test("unrecognised paths are left unhandled for a static file server underneath", async () => {
  const { dependencies } = buildDependencies();
  const handler = createControlPlaneRoutes(dependencies);

  await withServer(handler, async (base) => {
    const response = await fetch(`${base}/index.html`);
    assert.equal(response.status, 404);
  });
});

test("the loopback guard refuses a request whose remote address is not local", async () => {
  const { dependencies } = buildDependencies();
  const handler = createControlPlaneRoutes(dependencies);

  const fakeReq = {
    method: "GET",
    socket: { remoteAddress: "203.0.113.5" },
    url: "/control/snapshot",
  };
  let statusCode;
  let body = "";
  const fakeRes = {
    end: (chunk) => {
      body = chunk?.toString("utf8") ?? "";
    },
    writeHead: (code) => {
      statusCode = code;
    },
  };

  const handled = await handler(fakeReq, fakeRes);
  assert.equal(handled, true);
  assert.equal(statusCode, 403);
  assert.equal(JSON.parse(body).error, "LOOPBACK_ONLY");
});

test("the message map covers every status and every frozen reason code exactly once", () => {
  assert.deepEqual(
    Object.keys(STATUS_MESSAGES).sort(),
    [...STATUS_CODES].sort(),
  );
  assert.deepEqual(
    Object.keys(REASON_MESSAGES).sort(),
    [...REASON_CODES].sort(),
  );
  for (const code of STATUS_CODES) {
    assert.equal(typeof statusMessage(code), "string");
    assert.ok(statusMessage(code).length > 0);
  }
  for (const code of REASON_CODES) {
    assert.equal(typeof reasonMessage(code), "string");
    assert.ok(reasonMessage(code).length > 0);
  }
  // The frozen public set has exactly 16 members (14 original + 2 rehearsal-
  // gate additions, docs/deviations.md D7).
  assert.equal(REASON_CODES.length, 16);
  assert.equal(STATUS_CODES.length, 12);
});

test("renderVerdict never renders the outcome word before a signed AUTHORIZED publication arrives", () => {
  for (const notYetAuthorized of [
    null,
    undefined,
    { outcome: "EXPIRED", paymentMoved: false },
    { outcome: "AUTHORIZED", paymentMoved: true }, // wrong paymentMoved: refused
    { outcome: "authorized", paymentMoved: false }, // wrong case: refused
    "AUTHORIZED", // not an object at all: refused
    { paymentMoved: false }, // no outcome at all
  ]) {
    const rendered = renderVerdict(notYetAuthorized);
    assert.notEqual(rendered.headline, "AUTHORIZED");
    assert.equal(JSON.stringify(rendered).includes("AUTHORIZED"), false);
  }

  const signed = renderVerdict({ outcome: "AUTHORIZED", paymentMoved: false });
  assert.equal(signed.headline, "AUTHORIZED");
  assert.equal(signed.outcome, "AUTHORIZED");
  assert.equal(signed.state, "authorized");
});

test("GET /control/snapshot forwards a null verdict unchanged -- the control plane never manufactures one", async () => {
  const { dependencies } = buildDependencies();
  const handler = createControlPlaneRoutes(dependencies);

  await withServer(handler, async (base) => {
    const response = await fetch(`${base}/control/snapshot`);
    const body = await response.json();
    assert.equal(body.verdict, null);
  });
});

test("createControlPlaneRoutes requires its dependencies", () => {
  assert.throws(() => createControlPlaneRoutes({}), TypeError);
  assert.throws(
    () => createControlPlaneRoutes({ getSnapshot: () => ({}) }),
    TypeError,
  );
});
