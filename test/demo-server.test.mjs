import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import { request as httpRequest } from "node:http";
import { PassThrough } from "node:stream";
import test from "node:test";

import { createDemoServer } from "../demo/server.mjs";

class FakeChild extends EventEmitter {
  constructor(pid) {
    super();
    this.pid = pid;
    this.stdout = new PassThrough();
    this.stderr = new PassThrough();
    this.killSignals = [];
  }

  kill(signal) {
    this.killSignals.push(signal);
    return true;
  }
}

function listen(server) {
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => {
      const { port } = server.address();
      resolve({
        base: `http://127.0.0.1:${port}`,
        origin: `http://127.0.0.1:${port}`,
        port,
      });
    });
  });
}

function close(server) {
  return new Promise((resolve) => server.close(resolve));
}

async function waitFor(predicate, message) {
  const deadline = Date.now() + 1_000;
  while (Date.now() < deadline) {
    if (predicate()) return;
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
  assert.fail(message);
}

function makeHarness() {
  const children = [];
  const kills = [];
  const timers = [];
  let nextId = 0;
  const server = createDemoServer({
    id: () => `run-${++nextId}`,
    nonce: "nonce-test-value-with-enough-entropy",
    spawnFn: (...args) => {
      const child = new FakeChild(9000 + children.length);
      children.push({ child, args });
      return child;
    },
    killProcess: (pid, signal) => {
      kills.push({ pid, signal });
      return true;
    },
    setTimeoutFn: (fn, ms) => {
      timers.push({ fn, ms });
      return { fn, ms };
    },
    clearTimeoutFn: () => {},
  });
  return { server, children, kills, timers };
}

async function req(base, path, { method = "GET", body, headers = {}, timeoutMs = 5_000 } = {}) {
  const url = new URL(path, base);
  return await new Promise((resolve, reject) => {
    const request = httpRequest(
      url,
      {
        method,
        headers: {
          host: url.host,
          ...(body === undefined ? {} : { "content-type": "application/json" }),
          ...headers,
        },
      },
      (res) => {
        let text = "";
        res.setEncoding("utf8");
        res.on("data", (chunk) => {
          text += chunk;
        });
        res.on("end", () => {
          let json = null;
          try {
            json = text ? JSON.parse(text) : null;
          } catch {}
          resolve({ status: res.statusCode, headers: res.headers, text, json });
        });
      },
    );
    request.on("error", reject);
    request.setTimeout(timeoutMs, () => {
      request.destroy(new Error(`request timed out: ${method} ${path}`));
    });
    if (body !== undefined) request.end(typeof body === "string" ? body : JSON.stringify(body));
    else request.end();
  });
}

function mutationHeaders(origin, nonce = "nonce-test-value-with-enough-entropy") {
  return {
    origin,
    "x-handshake-demo-nonce": nonce,
  };
}

function validBody(overrides = {}) {
  return {
    agent: true,
    amount: "100",
    mode: "stub",
    model: "glm-5.3-flash",
    ...overrides,
  };
}

test("GET is read-only and legacy GET /run cannot start work", async () => {
  const { server, children } = makeHarness();
  const { base } = await listen(server);
  try {
    const page = await req(base, "/");
    assert.equal(page.status, 200);
    assert.match(page.text, /handshake-demo-nonce/);
    assert.equal(page.headers["cache-control"], "no-store");
    const legacy = await req(base, "/run?amount=100");
    assert.equal(legacy.status, 404);
    assert.equal(children.length, 0);
  } finally {
    await close(server);
  }
});

test("POST /runs requires loopback host, origin, nonce, JSON, exact keys, model, and canonical USD amount", async () => {
  const { server, children } = makeHarness();
  const { base, origin } = await listen(server);
  try {
    const noOrigin = await req(base, "/runs", { method: "POST", body: validBody() });
    assert.equal(noOrigin.status, 403);
    const foreignOrigin = await req(base, "/runs", {
      method: "POST",
      body: validBody(),
      headers: mutationHeaders("http://evil.test"),
    });
    assert.equal(foreignOrigin.status, 403);
    const badNonce = await req(base, "/runs", {
      method: "POST",
      body: validBody(),
      headers: mutationHeaders(origin, "bad"),
    });
    assert.equal(badNonce.status, 403);
    const badHost = await req(base, "/runs", {
      method: "POST",
      body: validBody(),
      headers: { ...mutationHeaders(origin), host: "localhost:1234" },
    });
    assert.equal(badHost.status, 403);
    const badType = await req(base, "/runs", {
      method: "POST",
      body: JSON.stringify(validBody()),
      headers: { ...mutationHeaders(origin), "content-type": "text/plain" },
    });
    assert.equal(badType.status, 415);

    for (const body of [
      "{",
      "x".repeat(5000),
      validBody({ extra: true }),
      validBody({ model: "bad model" }),
      validBody({ amount: "0" }),
      validBody({ amount: "01" }),
      validBody({ amount: "9007199254740992" }),
      { agent: true, amount: "100", currency: "EUR", mode: "stub", model: "glm-5.3-flash" },
    ]) {
      const response = await req(base, "/runs", {
        method: "POST",
        body,
        headers: mutationHeaders(origin),
      });
      assert.notEqual(response.status, 201, JSON.stringify(body));
    }
    assert.equal(children.length, 0);
  } finally {
    await close(server);
  }
});

test("POST /runs starts one argv-only run, rejects active replacement, and enforces live phrase", async () => {
  const { server, children } = makeHarness();
  const { base, origin } = await listen(server);
  try {
    const badLive = await req(base, "/runs", {
      method: "POST",
      body: validBody({ mode: "live", liveConfirmation: "RUN LIVE USD 99" }),
      headers: mutationHeaders(origin),
    });
    assert.equal(badLive.status, 400);
    const created = await req(base, "/runs", {
      method: "POST",
      body: validBody({ amount: "9007199254740991" }),
      headers: mutationHeaders(origin),
    });
    assert.equal(created.status, 201);
    assert.deepEqual(created.json, { runId: "run-1", events: "/runs/run-1/events" });
    assert.equal(children.length, 1);
    const [execPath, args, options] = children[0].args;
    assert.equal(execPath, process.execPath);
    assert.equal(options.shell, false);
    assert.equal(Array.isArray(args), true);
    assert.ok(args.includes("--amount"));
    assert.ok(args.includes("9007199254740991"));
    assert.ok(args.includes("--currency"));
    assert.ok(args.includes("USD"));
    assert.ok(args.includes("--stub"));
    assert.ok(args.includes("--agent-decider"));
    assert.doesNotMatch(args.join(" "), /bad;rm/);

    const active = await req(base, "/runs", {
      method: "POST",
      body: validBody(),
      headers: mutationHeaders(origin),
    });
    assert.equal(active.status, 409);
    assert.equal(children.length, 1);
  } finally {
    await close(server);
  }
});

test("successful live-mode POST requires exact phrase and omits --stub", async () => {
  const { server, children } = makeHarness();
  const { base, origin } = await listen(server);
  try {
    const created = await req(base, "/runs", {
      method: "POST",
      body: validBody({
        agent: false,
        amount: "42",
        mode: "live",
        liveConfirmation: "RUN LIVE USD 42",
      }),
      headers: mutationHeaders(origin),
    });
    assert.equal(created.status, 201);
    assert.equal(children.length, 1);
    const [, args, options] = children[0].args;
    assert.equal(options.shell, false);
    assert.equal(args.includes("--stub"), false);
    assert.deepEqual(args.slice(1, 5), ["--amount", "42", "--currency", "USD"]);
  } finally {
    await close(server);
  }
});

test("malformed encoded run ids fail closed without hanging", async () => {
  const { server, children } = makeHarness();
  const { base } = await listen(server);
  try {
    const response = await req(base, "/runs/%ZZ/events");
    assert.equal(response.status, 400);
    assert.match(response.text, /BAD_RUN_ID/);
    assert.equal(children.length, 0);
  } finally {
    await close(server);
  }
});

test("synchronous spawn failures return a structured error and leave no active run", async () => {
  const server = createDemoServer({
    nonce: "nonce-test-value-with-enough-entropy",
    spawnFn: () => {
      throw new Error("spawn exploded");
    },
  });
  const { base, origin } = await listen(server);
  try {
    const response = await req(base, "/runs", {
      method: "POST",
      body: validBody(),
      headers: mutationHeaders(origin),
    });
    assert.equal(response.status, 500);
    assert.match(response.text, /RUN_START_FAILED/);
    assert.equal(server.demo.activeRunId, null);
    assert.equal(server.demo.runs.size, 0);
  } finally {
    await close(server);
  }
});

test("SSE replays buffered events and disconnecting does not cancel work", async () => {
  const { server, children, kills } = makeHarness();
  const { base, origin } = await listen(server);
  try {
    const created = await req(base, "/runs", {
      method: "POST",
      body: validBody(),
      headers: mutationHeaders(origin),
    });
    children[0].child.stderr.write('{"stage":"PROPOSED","message":"proposal ready"}\n');
    const first = await new Promise((resolve, reject) => {
      const request = httpRequest(new URL(created.json.events, base), (res) => {
        let text = "";
        res.setEncoding("utf8");
        res.on("data", (chunk) => {
          text += chunk;
          if (text.includes("event: stage")) {
            request.destroy();
            resolve(text);
          }
        });
      });
      request.on("error", (error) => {
        if (error.code !== "ECONNRESET") reject(error);
      });
      request.end();
    });
    assert.match(first, /event: started/);
    assert.match(first, /event: stage/);
    assert.match(first, /proposal ready/);
    assert.equal(children.length, 1);
    assert.equal(kills.length, 0);
  } finally {
    await close(server);
  }
});

test("child close ends SSE subscribers and clears subscriber bookkeeping", async () => {
  const { server, children } = makeHarness();
  const { base, origin } = await listen(server);
  try {
    const created = await req(base, "/runs", {
      method: "POST",
      body: validBody(),
      headers: mutationHeaders(origin),
    });
    const ended = new Promise((resolve, reject) => {
      const request = httpRequest(new URL(created.json.events, base), (res) => {
        let text = "";
        res.setEncoding("utf8");
        res.on("data", (chunk) => {
          text += chunk;
        });
        res.on("end", () => resolve(text));
      });
      request.on("error", reject);
      request.setTimeout(5_000, () => request.destroy(new Error("SSE did not end")));
      request.end();
    });
    const run = server.demo.runs.get(created.json.runId);
    await waitFor(() => run.subscribers.size === 1, "SSE subscriber was not registered");
    assert.equal(run.subscribers.size, 1);
    children[0].child.emit("close", 0, null);
    const text = await ended;
    assert.match(text, /event: exit/);
    assert.equal(run.subscribers.size, 0);
    const replay = await req(base, created.json.events);
    assert.equal(replay.status, 200);
    assert.match(replay.text, /event: exit/);
  } finally {
    await close(server);
  }
});

test("DELETE cancels only the named run, escalates after grace, and is idempotent", async () => {
  const { server, children, kills, timers } = makeHarness();
  const { base, origin } = await listen(server);
  try {
    const created = await req(base, "/runs", {
      method: "POST",
      body: validBody(),
      headers: mutationHeaders(origin),
    });
    const cancelled = await req(base, `/runs/${created.json.runId}`, {
      method: "DELETE",
      headers: mutationHeaders(origin),
    });
    assert.equal(cancelled.status, 202);
    assert.deepEqual(kills[0], { pid: -9000, signal: "SIGTERM" });
    assert.equal(timers[0].ms, 1500);
    timers[0].fn();
    assert.deepEqual(kills[1], { pid: -9000, signal: "SIGKILL" });
    assert.equal(server.demo.activeRunId, null);

    const second = await req(base, `/runs/${created.json.runId}`, {
      method: "DELETE",
      headers: mutationHeaders(origin),
    });
    assert.equal(second.status, 204);
    assert.equal(children[0].child.killSignals.length, 0);
  } finally {
    await close(server);
  }
});

test("server close cancels the active detached child and ends subscribers", async () => {
  const { server, children, kills, timers } = makeHarness();
  const { base, origin } = await listen(server);
  const created = await req(base, "/runs", {
    method: "POST",
    body: validBody(),
    headers: mutationHeaders(origin),
  });
  const ended = new Promise((resolve, reject) => {
    const request = httpRequest(new URL(created.json.events, base), (res) => {
      let text = "";
      res.setEncoding("utf8");
      res.on("data", (chunk) => {
        text += chunk;
      });
      res.on("end", () => resolve(text));
    });
    request.on("error", reject);
    request.setTimeout(5_000, () => request.destroy(new Error("SSE did not end on server close")));
    request.end();
  });
  const run = server.demo.runs.get(created.json.runId);
  await waitFor(() => run.subscribers.size === 1, "SSE subscriber was not registered");
  assert.equal(run.subscribers.size, 1);
  await close(server);
  const text = await ended;
  assert.match(text, /event: cancelled/);
  assert.equal(run.subscribers.size, 0);
  assert.deepEqual(kills[0], { pid: -9000, signal: "SIGTERM" });
  assert.equal(timers[0].ms, 1500);
});

test("completed run pruning is bounded without evicting active run", async () => {
  const { server, children } = makeHarness();
  const { base, origin } = await listen(server);
  try {
    for (let index = 0; index < 25; index += 1) {
      const created = await req(base, "/runs", {
        method: "POST",
        body: validBody({ agent: false }),
        headers: mutationHeaders(origin),
      });
      children.at(-1).child.emit("close", 0, null);
      assert.equal(created.status, 201);
    }
    assert.equal(server.demo.runs.size, 20);
    const active = await req(base, "/runs", {
      method: "POST",
      body: validBody({ amount: "101", agent: false }),
      headers: mutationHeaders(origin),
    });
    assert.equal(active.status, 201);
    assert.equal(server.demo.runs.has(active.json.runId), true);
    assert.equal(server.demo.activeRunId, active.json.runId);
  } finally {
    await close(server);
  }
});
