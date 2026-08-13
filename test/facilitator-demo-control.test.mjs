import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import http from "node:http";
import test from "node:test";

import { createFacilitatorDemoControlHandler } from "../src/testing/facilitator-demo-control.mjs";

const PRODUCTION_ORIGIN = "https://clockchain-research.vercel.app";

async function withServer(launchDemo, run, getDemoState = async () => "ready") {
  const handler = createFacilitatorDemoControlHandler({
    allowedOrigins: [PRODUCTION_ORIGIN, "http://localhost:3000"],
    getDemoState,
    launchDemo,
  });
  const server = http.createServer(handler);
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  assert.equal(typeof address, "object");
  try {
    await run(`http://127.0.0.1:${address.port}`);
  } finally {
    await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
  }
}

test("reports a ready loopback controller to the production monitor", async () => {
  await withServer(async () => {}, async (base) => {
    const response = await fetch(`${base}/control/status`, {
      headers: { origin: PRODUCTION_ORIGIN },
    });
    assert.equal(response.status, 200);
    assert.equal(response.headers.get("access-control-allow-origin"), PRODUCTION_ORIGIN);
    assert.deepEqual(await response.json(), {
      ok: true,
      ready: true,
      state: "ready",
    });
  });
});

test("reports and preserves an active run across page reloads", async () => {
  let calls = 0;
  await withServer(async () => { calls += 1; }, async (base) => {
    const status = await fetch(`${base}/control/status`, {
      headers: { origin: PRODUCTION_ORIGIN },
    });
    assert.deepEqual(await status.json(), {
      ok: true,
      ready: false,
      state: "active",
    });

    const duplicate = await fetch(`${base}/control/start`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        origin: PRODUCTION_ORIGIN,
        "x-clockchain-facilitator": "start-fresh-demo",
      },
      body: "{}",
    });
    assert.equal(duplicate.status, 409);
    assert.deepEqual(await duplicate.json(), {
      code: "DEMO_ALREADY_ACTIVE",
      ok: false,
      state: "active",
    });
    assert.equal(calls, 0);
  }, async () => "active");
});

test("reports an orphaned server session as blocked and refuses a replacement run", async () => {
  let calls = 0;
  await withServer(async () => { calls += 1; }, async (base) => {
    const status = await fetch(`${base}/control/status`, {
      headers: { origin: PRODUCTION_ORIGIN },
    });
    assert.deepEqual(await status.json(), {
      ok: true,
      ready: false,
      state: "blocked",
    });
    const replacement = await fetch(`${base}/control/start`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        origin: PRODUCTION_ORIGIN,
        "x-clockchain-facilitator": "start-fresh-demo",
      },
      body: "{}",
    });
    assert.equal(replacement.status, 409);
    assert.deepEqual(await replacement.json(), {
      code: "DEMO_SESSION_OPEN",
      ok: false,
      state: "blocked",
    });
    assert.equal(calls, 0);
  }, async () => "blocked");
});

test("preflights only the exact monitor origin and facilitator header", async () => {
  await withServer(async () => {}, async (base) => {
    const response = await fetch(`${base}/control/start`, {
      method: "OPTIONS",
      headers: {
        origin: PRODUCTION_ORIGIN,
        "access-control-request-method": "POST",
        "access-control-request-headers": "content-type,x-clockchain-facilitator",
      },
    });
    assert.equal(response.status, 204);
    assert.equal(response.headers.get("access-control-allow-origin"), PRODUCTION_ORIGIN);
    assert.equal(response.headers.get("access-control-allow-private-network"), "true");
    assert.match(response.headers.get("access-control-allow-headers") ?? "", /x-clockchain-facilitator/);

    const refused = await fetch(`${base}/control/start`, {
      method: "OPTIONS",
      headers: { origin: "https://example.com" },
    });
    assert.equal(refused.status, 403);
  });
});

test("starts one fresh demo only after an explicit trusted-page click", async () => {
  let release;
  let calls = 0;
  const pending = new Promise((resolve) => { release = resolve; });

  await withServer(async () => {
    calls += 1;
    await pending;
  }, async (base) => {
    const start = fetch(`${base}/control/start`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        origin: PRODUCTION_ORIGIN,
        "x-clockchain-facilitator": "start-fresh-demo",
      },
      body: "{}",
    });

    await new Promise((resolve) => setTimeout(resolve, 20));
    const duplicate = await fetch(`${base}/control/start`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        origin: PRODUCTION_ORIGIN,
        "x-clockchain-facilitator": "start-fresh-demo",
      },
      body: "{}",
    });
    assert.equal(duplicate.status, 409);
    assert.deepEqual(await duplicate.json(), {
      code: "DEMO_START_IN_PROGRESS",
      ok: false,
      state: "starting",
    });

    release();
    const response = await start;
    assert.equal(response.status, 202);
    assert.deepEqual(await response.json(), {
      ok: true,
      state: "started",
    });
    assert.equal(calls, 1);
  });
});

test("rejects ambient web requests that lack the trusted origin or click marker", async () => {
  let calls = 0;
  await withServer(async () => { calls += 1; }, async (base) => {
    for (const headers of [
      { "content-type": "application/json", origin: "https://example.com", "x-clockchain-facilitator": "start-fresh-demo" },
      { "content-type": "application/json", origin: PRODUCTION_ORIGIN },
    ]) {
      const response = await fetch(`${base}/control/start`, {
        method: "POST",
        headers,
        body: "{}",
      });
      assert.equal(response.status, 403);
      assert.deepEqual(await response.json(), { code: "FORBIDDEN", ok: false });
    }
    assert.equal(calls, 0);
  });
});

test("fails closed without exposing launcher output", async () => {
  await withServer(async () => {
    throw new Error("secret path and token must not escape");
  }, async (base) => {
    const response = await fetch(`${base}/control/start`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        origin: PRODUCTION_ORIGIN,
        "x-clockchain-facilitator": "start-fresh-demo",
      },
      body: "{}",
    });
    assert.equal(response.status, 500);
    const text = await response.text();
    assert.equal(text, '{"code":"DEMO_START_FAILED","ok":false,"state":"ready"}');
    assert.doesNotMatch(text, /secret|token|path/);
  });
});

test("the executable controller stays loopback-only and launches the existing tmux demo without a shell", async () => {
  const source = await readFile(new URL("../bin/facilitator-demo-control.mjs", import.meta.url), "utf8");
  assert.match(source, /listen\(port, "127\.0\.0\.1"/);
  assert.match(source, /spawn\(launcherPath, \[\]/);
  assert.match(source, /shell:\s*false/);
  assert.match(source, /start-live-tmux-demo\.zsh/);
  assert.match(source, /http:\/\/localhost:3101/);
  assert.match(source, /getDemoState/);
  assert.match(source, /clockchain-controller/);
  assert.doesNotMatch(source, /0\.0\.0\.0|exec\(|execSync\(|shell:\s*true/);
});

test("the facilitator launcher keeps one stable tmux controller session", async () => {
  const source = await readFile(new URL("../scripts/start-facilitator-demo-controller.zsh", import.meta.url), "utf8");
  assert.match(source, /clockchain-facilitator-control/);
  assert.match(source, /facilitator-demo-control\.mjs/);
  assert.match(source, /respawn-pane -k/);
  assert.match(source, /127\.0\.0\.1/);
});

test("the live launcher refuses to kill an already active controller run", async () => {
  const source = await readFile(new URL("../scripts/start-live-tmux-demo.zsh", import.meta.url), "utf8");
  assert.match(source, /A Clockchain live run is already active/);
  assert.match(source, /has-session -t "\$CONTROLLER_SESSION"/);
  assert.doesNotMatch(source, /respawn-pane -k -t "\$CONTROLLER_SESSION/);
});
