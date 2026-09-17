#!/usr/bin/env node
import { spawn } from "node:child_process";
import { randomBytes, randomUUID } from "node:crypto";
import { readFile } from "node:fs/promises";
import { createServer } from "node:http";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { isCanonicalUsdPaymentAmount } from "../src/core/payment-amount.mjs";

const DEMO_DIR = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = dirname(DEMO_DIR);
const SCRIPT = join(REPO_ROOT, "scripts", "run-local-demo.mjs");
const PAGE = join(DEMO_DIR, "index.html");
const HOST = "127.0.0.1";
const DEFAULT_PORT = Number(process.env.PORT ?? 5002);
const MAX_BODY_BYTES = 4096;
const MAX_EVENTS_PER_RUN = 200;
const MAX_COMPLETED_RUNS = 20;
const KILL_GRACE_MS = 1500;
const MODEL_PATTERN = /^[a-zA-Z0-9._-]{1,64}$/;
const TRANSITION_LINE =
  /^\s*(proposal|acceptance|acknowledgment)\s+block\s+(\d+)\s+ledger\s+(\S+)\s*$/;
const AGENT_LINE = /^Agent .+ is evaluating|^Agent .+ decided|^Agent .+ could not reach|^Agent .+ reply was not/;

function defaultNonce() {
  return randomBytes(32).toString("base64url");
}

function defaultRunId() {
  return randomUUID();
}

function writeJson(res, status, body) {
  res.writeHead(status, {
    "cache-control": "no-store",
    "content-type": "application/json; charset=utf-8",
  });
  res.end(JSON.stringify(body));
}

function writeError(res, status, code, message) {
  writeJson(res, status, { error: { code, message } });
}

function safeDecodeURIComponent(value) {
  try {
    return decodeURIComponent(value);
  } catch {
    return null;
  }
}

function securityHeaders(extra = {}) {
  return {
    "cache-control": "no-store",
    "content-security-policy": "default-src 'self'; connect-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'",
    "cross-origin-resource-policy": "same-origin",
    "referrer-policy": "no-referrer",
    "x-content-type-options": "nosniff",
    ...extra,
  };
}

function isPlainJsonObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

async function readJsonBody(req) {
  let size = 0;
  let body = "";
  for await (const chunk of req) {
    size += chunk.length;
    if (size > MAX_BODY_BYTES) {
      const error = new Error("request body is too large");
      error.status = 413;
      error.code = "BODY_TOO_LARGE";
      throw error;
    }
    body += chunk.toString("utf8");
  }
  try {
    return JSON.parse(body);
  } catch {
    const error = new Error("request body must be valid JSON");
    error.status = 400;
    error.code = "BAD_JSON";
    throw error;
  }
}

function validateMutationRequest(req, res, origin) {
  if (req.headers.host !== origin.slice("http://".length)) {
    writeError(res, 403, "BAD_HOST", "Request host is not this loopback demo server.");
    return false;
  }
  if (req.headers.origin !== origin) {
    writeError(res, 403, "BAD_ORIGIN", "Request origin is not this loopback demo page.");
    return false;
  }
  if (req.headers["x-handshake-demo-nonce"] !== res.demoNonce) {
    writeError(res, 403, "BAD_NONCE", "Request nonce is invalid.");
    return false;
  }
  return true;
}

function validateRunBody(body) {
  if (!isPlainJsonObject(body)) {
    return { ok: false, status: 400, code: "BAD_BODY", message: "Request body must be a JSON object." };
  }
  const keys = Object.keys(body).sort();
  const mode = body.mode;
  const expectedKeys =
    mode === "live"
      ? ["agent", "amount", "liveConfirmation", "mode", "model"]
      : ["agent", "amount", "mode", "model"];
  if (
    keys.length !== expectedKeys.length ||
    keys.some((key, index) => key !== expectedKeys[index])
  ) {
    return { ok: false, status: 400, code: "BAD_KEYS", message: "Request body contains unsupported fields." };
  }
  if (typeof body.amount !== "string" || !isCanonicalUsdPaymentAmount({ currency: "USD", value: body.amount })) {
    return { ok: false, status: 400, code: "BAD_AMOUNT", message: "Amount must be a canonical USD safe integer string." };
  }
  if (mode !== "stub" && mode !== "live") {
    return { ok: false, status: 400, code: "BAD_MODE", message: "Mode must be stub or live." };
  }
  if (typeof body.agent !== "boolean") {
    return { ok: false, status: 400, code: "BAD_AGENT", message: "Agent flag must be boolean." };
  }
  if (typeof body.model !== "string" || !MODEL_PATTERN.test(body.model)) {
    return { ok: false, status: 400, code: "BAD_MODEL", message: "Model name contains unsupported characters." };
  }
  if (mode === "live" && body.liveConfirmation !== `RUN LIVE USD ${body.amount}`) {
    return { ok: false, status: 400, code: "BAD_LIVE_CONFIRMATION", message: "Live mode confirmation phrase is incorrect." };
  }
  return { ok: true, value: body };
}

function sseWrite(res, event, data) {
  if (!res.writableEnded) {
    res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);
  }
}

function makeTerminator({ killProcess = process.kill, setTimeoutFn = setTimeout, clearTimeoutFn = clearTimeout } = {}) {
  return function terminate(run, signal = "SIGTERM") {
    if (!run.child || run.killTimer) return;
    const pid = run.child.pid;
    const sendSignal = (nextSignal) => {
      if (pid && process.platform !== "win32") {
        killProcess(-pid, nextSignal);
      } else if (typeof run.child.kill === "function") {
        run.child.kill(nextSignal);
      }
    };
    try {
      sendSignal(signal);
    } catch {
      if (typeof run.child.kill === "function") run.child.kill(signal);
    }
    run.killTimer = setTimeoutFn(() => {
      try {
        sendSignal("SIGKILL");
      } catch {
        if (typeof run.child.kill === "function") run.child.kill("SIGKILL");
      }
    }, KILL_GRACE_MS);
    run.clearKillTimer = () => clearTimeoutFn(run.killTimer);
  };
}

export function createDemoServer({
  spawnFn = spawn,
  pageReader = readFile,
  nonce = defaultNonce(),
  id = defaultRunId,
  killProcess = process.kill,
  setTimeoutFn = setTimeout,
  clearTimeoutFn = clearTimeout,
  env = process.env,
} = {}) {
  const runs = new Map();
  const completedOrder = [];
  let activeRunId = null;
  let server;
  const terminate = makeTerminator({ killProcess, setTimeoutFn, clearTimeoutFn });

  const endSubscribers = (run) => {
    for (const subscriber of run.subscribers) {
      if (!subscriber.writableEnded) subscriber.end();
    }
    run.subscribers.clear();
  };

  const prune = () => {
    while (completedOrder.length > MAX_COMPLETED_RUNS) {
      const oldId = completedOrder.shift();
      if (oldId !== activeRunId) runs.delete(oldId);
    }
  };

  const emit = (run, event, data) => {
    const item = { event, data };
    run.events.push(item);
    if (run.events.length > MAX_EVENTS_PER_RUN) run.events.shift();
    for (const subscriber of run.subscribers) sseWrite(subscriber, event, data);
  };

  const finishRun = (run, event, data, { clearKillTimer = true } = {}) => {
    if (run.terminal) return;
    run.terminal = true;
    if (clearKillTimer && run.clearKillTimer) run.clearKillTimer();
    emit(run, event, data);
    endSubscribers(run);
    if (activeRunId === run.id) activeRunId = null;
    completedOrder.push(run.id);
    prune();
  };

  const shutdownActiveRun = () => {
    if (activeRunId === null) return;
    const run = runs.get(activeRunId);
    if (!run || run.terminal) return;
    terminate(run, "SIGTERM");
    finishRun(run, "cancelled", { runId: run.id }, { clearKillTimer: false });
  };

  const classify = (run, line, fromStderr) => {
    if (fromStderr) {
      try {
        const parsed = JSON.parse(line);
        emit(run, typeof parsed.stage === "string" ? "stage" : "status", parsed);
      } catch {
        emit(run, "log", { line });
      }
      return;
    }
    const transition = TRANSITION_LINE.exec(line);
    if (transition) {
      emit(run, "transition", { kind: transition[1], block: transition[2], ledger: transition[3] });
      return;
    }
    if (line.startsWith("Verifier outcome:")) {
      emit(run, "verdict", { outcome: line.split(":")[1].trim() });
      return;
    }
    if (line.startsWith("No money moved:")) {
      emit(run, "nomove", { value: line.split(":")[1].trim() });
      return;
    }
    if (AGENT_LINE.test(line)) {
      emit(run, "agent", { line });
      return;
    }
    if (line.trim().length > 0) emit(run, "log", { line });
  };

  const drain = (run, chunk, fromStderr, key) => {
    const text = run[key] + chunk.toString("utf8");
    const lines = text.split("\n");
    run[key] = lines.pop() ?? "";
    for (const line of lines) classify(run, line, fromStderr);
  };

  const startRun = (body) => {
    const runId = id();
    const args = [SCRIPT, "--amount", body.amount, "--currency", "USD"];
    if (body.mode === "stub") args.push("--stub");
    if (body.agent) args.push("--agent-decider", "--decider-model", body.model);
    let child;
    try {
      child = spawnFn(process.execPath, args, {
        cwd: REPO_ROOT,
        detached: process.platform !== "win32",
        env: {
          ...env,
          CLOCKCHAIN_FUNDING_PASSWORD_FILE: env.CLOCKCHAIN_FUNDING_PASSWORD_FILE ?? join(REPO_ROOT, "keys/funding.password"),
        },
        shell: false,
        stdio: ["ignore", "pipe", "pipe"],
      });
    } catch {
      return null;
    }
    const run = {
      child,
      events: [],
      id: runId,
      outBuffer: "",
      errBuffer: "",
      subscribers: new Set(),
      terminal: false,
    };
    runs.set(runId, run);
    activeRunId = runId;
    emit(run, "started", { agent: body.agent, args: args.slice(1), live: body.mode === "live", runId });
    child.stdout?.on?.("data", (chunk) => drain(run, chunk, false, "outBuffer"));
    child.stderr?.on?.("data", (chunk) => drain(run, chunk, true, "errBuffer"));
    child.on?.("close", (code, signal) => {
      if (run.clearKillTimer) run.clearKillTimer();
      if (run.outBuffer.trim().length > 0) classify(run, run.outBuffer, false);
      if (run.errBuffer.trim().length > 0) classify(run, run.errBuffer, true);
      finishRun(run, "exit", { code, signal: signal ?? null });
    });
    child.on?.("error", () => {
      finishRun(run, "exit", { code: 1, signal: null });
    });
    return run;
  };

  server = createServer(async (req, res) => {
    const address = server.address();
    const port = typeof address === "object" && address ? address.port : DEFAULT_PORT;
    const origin = `http://${HOST}:${port}`;
    res.demoNonce = nonce;
    const url = new URL(req.url ?? "/", origin);

    if (url.pathname === "/") {
      if (req.method !== "GET" && req.method !== "HEAD") {
        writeError(res, 405, "METHOD_NOT_ALLOWED", "Method is not allowed.");
        return;
      }
      try {
        const page = String(await pageReader(PAGE));
        const withNonce = page.replace("</head>", `<meta name="handshake-demo-nonce" content="${nonce}">\n</head>`);
        res.writeHead(200, securityHeaders({ "content-type": "text/html; charset=utf-8" }));
        res.end(req.method === "HEAD" ? "" : withNonce);
      } catch {
        writeError(res, 500, "PAGE_MISSING", "Demo page is unavailable.");
      }
      return;
    }

    if (url.pathname === "/runs") {
      if (req.method !== "POST") {
        writeError(res, 405, "METHOD_NOT_ALLOWED", "Method is not allowed.");
        return;
      }
      if (!validateMutationRequest(req, res, origin)) return;
      const contentType = String(req.headers["content-type"] ?? "").split(";")[0].trim();
      if (contentType !== "application/json") {
        writeError(res, 415, "BAD_CONTENT_TYPE", "Request body must be application/json.");
        return;
      }
      if (activeRunId !== null) {
        writeError(res, 409, "RUN_ACTIVE", "A demo run is already active.");
        return;
      }
      let body;
      try {
        body = await readJsonBody(req);
      } catch (error) {
        writeError(res, error.status ?? 400, error.code ?? "BAD_BODY", error.message);
        return;
      }
      const validated = validateRunBody(body);
      if (!validated.ok) {
        writeError(res, validated.status, validated.code, validated.message);
        return;
      }
      const run = startRun(validated.value);
      if (!run) {
        writeError(res, 500, "RUN_START_FAILED", "Demo run could not be started.");
        return;
      }
      writeJson(res, 201, { runId: run.id, events: `/runs/${encodeURIComponent(run.id)}/events` });
      return;
    }

    const runMatch = /^\/runs\/([^/]+)(?:\/events)?$/.exec(url.pathname);
    if (runMatch) {
      const runId = safeDecodeURIComponent(runMatch[1]);
      if (runId === null) {
        writeError(res, 400, "BAD_RUN_ID", "Run id is malformed.");
        return;
      }
      const run = runs.get(runId);
      const isEventsPath = url.pathname.endsWith("/events");
      if (isEventsPath) {
        if (req.method !== "GET") {
          writeError(res, 405, "METHOD_NOT_ALLOWED", "Method is not allowed.");
          return;
        }
        if (!run) {
          writeError(res, 404, "RUN_NOT_FOUND", "Run was not found.");
          return;
        }
        res.writeHead(200, {
          "cache-control": "no-cache, no-store",
          "connection": "keep-alive",
          "content-type": "text/event-stream",
          "x-accel-buffering": "no",
        });
        for (const item of run.events) sseWrite(res, item.event, item.data);
        if (run.terminal) {
          res.end();
          return;
        }
        run.subscribers.add(res);
        req.on("close", () => run.subscribers.delete(res));
        return;
      }
      if (req.method !== "DELETE") {
        writeError(res, 405, "METHOD_NOT_ALLOWED", "Method is not allowed.");
        return;
      }
      if (!validateMutationRequest(req, res, origin)) return;
      if (!run || run.terminal) {
        res.writeHead(204, securityHeaders());
        res.end();
        return;
      }
      terminate(run, "SIGTERM");
      finishRun(run, "cancelled", { runId }, { clearKillTimer: false });
      res.writeHead(202, securityHeaders({ "content-type": "application/json; charset=utf-8" }));
      res.end(JSON.stringify({ ok: true }));
      return;
    }

    writeError(res, 404, "NOT_FOUND", "Route was not found.");
  });

  server.demo = { runs, get activeRunId() { return activeRunId; } };
  const originalClose = server.close.bind(server);
  server.close = (...args) => {
    shutdownActiveRun();
    return originalClose(...args);
  };
  return server;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const server = createDemoServer();
  let shuttingDown = false;
  const shutdown = () => {
    if (shuttingDown) return;
    shuttingDown = true;
    server.close();
  };
  process.once("SIGINT", shutdown);
  process.once("SIGTERM", shutdown);
  server.listen(DEFAULT_PORT, HOST, () => {
    process.stdout.write(
      `Clockchain browser demo: http://${HOST}:${DEFAULT_PORT}\n` +
        "Stub mode is the default. Live mode requires an explicit in-page confirmation phrase.\n",
    );
  });
}
