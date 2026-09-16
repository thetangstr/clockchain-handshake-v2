#!/usr/bin/env node
// Browser demo harness: serves demo/index.html and streams a real run of
// scripts/run-local-demo.mjs to the page over Server-Sent Events. The demo
// script itself is unchanged — this process only supervises it, so every stage
// line the page renders is emitted by the same code the CLI demo runs.
//
//   node demo/server.mjs            → http://127.0.0.1:5002
//   PORT=8080 node demo/server.mjs
//
// Loopback only. Run parameters arrive as query params and are validated
// against the same shapes the protocol accepts before becoming child-process
// argv entries (spawn, never a shell). A new run kills any run in progress.
import { spawn } from "node:child_process";
import { readFile } from "node:fs/promises";
import { createServer } from "node:http";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const DEMO_DIR = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = dirname(DEMO_DIR);
const SCRIPT = join(REPO_ROOT, "scripts", "run-local-demo.mjs");
const PAGE = join(DEMO_DIR, "index.html");
const HOST = "127.0.0.1";
const PORT = Number(process.env.PORT ?? 5002);

const AMOUNT_PATTERN = /^[0-9]{1,18}$/;
const CURRENCY_PATTERN = /^[A-Z]{3}$/;
const MODEL_PATTERN = /^[a-zA-Z0-9._-]{1,64}$/;
const TRANSITION_LINE =
  /^\s*(proposal|acceptance|acknowledgment)\s+block\s+(\d+)\s+ledger\s+(\S+)\s*$/;
const AGENT_LINE = /^Agent .+ is evaluating|^Agent .+ decided|^Agent .+ could not reach|^Agent .+ reply was not/;

let current = null;

function send(res, event, data) {
  if (!res.writableEnded) {
    res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);
  }
}

function failRun(res, message) {
  send(res, "run-error", { message });
  res.end();
}

function startRun(url, res) {
  res.writeHead(200, {
    "cache-control": "no-cache",
    "connection": "keep-alive",
    "content-type": "text/event-stream",
  });
  res.on("close", () => {
    if (current?.res === res) {
      current.child.kill("SIGTERM");
      current = null;
    }
  });

  const params = url.searchParams;
  const amount = params.get("amount") ?? "100";
  const currency = params.get("currency") ?? "USD";
  const model = params.get("model") ?? "glm-5.3-flash";
  const live = params.get("mode") === "live";
  const agent = params.get("agent") !== "0";

  if (!AMOUNT_PATTERN.test(amount) || BigInt(amount) === 0n) {
    return failRun(res, "Amount must be a positive integer string.");
  }
  if (!CURRENCY_PATTERN.test(currency)) {
    return failRun(res, "Currency must be a three-letter code (e.g. USD).");
  }
  if (agent && !MODEL_PATTERN.test(model)) {
    return failRun(res, "Model name contains unsupported characters.");
  }

  if (current !== null) {
    current.child.kill("SIGTERM");
    current = null;
  }

  const args = [SCRIPT, "--amount", amount, "--currency", currency];
  if (!live) {
    args.push("--stub");
  }
  if (agent) {
    args.push("--agent-decider", "--decider-model", model);
  }
  const child = spawn(process.execPath, args, {
    cwd: REPO_ROOT,
    env: {
      ...process.env,
      CLOCKCHAIN_FUNDING_PASSWORD_FILE:
        process.env.CLOCKCHAIN_FUNDING_PASSWORD_FILE ??
        join(REPO_ROOT, "keys/funding.password"),
    },
  });
  current = { child, res };
  send(res, "started", { agent, args: args.slice(1), live });

  const classify = (line, fromStderr) => {
    if (fromStderr) {
      try {
        const parsed = JSON.parse(line);
        if (typeof parsed.stage === "string") {
          send(res, "stage", parsed);
        } else {
          send(res, "status", parsed);
        }
      } catch {
        send(res, "log", { line });
      }
      return;
    }
    const transition = TRANSITION_LINE.exec(line);
    if (transition) {
      send(res, "transition", {
        block: transition[2],
        kind: transition[1],
        ledger: transition[3],
      });
      return;
    }
    if (line.startsWith("Verifier outcome:")) {
      send(res, "verdict", { outcome: line.split(":")[1].trim() });
      return;
    }
    if (line.startsWith("No money moved:")) {
      send(res, "nomove", { value: line.split(":")[1].trim() });
      return;
    }
    if (AGENT_LINE.test(line)) {
      send(res, "agent", { line });
      return;
    }
    if (line.trim().length > 0) {
      send(res, "log", { line });
    }
  };

  let outBuffer = "";
  let errBuffer = "";
  const drain = (chunk, fromStderr, buffer, setBuffer) => {
    const text = buffer + chunk;
    const lines = text.split("\n");
    setBuffer(lines.pop() ?? "");
    for (const line of lines) {
      classify(line, fromStderr);
    }
  };
  child.stdout.on("data", (chunk) =>
    drain(chunk.toString("utf8"), false, outBuffer, (rest) => {
      outBuffer = rest;
    }));
  child.stderr.on("data", (chunk) =>
    drain(chunk.toString("utf8"), true, errBuffer, (rest) => {
      errBuffer = rest;
    }));

  child.on("close", (code) => {
    if (current?.child === child) {
      current = null;
    }
    if (outBuffer.trim().length > 0) {
      classify(outBuffer, false);
    }
    if (errBuffer.trim().length > 0) {
      classify(errBuffer, true);
    }
    send(res, "exit", { code });
    res.end();
  });
}

const server = createServer(async (req, res) => {
  const url = new URL(req.url ?? "/", `http://${HOST}`);
  if (url.pathname === "/run") {
    startRun(url, res);
    return;
  }
  if (url.pathname === "/") {
    try {
      const page = await readFile(PAGE);
      res.writeHead(200, { "content-type": "text/html; charset=utf-8" });
      res.end(page);
    } catch {
      res.writeHead(500).end("demo/index.html missing");
    }
    return;
  }
  res.writeHead(404).end("not found");
});

server.listen(PORT, HOST, () => {
  process.stdout.write(
    `Clockchain browser demo → http://${HOST}:${PORT}\n` +
      `Stub mode is the default; add ?mode=live for the real chain.\n`,
  );
});
