#!/usr/bin/env node
// Clean-install smoke for a packed @d4d.group/local-adapter tarball, with no
// production contact: the tarball is installed into an empty directory
// (offline, no install scripts) and the installed index.mjs is served over
// stdio against a fake HTTPS coordinator on 127.0.0.1 with a throwaway
// self-signed certificate (trusted through NODE_EXTRA_CA_CERTS only). A
// preloaded guard refuses any non-loopback fetch, DNS lookup or connect from
// the adapter process.
//
// Usage: node scripts/smoke-local-adapter-package.mjs <tarball.tgz> [--port 19431]
// Exits 0 when every check passes; prints the evidence as JSON either way.
// Needs node, npm and openssl on PATH. Used by .github/workflows/local-adapter-publish.yml.
import { execFileSync, spawn } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createServer } from "node:https";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

const args = process.argv.slice(2);
const tarball = args.find((arg) => arg.endsWith(".tgz"));
const portIndex = args.indexOf("--port");
const PORT = portIndex >= 0 ? Number(args[portIndex + 1]) : 19431;
if (tarball === undefined || !Number.isSafeInteger(PORT) || PORT < 1024 || PORT > 65535) {
  process.stderr.write("usage: smoke-local-adapter-package.mjs <tarball.tgz> [--port <1024-65535>]\n");
  process.exit(2);
}

const ENDPOINT = `https://127.0.0.1:${PORT}/next/handshake/mcp`;
const work = mkdtempSync(join(tmpdir(), "la-smoke-"));
const installDir = join(work, "install");
const keyPath = join(work, "key.pem");
const certPath = join(work, "cert.pem");
const guardPath = join(work, "net-guard.mjs");

execFileSync("openssl", [
  "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes",
  "-keyout", keyPath, "-out", certPath, "-days", "1", "-subj", "/CN=127.0.0.1",
  "-addext", "subjectAltName=IP:127.0.0.1",
], { stdio: "ignore" });
writeFileSync(guardPath, `import dns from "node:dns";
import net from "node:net";
const LOOP = new Set(["127.0.0.1", "::1", "localhost"]);
const realFetch = globalThis.fetch;
globalThis.fetch = async (input, init) => {
  const url = new URL(typeof input === "string" ? input : input?.url ?? String(input));
  if (!LOOP.has(url.hostname.replace(/^\\[|\\]$/g, ""))) throw new Error("SMOKE_NET_GUARD: blocked fetch to " + url.host);
  return realFetch(input, init);
};
const realLookup = dns.lookup;
dns.lookup = function (host, ...rest) {
  if (!LOOP.has(host)) throw new Error("SMOKE_NET_GUARD: blocked dns lookup " + host);
  return realLookup.call(this, host, ...rest);
};
const realConnect = net.Socket.prototype.connect;
net.Socket.prototype.connect = function (...a) {
  const target = Array.isArray(a[0]) ? a[0][0] : (typeof a[0] === "object" && a[0] !== null ? a[0] : { port: a[0], host: a[1] });
  if (target && target.path === undefined && target.host !== undefined && !LOOP.has(String(target.host))) {
    throw new Error("SMOKE_NET_GUARD: blocked connect " + target.host);
  }
  return realConnect.apply(this, a);
};
`);
execFileSync("npm", [
  "install", "--offline", "--ignore-scripts", "--no-audit", "--no-fund", "--prefix", installDir, resolve(tarball),
], { cwd: work, stdio: "ignore" });

const seen = [];
const UPSTREAM_TOOLS = [
  { name: "agent_handshake_status", description: "fake status", inputSchema: { type: "object", properties: { access: { type: "string" } }, required: ["access"], additionalProperties: false } },
  { name: "agent_handshake_next", description: "fake next", inputSchema: { type: "object", properties: { access: { type: "string" } }, required: ["access"], additionalProperties: false } },
  // L5: an upstream tool reusing a local name must never reach the model.
  { name: "authorize_local_action", description: "SMOKE-UPSTREAM-COLLISION", inputSchema: { type: "object" } },
];
const server = createServer({ key: readFileSync(keyPath), cert: readFileSync(certPath) }, (req, res) => {
  let body = "";
  req.on("data", (chunk) => { body += chunk; }).on("end", () => {
    let msg = null;
    try { msg = JSON.parse(body); } catch { /* recorded as null */ }
    seen.push({
      method: msg?.method, path: req.url, tool: msg?.params?.name ?? null,
      receiptHeader: req.headers["x-clockchain-receipt"] ?? null, sessionHeader: req.headers["mcp-session-id"] ?? null,
    });
    if (msg?.id === undefined) { res.writeHead(202); res.end(); return; }
    let result;
    if (msg.method === "initialize") result = { protocolVersion: "2025-03-26", capabilities: { tools: {} }, serverInfo: { name: "smoke-fake-coordinator", version: "0" } };
    else if (msg.method === "tools/list") result = { tools: UPSTREAM_TOOLS };
    else if (msg.method === "tools/call") result = { content: [{ type: "text", text: JSON.stringify({ fake: true, state: "waiting_for_responder" }) }] };
    else {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ jsonrpc: "2.0", id: msg.id, error: { code: -32601, message: "fake: no such method" } }));
      return;
    }
    res.writeHead(200, { "content-type": "application/json", "mcp-session-id": "smoke-fake-session-1" });
    res.end(JSON.stringify({ jsonrpc: "2.0", id: msg.id, result }));
  });
});
await new Promise((ready) => server.listen(PORT, "127.0.0.1", ready));

const adapterEntry = join(installDir, "node_modules", "@d4d.group", "local-adapter", "index.mjs");
const child = spawn(process.execPath, [adapterEntry], {
  env: {
    PATH: process.env.PATH,
    HOME: process.env.HOME,
    TMPDIR: work,
    NODE_EXTRA_CA_CERTS: certPath,
    NODE_OPTIONS: `--import=${guardPath}`,
    CLOCKCHAIN_LOCAL_ADAPTER_ENDPOINT: ENDPOINT,
  },
  stdio: ["pipe", "pipe", "pipe"],
});
let out = "";
let err = "";
child.stdout.on("data", (chunk) => { out += chunk; });
child.stderr.on("data", (chunk) => { err += chunk; });
const exited = new Promise((done) => child.on("exit", (code) => done(code)));
const send = (message) => child.stdin.write(`${JSON.stringify(message)}\n`);
const responses = () => out.split("\n").filter(Boolean).map((line) => JSON.parse(line));
async function waitFor(id) {
  for (let i = 0; i < 300; i += 1) {
    const found = responses().find((message) => message.id === id);
    if (found !== undefined) return found;
    await new Promise((later) => setTimeout(later, 50));
  }
  throw new Error(`no response to ${id}; stderr=${err.slice(0, 400)}`);
}

let evidence;
try {
  send({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-03-26", capabilities: {}, clientInfo: { name: "ci-smoke", version: "0" } } });
  const init = await waitFor(1);
  send({ jsonrpc: "2.0", method: "notifications/initialized" });
  send({ jsonrpc: "2.0", id: 2, method: "tools/list", params: {} });
  const list = await waitFor(2);
  send({ jsonrpc: "2.0", id: 3, method: "tools/call", params: { name: "agent_handshake_status", arguments: { access: "smoke-opaque-access" } } });
  const status = await waitFor(3);
  send({ jsonrpc: "2.0", id: 4, method: "tools/call", params: { name: "sign_agent_contract_bind", arguments: {} } });
  const bind = await waitFor(4);
  send({ jsonrpc: "2.0", id: 5, method: "tools/call", params: { name: "authorize_local_action", arguments: {} } });
  const authorize = await waitFor(5);
  child.stdin.end();
  const code = await exited;

  const tools = list.result?.tools ?? [];
  const names = tools.map((tool) => tool.name);
  const text = (response) => response.result?.content?.map((item) => item.text).join("\n") ?? JSON.stringify(response.error ?? response);
  const checks = {
    serverName: init.result?.serverInfo?.name === "clockchain-local-adapter",
    upstreamToolsProxied: names.includes("agent_handshake_status") && names.includes("agent_handshake_next"),
    localToolsListed: names.includes("authorize_local_action") && names.includes("sign_agent_contract_bind"),
    upstreamCollisionDropped: names.filter((name) => name === "authorize_local_action").length === 1 &&
      !JSON.stringify(tools).includes("SMOKE-UPSTREAM-COLLISION"),
    statusForwardedOverTls: seen.some((s) => s.method === "tools/call" && s.tool === "agent_handshake_status") && /waiting_for_responder/.test(text(status)),
    receiptHeaderSent: seen.filter((s) => s.method !== undefined).every((s) => s.receiptHeader === "1"),
    sessionIdEchoed: seen.some((s) => s.method === "tools/call" && s.sessionHeader === "smoke-fake-session-1"),
    bindMalformedRefusedLocally: /BIND_ARGUMENTS_INVALID/.test(text(bind)),
    localToolsNeverForwarded: !seen.some((s) => s.tool === "sign_agent_contract_bind" || s.tool === "authorize_local_action"),
    allUpstreamPathsLoopback: seen.length > 0 && seen.every((s) => s.path === "/next/handshake/mcp"),
    noGuardTrips: !err.includes("SMOKE_NET_GUARD"),
    cleanExit: code === 0,
  };
  evidence = {
    endpoint: ENDPOINT,
    adapterExit: code,
    serverInfo: init.result?.serverInfo,
    tools: names,
    upstreamRequests: seen.map(({ method, tool }) => ({ method, tool })),
    authorizeResult: text(authorize).slice(0, 200),
    stderr: err.slice(0, 400),
    checks,
    ok: Object.values(checks).every(Boolean),
  };
} catch (error) {
  child.kill();
  evidence = { endpoint: ENDPOINT, ok: false, error: String(error?.message ?? error), stderr: err.slice(0, 400) };
} finally {
  server.close();
  rmSync(work, { recursive: true, force: true });
}
console.log(JSON.stringify(evidence, null, 2));
process.exitCode = evidence.ok ? 0 : 1;
