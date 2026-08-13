#!/usr/bin/env node

import { spawn } from "node:child_process";
import http from "node:http";
import { fileURLToPath } from "node:url";

import { createFacilitatorDemoControlHandler } from "../src/testing/facilitator-demo-control.mjs";

const DEFAULT_PORT = 43181;
const launcherPath = fileURLToPath(new URL("../scripts/start-live-tmux-demo.zsh", import.meta.url));
const configuredPort = Number.parseInt(process.env.CLOCKCHAIN_FACILITATOR_CONTROL_PORT ?? "", 10);
const port = Number.isSafeInteger(configuredPort) && configuredPort > 0 && configuredPort <= 65535
  ? configuredPort
  : DEFAULT_PORT;

function launchDemo() {
  return new Promise((resolve, reject) => {
    const child = spawn(launcherPath, [], {
      cwd: fileURLToPath(new URL("..", import.meta.url)),
      env: process.env,
      shell: false,
      stdio: "ignore",
    });
    child.once("error", reject);
    child.once("exit", (code, signal) => {
      if (code === 0 && signal === null) resolve();
      else reject(new Error("The demo launcher did not complete successfully."));
    });
  });
}

const handler = createFacilitatorDemoControlHandler({
  allowedOrigins: [
    "https://clockchain-research.vercel.app",
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    "http://localhost:3101",
    "http://127.0.0.1:3101",
  ],
  launchDemo,
});
const server = http.createServer(handler);

server.listen(port, "127.0.0.1", () => {
  process.stdout.write(`Clockchain facilitator control ready at http://127.0.0.1:${port}\n`);
});

function shutdown() {
  server.close(() => process.exit(0));
}

process.once("SIGINT", shutdown);
process.once("SIGTERM", shutdown);
