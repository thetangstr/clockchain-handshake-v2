import { test } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");

async function readRootFile(path) {
  return readFile(join(ROOT, path), "utf8");
}

test("host container runs on Node 22 as a non-root production install", async () => {
  const dockerfile = await readRootFile("Dockerfile");

  assert.match(dockerfile, /^FROM node:22(?:\b|[-:])/m);
  assert.match(dockerfile, /^WORKDIR \/app$/m);
  assert.match(dockerfile, /^ENV NODE_ENV=production$/m);
  assert.match(
    dockerfile,
    /^ENV CLOCKCHAIN_FUNDING_PASSWORD_FILE=\/app\/keys\/funding\.password$/m,
  );
  assert.match(dockerfile, /^RUN npm ci --omit=dev$/m);
  assert.match(dockerfile, /^USER node$/m);
});

test("host container includes only runtime-required project directories", async () => {
  const dockerfile = await readRootFile("Dockerfile");

  assert.match(dockerfile, /^COPY bin \.\/bin$/m);
  assert.match(dockerfile, /^COPY src \.\/src$/m);
  assert.match(dockerfile, /^COPY prompts \.\/prompts$/m);
});

test("host container prepares writable runtime directories and default keystore path", async () => {
  const dockerfile = await readRootFile("Dockerfile");

  assert.match(dockerfile, /^RUN mkdir -p \/app\/keys \/app\/runs /m);
  assert.match(
    dockerfile,
    /^CMD \["node","bin\/clockchain-host\.mjs","--keystore","\/app\/keys\/funding-wallet\.json"\]$/m,
  );
});

test("docker build context excludes local secrets, run output, git data, and installs", async () => {
  const dockerignore = await readRootFile(".dockerignore");
  const ignored = new Set(
    dockerignore
      .split(/\r?\n/)
      .map((line) => line.trim())
      .filter((line) => line && !line.startsWith("#")),
  );

  const requiredPatterns = [
    ".git",
    ".git/",
    "keys",
    "keys/",
    "runs",
    "runs/",
    "node_modules",
    "node_modules/",
    "state",
    "state/",
    "*.log",
    "**/private/",
    "**/*.key",
    "**/*.pem",
    "**/keystore*.json",
    "**/funding-journal/",
    "**/.env",
    "**/run-state/",
    "config/secrets.json",
    ".context/",
    "*.secret.json",
  ];

  for (const pattern of requiredPatterns) {
    assert.ok(ignored.has(pattern), `.dockerignore must include ${pattern}`);
  }
});
