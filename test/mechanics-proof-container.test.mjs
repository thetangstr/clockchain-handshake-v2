import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

async function text(path) {
  return readFile(path, "utf8");
}

test("mechanics proof Fargate app Dockerfile is pinned, nonroot, and entrypoint-scoped", async () => {
  const dockerfile = await text("infra/mechanics-proof/Dockerfile");
  assert.match(dockerfile, /^FROM docker\.io\/library\/node:24\.11\.1-bookworm-slim@sha256:44b49d6e2d23f6754fb084ef9d34ff14590343ad1ee168f8acf8f7bc9fccde2f$/m);
  assert.match(dockerfile, /^ARG SOURCE_COMMIT$/m);
  assert.match(dockerfile, /^LABEL org\.opencontainers\.image\.revision=\$SOURCE_COMMIT$/m);
  assert.match(dockerfile, /^RUN case "\$SOURCE_COMMIT" in \(\*\[!0-9a-f\]\*|""\) exit 1;; esac && test "\$\{#SOURCE_COMMIT\}" = "40"$/m);
  assert.doesNotMatch(dockerfile, /^RUN test -n "\$SOURCE_COMMIT" && test "\$\{#SOURCE_COMMIT\}" = "40"$/m);
  assert.match(dockerfile, /^ENV NODE_ENV=production$/m);
  assert.match(dockerfile, /^RUN npm ci --omit=dev && rm -rf node_modules\/@anthropic-ai\/claude-agent-sdk-linux-x64-musl$/m);
  assert.match(dockerfile, /^RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates openssl && rm -rf \/var\/lib\/apt\/lists\/\*$/m);
  assert.match(dockerfile, /^RUN mkdir -p \/workspace && chown node:node \/workspace$/m);
  assert.match(dockerfile, /^RUN node scripts\/install-pinned-agent-handshake-release\.mjs \/app\/release-assets$/m);
  assert.doesNotMatch(dockerfile, /chown -R .*\/app/);
  assert.match(dockerfile, /^USER node$/m);
  assert.match(dockerfile, /^EXPOSE 8443$/m);
  assert.match(dockerfile, /^ENTRYPOINT \["node","bin\/mechanics-proof-party\.mjs"\]$/m);
  assert.doesNotMatch(dockerfile, /COPY .*keys|COPY .*\.env|ARG .*SECRET|ENV .*PRIVATE|USER root/);
  assert.ok(dockerfile.indexOf("RUN npm ci") < dockerfile.indexOf("ARG SOURCE_COMMIT"));
});

test("mechanics proof image contains only the pinned AWS task dependencies", async () => {
  const packageJson = JSON.parse(await text("package.json"));
  const awsDependencies = Object.fromEntries(Object.entries(packageJson.dependencies).filter(([name]) => name.startsWith("@aws-sdk/")));
  assert.deepEqual(awsDependencies, {
    "@aws-sdk/client-sqs": "3.1097.0",
    "@aws-sdk/client-sts": "3.1097.0",
  });
});

test("mechanics proof build context excludes credentials, local auth, and private outputs", async () => {
  const dockerignore = await text(".dockerignore");
  const ignored = new Set(dockerignore.split(/\r?\n/).map((line) => line.trim()).filter((line) => line && !line.startsWith("#")));
  for (const pattern of [
    ".codex/",
    ".claude/",
    ".config/",
    ".npmrc",
    "**/auth.json",
    "**/credentials.json",
    "**/*.secret",
    "**/mechanics-proof-evidence/",
  ]) {
    assert.ok(ignored.has(pattern), `.dockerignore must include ${pattern}`);
  }
});
