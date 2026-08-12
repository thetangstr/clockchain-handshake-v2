import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { readFile } from "node:fs/promises";
import { PassThrough, Readable } from "node:stream";
import { promisify } from "node:util";
import test from "node:test";

import { runMain } from "../bin/mechanics-proof-party.mjs";

const execFileAsync = promisify(execFile);
const SESSION = "11111111-2222-4333-8444-555555555555";

function env(overrides = {}) {
  return {
    PATH: process.env.PATH,
    CLOCKCHAIN_SESSION_ID: SESSION,
    CLOCKCHAIN_ROLE: "initiator",
    CLOCKCHAIN_CLIENT: "codex",
    CLOCKCHAIN_MCP_URL: "https://mcp.clockchain.network/handshake/mcp",
    CLOCKCHAIN_A2A_PORT: "8443",
    CLOCKCHAIN_A2A_PEER_ENDPOINT: "https://10.0.12.34:8443",
    CLOCKCHAIN_WORKSPACE: "/workspace/initiator",
    CLOCKCHAIN_HOME: "/workspace/initiator/home",
    CLOCKCHAIN_STATE_DIR: "/workspace/initiator/state",
    CLOCKCHAIN_CODEX_AUTH_SECRET_REF: "arn:aws:secretsmanager:us-west-2:123456789012:secret:codex-bootstrap",
    ...overrides,
  };
}

test("mechanics proof party entrypoint emits fail-closed public capability preflight only", async () => {
  const { stdout } = await execFileAsync(process.execPath, ["bin/mechanics-proof-party.mjs", "--capability-preflight"], {
    cwd: process.cwd(),
    env: env(),
  });
  const output = JSON.parse(stdout);
  assert.equal(output.schema, "clockchain.mechanics-proof-party-capability/v1");
  assert.equal(output.sessionId, SESSION);
  assert.equal(output.role, "initiator");
  assert.equal(output.client, "codex");
  assert.equal(output.mcpUrl, "https://mcp.clockchain.network/handshake/mcp");
  assert.equal(output.signerGeneratedInsideRuntime, true);
  assert.equal(output.a2aCardKeyGeneratedInsideRuntime, true);
  assert.equal(output.controllerProvidedSignerMaterialAccepted, false);
  assert.equal(output.agentLoopImplemented, true);
  assert.equal(output.failClosedUntilLiveDriver, false);
  assert.equal(output.a2aPeerEndpointScheme, "https-private");
  assert.equal(output.directA2ARequired, true);
  assert.equal("directHttpA2ARequired" in output, false);
  assert.match(output.partySignerAddress, /^0x[0-9a-f]{40}$/);
  assert.match(output.a2aCardAddress, /^0x[0-9a-f]{40}$/);
  assert.notEqual(output.partySignerAddress, output.a2aCardAddress);
  assert.doesNotMatch(stdout, /privateKey|cc_secret|arn:aws|\/workspace|\/Users|transcript|reasoning/i);
});

test("mechanics proof party entrypoint selects Claude Bedrock identity without Anthropic secret", async () => {
  const { stdout } = await execFileAsync(process.execPath, ["bin/mechanics-proof-party.mjs", "--capability-preflight"], {
    cwd: process.cwd(),
    env: env({
      CLOCKCHAIN_ROLE: "responder",
      CLOCKCHAIN_CLIENT: "claude",
      CLOCKCHAIN_A2A_PEER_ENDPOINT: "https://initiator.task.local:8443",
      CLOCKCHAIN_CLAUDE_PROVIDER: "bedrock",
      CLOCKCHAIN_BEDROCK_MODEL_ID: "us.anthropic.claude-sonnet-4-6",
      ANTHROPIC_API_KEY: undefined,
      CLOCKCHAIN_CODEX_AUTH_SECRET_REF: undefined,
    }),
  });
  const output = JSON.parse(stdout);
  assert.equal(output.role, "responder");
  assert.equal(output.client, "claude");
  assert.equal(output.provider, "bedrock");
  assert.equal(output.bedrockModelId, "us.anthropic.claude-sonnet-4-6");
  assert.equal(output.providerCredentialValueAccepted, false);
  assert.doesNotMatch(stdout, /ANTHROPIC_API_KEY|cc_secret|privateKey/i);
});

test("mechanics proof party entrypoint accepts one private Codex subscription auth channel only", async () => {
  const { stdout } = await execFileAsync(process.execPath, ["bin/mechanics-proof-party.mjs", "--capability-preflight"], {
    cwd: process.cwd(),
    env: env({
      CLOCKCHAIN_CODEX_AUTH_SECRET_REF: undefined,
      CLOCKCHAIN_CODEX_AUTH_JSON_BASE64: Buffer.from(JSON.stringify({ tokens: { access_token: "codex-access-secret", id_token: "codex-id-secret", refresh_token: "codex-refresh-secret" } }), "utf8").toString("base64"),
      CLOCKCHAIN_CODEX_MODEL: "gpt-5.6-terra",
    }),
  });
  const output = JSON.parse(stdout);
  assert.equal(output.provider, "codex-subscription-auth");
  assert.equal(output.providerCredentialValueAccepted, false);
  assert.doesNotMatch(stdout, /codex-access-secret|codex-id-secret|codex-refresh-secret|CLOCKCHAIN_CODEX_AUTH_JSON_BASE64/i);
  for (const candidate of [
    env({ CLOCKCHAIN_CODEX_AUTH_JSON_BASE64: "abcd", CODEX_API_KEY: "codex-api-secret" }),
    env({ CLOCKCHAIN_CODEX_AUTH_SECRET_REF: undefined, CLOCKCHAIN_CODEX_AUTH_JSON_BASE64: "abcd", OPENAI_API_KEY: "openai-api-secret" }),
    env({ CLOCKCHAIN_CODEX_AUTH_SECRET_REF: undefined, CODEX_API_KEY: "codex-api-secret", OPENAI_API_KEY: "openai-api-secret" }),
    env({ CLOCKCHAIN_CODEX_AUTH_SECRET_REF: undefined, CLOCKCHAIN_CODEX_AUTH_JSON_BASE64: undefined }),
  ]) {
    await assert.rejects(
      () => execFileAsync(process.execPath, ["bin/mechanics-proof-party.mjs", "--capability-preflight"], { cwd: process.cwd(), env: candidate }),
      /Command failed/,
    );
  }
});

test("mechanics proof party entrypoint rejects cross-role provider auth", async () => {
  for (const candidate of [
    env({
      CLOCKCHAIN_CODEX_AUTH_SECRET_REF: undefined,
      CLOCKCHAIN_CODEX_AUTH_JSON_BASE64: "abcd",
      CLAUDE_CODE_USE_BEDROCK: "1",
      ANTHROPIC_MODEL: "us.anthropic.claude-sonnet-4-6",
    }),
    env({
      CLOCKCHAIN_ROLE: "responder",
      CLOCKCHAIN_CLIENT: "claude",
      CLOCKCHAIN_A2A_PEER_ENDPOINT: "https://initiator.task.local:8443",
      CLOCKCHAIN_CLAUDE_PROVIDER: "bedrock",
      CLOCKCHAIN_BEDROCK_MODEL_ID: "us.anthropic.claude-sonnet-4-6",
      CLOCKCHAIN_CODEX_AUTH_JSON_BASE64: "abcd",
      CLOCKCHAIN_CODEX_MODEL: "gpt-5.6-terra",
      CLOCKCHAIN_CODEX_AUTH_SECRET_REF: undefined,
    }),
  ]) {
    await assert.rejects(
      () => execFileAsync(process.execPath, ["bin/mechanics-proof-party.mjs", "--capability-preflight"], { cwd: process.cwd(), env: candidate }),
      /Command failed/,
    );
  }
});

test("mechanics proof party entrypoint rejects controller signer material and unsafe modes", async () => {
  for (const candidate of [
    env({ CLOCKCHAIN_SIGNER_PRIVATE_KEY: "0x1234" }),
    env({ CLOCKCHAIN_SIGNER_SEED: "seed" }),
    env({ CLOCKCHAIN_MCP_URL: "https://mcp.clockchain.network/mcp" }),
    env({ CLOCKCHAIN_A2A_PEER_ENDPOINT: "http://10.0.12.34:8443" }),
    env({ CLOCKCHAIN_A2A_PEER_ENDPOINT: "https://10.0.12.34:8443/a2a" }),
    env({ CLOCKCHAIN_A2A_PEER_ENDPOINT: "https://10.999.12.34:8443" }),
    env({ CLOCKCHAIN_A2A_PEER_ENDPOINT: "https://127.0.0.1:8443" }),
    env({ CLOCKCHAIN_A2A_PEER_ENDPOINT: "https://example.com:8443" }),
    env({ CLOCKCHAIN_ROLE: "payer" }),
  ]) {
    await assert.rejects(
      () => execFileAsync(process.execPath, ["bin/mechanics-proof-party.mjs", "--capability-preflight"], { cwd: process.cwd(), env: candidate }),
      /Command failed/,
    );
  }
  await assert.rejects(
    () => execFileAsync(process.execPath, ["bin/mechanics-proof-party.mjs", "--run"], { cwd: process.cwd(), env: env() }),
    /Command failed/,
  );
});

test("mechanics proof party source does not contain provider secrets or local auth reads", async () => {
  const source = await readFile("bin/mechanics-proof-party.mjs", "utf8");
  assert.doesNotMatch(source, /readFile.*(?:auth|credentials|subscription)|ANTHROPIC_API_KEY.*stdout|privateKey.*JSON/i);
});

test("run mode emits bootstrap first, consumes one peer descriptor, then emits terminal evidence", async () => {
  const output = new PassThrough();
  let text = "";
  output.on("data", (chunk) => { text += chunk.toString("utf8"); });
  const peer = { schema: "clockchain.mechanics-proof-party-bootstrap/v1", peer: true };
  const calls = [];
  const code = await runMain({
    argv: ["node", "bin/mechanics-proof-party.mjs", "--run"],
    createBootstrapExchange: ({ role, runId, stdin, stdout }) => {
      assert.equal(role, "responder");
      assert.equal(runId, SESSION);
      assert.ok(stdin);
      assert.equal(stdout, output);
      return {
        async publishOwnDescriptor(descriptor) {
          calls.push("exchange.publish");
          assert.deepEqual(descriptor, { schema: "clockchain.mechanics-proof-party-bootstrap/v1", local: true });
          stdout.write(`${JSON.stringify(descriptor)}\n`);
        },
        async awaitPeerDescriptor() { calls.push("exchange.await"); return peer; },
        async destroy() { calls.push("exchange.destroy"); return { destroyed: true }; },
      };
    },
    createRuntime: async () => ({
      bootstrapDescriptor() { calls.push("bootstrap"); return { schema: "clockchain.mechanics-proof-party-bootstrap/v1", local: true }; },
      async destroy() { calls.push("destroy"); },
      async run({ peerDescriptor }) { calls.push("run"); assert.deepEqual(peerDescriptor, peer); return { schema: "clockchain.mechanics-proof-party-evidence/v1", completed: true }; },
    }),
    env: runEnv(),
    stderr: new PassThrough(),
    stdin: Readable.from([`${JSON.stringify(peer)}\n`]),
    stdout: output,
  });
  assert.equal(code, 0);
  assert.deepEqual(calls, ["bootstrap", "exchange.publish", "exchange.await", "exchange.destroy", "run"]);
  assert.deepEqual(text.trim().split("\n").map(JSON.parse), [
    { schema: "clockchain.mechanics-proof-party-bootstrap/v1", local: true },
    { schema: "clockchain.mechanics-proof-party-evidence/v1", completed: true },
  ]);
});

test("managed run mode selects SQS exchange without publishing queue URLs", async () => {
  const output = new PassThrough();
  let text = "";
  output.on("data", (chunk) => { text += chunk.toString("utf8"); });
  const calls = [];
  const peer = { schema: "clockchain.mechanics-proof-party-bootstrap/v1", peer: true };
  const trustedOptions = {
    harness: "claude",
    listenHost: "0.0.0.0",
    manifestDigest: "a".repeat(64),
    mandate: { statement: "trusted" },
    mcpEndpoint: "https://mcp.clockchain.network/handshake/mcp",
    opensslPath: "/usr/bin/openssl",
    port: 8443,
    publicEndpoint: "https://10.0.0.11:8443",
    role: "responder",
    root: "/workspace/responder",
    runId: SESSION,
    runtimeId: "ecs-runtime-responder",
    taskId: "ecs-task-responder",
    workloadAttestationDigest: "b".repeat(64),
  };
  const code = await runMain({
    argv: ["node", "bin/mechanics-proof-party.mjs", "--run-managed"],
    createManagedBootstrapExchange(options) {
      calls.push(["exchange.create", options]);
      return {
        async publishOwnDescriptor() { calls.push("exchange.publish"); return { published: true }; },
        async awaitPeerDescriptor() { calls.push("exchange.await"); return peer; },
        async destroy() { calls.push("exchange.destroy"); return { destroyed: true }; },
      };
    },
    createRuntime: async (options) => {
      assert.equal(options, trustedOptions);
      return ({
        bootstrapDescriptor() { return { schema: "clockchain.mechanics-proof-party-bootstrap/v1", local: true }; },
        async destroy() { calls.push("runtime.destroy"); },
        async run({ peerDescriptor }) { assert.equal(peerDescriptor, peer); return { schema: "clockchain.mechanics-proof-party-evidence/v1", completed: true }; },
      });
    },
    env: runEnv({
      AWS_REGION: "us-west-2",
      CLOCKCHAIN_BOOTSTRAP_OWN_QUEUE_URL: `https://sqs.us-west-2.amazonaws.com/123456789012/own-${SESSION}`,
      CLOCKCHAIN_BOOTSTRAP_PEER_QUEUE_URL: `https://sqs.us-west-2.amazonaws.com/123456789012/peer-${SESSION}`,
    }),
    stderr: new PassThrough(),
    stdin: Readable.from([]),
    stdout: output,
    async resolveManagedRunOptions({ env }) {
      assert.equal(env.CLOCKCHAIN_RUNTIME_ID, "runtime-responder");
      return trustedOptions;
    },
  });
  assert.equal(code, 0);
  assert.equal(calls[0][0], "exchange.create");
  assert.deepEqual(calls[0][1], {
    ownQueueUrl: `https://sqs.us-west-2.amazonaws.com/123456789012/own-${SESSION}`,
    peerQueueUrl: `https://sqs.us-west-2.amazonaws.com/123456789012/peer-${SESSION}`,
    region: "us-west-2",
    role: "responder",
    runId: SESSION,
  });
  assert.deepEqual(calls.slice(1), ["exchange.publish", "exchange.await", "exchange.destroy"]);
  assert.doesNotMatch(text, /sqs|amazonaws|queue/i);
});

test("managed run mode emits ECS attestation before bootstrap descriptor", async () => {
  const output = new PassThrough();
  let text = "";
  output.on("data", (chunk) => { text += chunk.toString("utf8"); });
  const peer = { schema: "clockchain.mechanics-proof-party-bootstrap/v1", peer: true };
  const trustedOptions = {
    harness: "claude",
    listenHost: "0.0.0.0",
    manifestDigest: "a".repeat(64),
    mandate: { statement: "trusted" },
    mcpEndpoint: "https://mcp.clockchain.network/handshake/mcp",
    opensslPath: "/usr/bin/openssl",
    port: 8443,
    publicEndpoint: "https://10.0.0.11:8443",
    role: "responder",
    root: "/workspace/responder",
    runId: SESSION,
    runtimeId: "ecs-task-responder",
    taskId: "task-responder",
    workloadAttestationDigest: "b".repeat(64),
  };
  const code = await runMain({
    argv: ["node", "bin/mechanics-proof-party.mjs", "--run-managed"],
    createManagedBootstrapExchange() {
      return {
        async publishOwnDescriptor(descriptor) { output.write(`${JSON.stringify(descriptor)}\n`); return { published: true }; },
        async awaitPeerDescriptor() { return peer; },
        async destroy() { return { destroyed: true }; },
      };
    },
    createRuntime: async () => ({
      bootstrapDescriptor() { return { schema: "clockchain.mechanics-proof-party-bootstrap/v1", local: true }; },
      async destroy() {},
      async run() { return { schema: "clockchain.mechanics-proof-party-evidence/v1", completed: true }; },
    }),
    env: runEnv({
      AWS_CONTAINER_CREDENTIALS_RELATIVE_URI: "/v2/credentials/12345678-1234-4234-9234-123456789abc",
      AWS_REGION: "us-west-2",
      CLOCKCHAIN_BOOTSTRAP_OWN_QUEUE_URL: `https://sqs.us-west-2.amazonaws.com/123456789012/own-${SESSION}`,
      CLOCKCHAIN_BOOTSTRAP_PEER_QUEUE_URL: `https://sqs.us-west-2.amazonaws.com/123456789012/peer-${SESSION}`,
    }),
    stderr: new PassThrough(),
    stdin: Readable.from([]),
    stdout: output,
    async resolveManagedRunOptions() {
      return {
        attestation: {
          schema: "clockchain.mechanics-proof-ecs-attestation/v1",
          workloadAttestationDigest: trustedOptions.workloadAttestationDigest,
          accountId: "123456789012",
        },
        runOptions: trustedOptions,
      };
    },
  });
  assert.equal(code, 0);
  const lines = text.trim().split("\n").map(JSON.parse);
  assert.equal(lines[0].schema, "clockchain.mechanics-proof-ecs-attestation/v1");
  assert.equal(lines[1].schema, "clockchain.mechanics-proof-party-bootstrap/v1");
  assert.equal(lines[2].schema, "clockchain.mechanics-proof-party-evidence/v1");
  assert.doesNotMatch(text, /sqs|amazonaws|credentials|169\.254/i);
});

test("managed run mode reports only an allowlisted post-attestation failure stage", async () => {
  const stderr = new PassThrough();
  let errorText = "";
  stderr.on("data", (chunk) => { errorText += chunk.toString("utf8"); });
  let runtimeDestroyed = false;
  const code = await runMain({
    argv: ["node", "bin/mechanics-proof-party.mjs", "--run-managed"],
    createManagedBootstrapExchange() {
      return {
        async publishOwnDescriptor() { throw new Error("secret-canary queue-url credentials"); },
        async awaitPeerDescriptor() { throw new Error("must not await"); },
        async destroy() { return { destroyed: true }; },
      };
    },
    createRuntime: async () => ({
      bootstrapDescriptor() { return { schema: "clockchain.mechanics-proof-party-bootstrap/v1" }; },
      async destroy() { runtimeDestroyed = true; },
      async run() { throw new Error("must not run"); },
    }),
    env: runEnv({
      AWS_REGION: "us-west-2",
      CLOCKCHAIN_BOOTSTRAP_OWN_QUEUE_URL: `https://sqs.us-west-2.amazonaws.com/123456789012/own-${SESSION}`,
      CLOCKCHAIN_BOOTSTRAP_PEER_QUEUE_URL: `https://sqs.us-west-2.amazonaws.com/123456789012/peer-${SESSION}`,
    }),
    stderr,
    stdin: Readable.from([]),
    stdout: new PassThrough(),
    async resolveManagedRunOptions() {
      return {
        attestation: { schema: "clockchain.mechanics-proof-ecs-attestation/v1" },
        runOptions: {
          harness: "claude",
          listenHost: "0.0.0.0",
          manifestDigest: "a".repeat(64),
          mandate: { statement: "trusted" },
          mcpEndpoint: "https://mcp.clockchain.network/handshake/mcp",
          opensslPath: "/usr/bin/openssl",
          port: 8443,
          publicEndpoint: "https://10.0.0.11:8443",
          role: "responder",
          root: "/workspace/responder",
          runId: SESSION,
          runtimeId: "ecs-task-responder",
          taskId: "task-responder",
          workloadAttestationDigest: "b".repeat(64),
        },
      };
    },
  });
  assert.equal(code, 1);
  assert.equal(runtimeDestroyed, true);
  assert.equal(errorText, "Mechanics proof party failed safely. stage=bootstrap-publish\n");
  assert.doesNotMatch(errorText, /secret|queue|credentials|amazonaws/i);
});

test("managed run mode holds after terminal evidence until controller stop", async () => {
  const output = new PassThrough();
  let text = "";
  output.on("data", (chunk) => { text += chunk.toString("utf8"); });
  let holdObserved = false;
  const peer = { schema: "clockchain.mechanics-proof-party-bootstrap/v1", peer: true };
  const trustedOptions = {
    harness: "claude",
    listenHost: "0.0.0.0",
    manifestDigest: "a".repeat(64),
    mandate: { statement: "trusted" },
    mcpEndpoint: "https://mcp.clockchain.network/handshake/mcp",
    opensslPath: "/usr/bin/openssl",
    port: 8443,
    publicEndpoint: "https://10.0.0.11:8443",
    role: "responder",
    root: "/workspace/responder",
    runId: SESSION,
    runtimeId: "ecs-task-responder",
    taskId: "task-responder",
    workloadAttestationDigest: "b".repeat(64),
  };
  const code = await runMain({
    argv: ["node", "bin/mechanics-proof-party.mjs", "--run-managed"],
    createManagedBootstrapExchange() {
      return {
        async publishOwnDescriptor() { return { published: true }; },
        async awaitPeerDescriptor() { return peer; },
        async destroy() { return { destroyed: true }; },
      };
    },
    createRuntime: async () => ({
      bootstrapDescriptor() { return { schema: "clockchain.mechanics-proof-party-bootstrap/v1", local: true }; },
      async destroy() {},
      async run() { return { schema: "clockchain.mechanics-proof-party-evidence/v1", completed: true }; },
    }),
    env: runEnv({
      AWS_REGION: "us-west-2",
      CLOCKCHAIN_BOOTSTRAP_OWN_QUEUE_URL: `https://sqs.us-west-2.amazonaws.com/123456789012/own-${SESSION}`,
      CLOCKCHAIN_BOOTSTRAP_PEER_QUEUE_URL: `https://sqs.us-west-2.amazonaws.com/123456789012/peer-${SESSION}`,
    }),
    stderr: new PassThrough(),
    stdin: Readable.from([]),
    stdout: output,
    async resolveManagedRunOptions() { return trustedOptions; },
    async holdManagedRun() {
      holdObserved = true;
      assert.equal(JSON.parse(text.trim().split("\n").at(-1)).schema, "clockchain.mechanics-proof-party-evidence/v1");
    },
  });
  assert.equal(code, 0);
  assert.equal(holdObserved, true);
});

test("managed run mode fails closed until ECS metadata supplies runtime identity", async () => {
  let runtimeCreated = false;
  const stderr = new PassThrough();
  let errorText = "";
  stderr.on("data", (chunk) => { errorText += chunk.toString("utf8"); });
  const code = await runMain({
    argv: ["node", "bin/mechanics-proof-party.mjs", "--run-managed"],
    createRuntime: async () => { runtimeCreated = true; },
    env: runEnv({
      AWS_REGION: "us-west-2",
      CLOCKCHAIN_A2A_PUBLIC_ENDPOINT: "https://10.99.99.99:8443",
      CLOCKCHAIN_BOOTSTRAP_OWN_QUEUE_URL: `https://sqs.us-west-2.amazonaws.com/123456789012/own-${SESSION}`,
      CLOCKCHAIN_BOOTSTRAP_PEER_QUEUE_URL: `https://sqs.us-west-2.amazonaws.com/123456789012/peer-${SESSION}`,
      CLOCKCHAIN_RUNTIME_ID: "controller-invented-runtime",
      CLOCKCHAIN_TASK_ID: "controller-invented-task",
      CLOCKCHAIN_WORKLOAD_ATTESTATION_DIGEST: "f".repeat(64),
    }),
    stderr,
    stdin: Readable.from([]),
    stdout: new PassThrough(),
  });
  assert.equal(code, 1);
  assert.equal(runtimeCreated, false);
  assert.equal(errorText, "Mechanics proof party failed safely.\n");
  assert.doesNotMatch(errorText, /controller|runtime|task|10\.99|attestation/i);
});

test("managed run mode rejects controller-supplied AWS credential overrides", async () => {
  for (const override of [
    { AWS_ACCESS_KEY_ID: "static-access" },
    { AWS_SECRET_ACCESS_KEY: "static-secret" },
    { AWS_SESSION_TOKEN: "static-session" },
    { AWS_WEB_IDENTITY_TOKEN_FILE: "/tmp/token" },
    { AWS_ROLE_ARN: "arn:aws:iam::123456789012:role/override" },
    { AWS_PROFILE: "controller-profile" },
    { AWS_SHARED_CREDENTIALS_FILE: "/tmp/credentials" },
    { AWS_CONTAINER_CREDENTIALS_FULL_URI: "http://controller.invalid/credentials" },
    { AWS_CONFIG_FILE: "/tmp/config" },
    { AWS_CONTAINER_AUTHORIZATION_TOKEN: "controller-token" },
    { AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE: "/tmp/controller-token" },
    { AWS_ENDPOINT_URL: "https://controller.invalid" },
    { AWS_ENDPOINT_URL_SQS: "https://controller.invalid/sqs" },
  ]) {
    let created = false;
    let runtimeCreated = false;
    let resolved = false;
    const stderr = new PassThrough();
    let errorText = "";
    stderr.on("data", (chunk) => { errorText += chunk.toString("utf8"); });
    const code = await runMain({
      argv: ["node", "bin/mechanics-proof-party.mjs", "--run-managed"],
      createManagedBootstrapExchange() { created = true; },
      createRuntime: async () => { runtimeCreated = true; throw new Error("must not create runtime"); },
      env: runEnv({
        AWS_REGION: "us-west-2",
        CLOCKCHAIN_BOOTSTRAP_OWN_QUEUE_URL: `https://sqs.us-west-2.amazonaws.com/123456789012/own-${SESSION}`,
        CLOCKCHAIN_BOOTSTRAP_PEER_QUEUE_URL: `https://sqs.us-west-2.amazonaws.com/123456789012/peer-${SESSION}`,
        ...override,
      }),
      stderr,
      stdin: Readable.from([]),
      stdout: new PassThrough(),
      resolveManagedRunOptions: async () => { resolved = true; throw new Error("must not resolve"); },
    });
    assert.equal(code, 1);
    assert.equal(created, false);
    assert.equal(runtimeCreated, false);
    assert.equal(resolved, false);
    assert.equal(errorText, "Mechanics proof party failed safely.\n");
    assert.doesNotMatch(errorText, /static|token|credentials|override|arn:aws|controller/i);
  }
});

test("local run mode remains independent of managed SQS configuration", async () => {
  const calls = [];
  const code = await runMain({
    argv: ["node", "bin/mechanics-proof-party.mjs", "--run"],
    createBootstrapExchange() {
      calls.push("local.create");
      return {
        async publishOwnDescriptor() { calls.push("local.publish"); return { published: true }; },
        async awaitPeerDescriptor() { calls.push("local.await"); return { peer: true }; },
        async destroy() { calls.push("local.destroy"); return { destroyed: true }; },
      };
    },
    createManagedBootstrapExchange() { calls.push("managed.create"); throw new Error("wrong exchange"); },
    createRuntime: async () => ({
      bootstrapDescriptor() { return { own: true }; },
      async run() { calls.push("runtime.run"); return { completed: true }; },
      async destroy() { calls.push("runtime.destroy"); },
    }),
    env: runEnv({ AWS_ACCESS_KEY_ID: "ignored-by-local-mode" }),
    stderr: new PassThrough(),
    stdin: Readable.from([]),
    stdout: new PassThrough(),
  });
  assert.equal(code, 0);
  assert.deepEqual(calls, ["local.create", "local.publish", "local.await", "local.destroy", "runtime.run"]);
});

test("run mode rejects a second peer descriptor and destroys the unstarted runtime", async () => {
  const calls = [];
  const peer = JSON.stringify({ schema: "clockchain.mechanics-proof-party-bootstrap/v1" });
  const code = await runMain({
    argv: ["node", "bin/mechanics-proof-party.mjs", "--run"],
    createRuntime: async () => ({
      bootstrapDescriptor() { return { schema: "clockchain.mechanics-proof-party-bootstrap/v1" }; },
      async destroy() { calls.push("destroy"); },
      async run() { calls.push("run"); },
    }),
    env: runEnv(),
    stderr: new PassThrough(),
    stdin: Readable.from([`${peer}\n${peer}\n`]),
    stdout: new PassThrough(),
  });
  assert.equal(code, 1);
  assert.deepEqual(calls, ["destroy"]);
});

function runEnv(overrides = {}) {
  return {
    PATH: process.env.PATH,
    CLOCKCHAIN_A2A_LISTEN_HOST: "0.0.0.0",
    CLOCKCHAIN_A2A_PORT: "8443",
    CLOCKCHAIN_A2A_PUBLIC_ENDPOINT: "https://responder.task.local:8443",
    CLOCKCHAIN_CLIENT: "claude",
    CLOCKCHAIN_HELPER_MANIFEST_DIGEST: "a".repeat(64),
    CLOCKCHAIN_MANDATE_JSON: JSON.stringify({
      reference: "northstar-harbor-demo",
      statement: "Confirm terms.",
      validForSeconds: "10",
      identityPolicy: { erc8004: "required_fresh", chainId: "eip155:11155111", registryAddress: "0x8004a818bfb912233c491871b3d84c89a494bd9e" },
    }),
    CLOCKCHAIN_MCP_URL: "https://mcp.clockchain.network/handshake/mcp",
    CLOCKCHAIN_OPENSSL_PATH: "/usr/bin/openssl",
    CLOCKCHAIN_PARTY_ROOT: "/workspace/responder",
    CLOCKCHAIN_ROLE: "responder",
    CLOCKCHAIN_RUN_ID: SESSION,
    CLOCKCHAIN_RUNTIME_ID: "runtime-responder",
    CLOCKCHAIN_TASK_ID: "task-responder",
    CLOCKCHAIN_WORKLOAD_ATTESTATION_DIGEST: "b".repeat(64),
    ...overrides,
  };
}
