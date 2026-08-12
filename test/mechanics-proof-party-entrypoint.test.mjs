import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { readFile } from "node:fs/promises";
import { promisify } from "node:util";
import test from "node:test";

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
    CLOCKCHAIN_A2A_PEER_ENDPOINT: "https://responder.task.local:8443/a2a",
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
  assert.equal(output.agentLoopImplemented, false);
  assert.equal(output.failClosedUntilLiveDriver, true);
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
      CLOCKCHAIN_A2A_PEER_ENDPOINT: "https://initiator.task.local:8443/a2a",
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

test("mechanics proof party entrypoint rejects controller signer material and unsafe modes", async () => {
  for (const candidate of [
    env({ CLOCKCHAIN_SIGNER_PRIVATE_KEY: "0x1234" }),
    env({ CLOCKCHAIN_SIGNER_SEED: "seed" }),
    env({ CLOCKCHAIN_MCP_URL: "https://mcp.clockchain.network/mcp" }),
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
