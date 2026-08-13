import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const NAMES = ["codex-initiator", "codex-responder", "claude-initiator", "claude-responder"];
const TOOLS = [
  "agent_handshake_status",
  "agent_handshake_join",
  "agent_handshake_next",
  "agent_handshake_submit",
  "agent_handshake_get_certificate",
];
const FORBIDDEN = ["amount", "currency", "invoice", "payer", "payee", "payment", "requestor", "settlement"];

const readPrompt = (name) => readFile(join(ROOT, "prompts", `${name}.md`), "utf8");

for (const name of NAMES) {
  test(`${name} is a concise, exact fresh-stakeholder prompt`, async () => {
    const text = await readPrompt(name);
    assert.ok(text.trim().split(/\s+/).length <= 230, `${name} exceeds 230 words`);
    assert.match(text, /https:\/\/mcp\.clockchain\.network\/mcp/);
    assert.match(text, /wallet-bridge\.mjs/);
    assert.match(text, /ERC-8004/);
    assert.match(text, /human approval/i);
    assert.match(text, /agent-certificate-proof\.mjs/);
    assert.match(text, /operatorPublicKey/);
    assert.match(text, /repositorySha/);
    assert.match(text, /private key/i);
    for (const tool of TOOLS) assert.match(text, new RegExp(`\\b${tool}\\b`));
    for (const word of FORBIDDEN) assert.doesNotMatch(text.toLowerCase(), new RegExp(`\\b${word}\\b`));
    assert.doesNotMatch(text, /\.json handoff|handoff file/i);
    assert.doesNotMatch(text, /signing companion/i);
    assert.match(text, /one to three plain-language sentences/i);
    assert.match(text, /what you verified.*what completed.*what happens next/i);
    assert.match(text, /do not narrate routine polling/i);
    assert.match(text, /raw JSON.*private material.*full hashes/i);
    assert.match(text, /final stakeholder summary/i);
    assert.match(text, /role.*ERC-8004 identity.*agreement status.*certificate verification.*no external business action/i);
    assert.match(text, /Never announce success before.*locally verified/i);
  });
}

test("Initiators create the one-time invitation and Responders consume it", async () => {
  for (const client of ["codex", "claude"]) {
    const initiator = await readPrompt(`${client}-initiator`);
    const responder = await readPrompt(`${client}-responder`);
    assert.match(initiator, /agent_handshake_invite/);
    assert.match(initiator, /NS-1847/);
    assert.match(initiator, /Two stakeholder agents may communicate about shipment NS-1847/);
    assert.match(initiator, /45/);
    assert.match(responder, /<INVITATION_URL>/);
    assert.doesNotMatch(responder, /agent_handshake_invite/);
    assert.match(responder, /Responder/);
    assert.match(initiator, /Initiator/);
  }
});

test("runbook records exact official client configuration and live registration steps", async () => {
  const text = await readFile(join(ROOT, "docs", "agent-handshake-demo.md"), "utf8");
  assert.match(text, /codex mcp add clockchain --url https:\/\/mcp\.clockchain\.network\/mcp --bearer-token-env-var CLOCKCHAIN_MCP_TOKEN/);
  assert.match(text, /bearer_token_env_var/);
  assert.match(text, /claude mcp add-json clockchain/);
  assert.match(text, /Authorization.*Bearer \$\{CLOCKCHAIN_MCP_TOKEN\}/);
  assert.match(text, /https:\/\/developers\.openai\.com\/codex\/mcp/);
  assert.match(text, /https:\/\/code\.claude\.com\/docs\/en\/mcp/);
  assert.match(text, /node bin\/wallet-bridge\.mjs init/);
  assert.match(text, /node bin\/wallet-bridge\.mjs register/);
  assert.match(text, /agent-certificate-proof\.mjs/);
  assert.match(text, /fresh ERC-8004 identity/i);
  assert.match(text, /two separate computers/i);
});
