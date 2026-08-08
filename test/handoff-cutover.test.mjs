import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import test from "node:test";

const ROOT = new URL("..", import.meta.url);

async function rootFile(path) {
  return readFile(join(ROOT.pathname, path), "utf8");
}

test("HANDOFF records the P4 live stranger gate and final cutover state", async () => {
  const text = await rootFile("HANDOFF.md");

  assert.match(text, /✅ P4 complete/);
  assert.match(text, /dc9117e8-8f5a-41ed-a425-78d35da5b8eb/);
  assert.match(text, /f599cc2e1bf22888ab8cb583a0a9a272636827be/);
  assert.match(text, /payer agent `9447`.*0xE356F056E19bb669930bdC3Bf0B033F991381242/is);
  assert.match(text, /requestor agent `9448`.*0x7fe49d91EA2703689B7E33b4170192270E1fCd7c/is);
  assert.match(text, /proposal `3101570`\s*\/\s*`809a17fb-34b0-4784-b476-702506b06680`/);
  assert.match(text, /acceptance `3101590`\s*\/\s*`73c361a1-e592-40ee-b197-1005f357692b`/);
  assert.match(text, /acknowledgment `3101592`\s*\/\s*`851d8e83-7b81-4ac6-b5eb-730e17d3f507`/);
  assert.match(text, /session digest\s*`e890b228555c5e6953d077af8008e5ef441cbffda56aa8b902fc1c72964d1ff7`/i);
  assert.match(text, /both certificates verified/i);
  assert.match(text, /`AUTHORIZED`/);
  assert.match(text, /`paymentMoved=false`/);
  assert.match(text, /no operator\/laptop host/i);
  assert.match(text, /production relay deployed/i);
  assert.match(text, /EVIDENCE_RECEIVED.*verdict was `null`/is);
  assert.match(text, /exact label true/i);
  assert.match(text, /\[object Object\].*false/i);
  assert.match(text, /AUTHORIZED\/payment-false true/i);
  assert.match(text, /host reopened next session/i);
  assert.match(text, /production-only\s*`HANDSHAKE_ALLOW_DEGRADED=true`/i);
  assert.match(text, /source default fail-closed/i);
  assert.match(text, /validator count non-blocking/i);
  assert.ok(!text.includes("secret value"));
});

test("historical plan files are explicitly marked as history after P4", async () => {
  for (const path of [
    "docs/two-agent-execution-plan.md",
    "docs/two-agent-build.md",
    "docs/two-agent-plan.md",
  ]) {
    const text = await rootFile(path);
    assert.match(
      text,
      /Historical note \(2026-08-08\):.*operator.*historical/is,
      `${path} must mark old operator language as historical`,
    );
  }
});
