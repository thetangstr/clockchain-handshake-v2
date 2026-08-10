import { isAbsolute } from "node:path";
import { parseArgs } from "node:util";

import { createAgentCliOperations } from "./operations.mjs";
import { AGENT_HANDSHAKE_HELPER_VERSION } from "./signing-request.mjs";

function invalid() { throw new Error("Agent handshake operation failed safely."); }

function payload(value) {
  if (typeof value !== "string" || value.length === 0 || !/^[A-Za-z0-9_-]+$/.test(value)) invalid();
  let decoded;
  try {
    const bytes = Buffer.from(value, "base64url");
    if (bytes.toString("base64url") !== value || bytes.length > 512 * 1024) invalid();
    decoded = JSON.parse(bytes.toString("utf8"));
  } catch { invalid(); }
  return decoded;
}

export async function runAgentHandshakeCli(argv, { operations = createAgentCliOperations() } = {}) {
  if (argv.length === 1 && argv[0] === "--version") {
    return Object.freeze({
      schema: "clockchain.agent-handshake-cli-version/v1",
      version: AGENT_HANDSHAKE_HELPER_VERSION,
    });
  }
  const [operation, ...args] = argv;
  if (!operations.names.includes(operation)) invalid();
  let values;
  try {
    values = parseArgs({
      args,
      allowPositionals: false,
      strict: true,
      options: {
        "state-dir": { type: "string" },
        "payload-base64url": { type: "string" },
      },
    }).values;
  } catch { invalid(); }
  if (typeof values["state-dir"] !== "string" || !isAbsolute(values["state-dir"])) invalid();
  const needsPayload = ["policy", "sign", "verify-certificate"].includes(operation);
  if (needsPayload !== Object.hasOwn(values, "payload-base64url")) invalid();
  return operations.dispatch({
    operation,
    stateDir: values["state-dir"],
    payload: needsPayload ? payload(values["payload-base64url"]) : undefined,
  });
}
