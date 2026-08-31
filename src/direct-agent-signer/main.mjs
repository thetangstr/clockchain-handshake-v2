import { isAbsolute } from "node:path";
import { parseArgs } from "node:util";

import {
  createDirectAgentSignerOperations,
  DIRECT_AGENT_SIGNER_VERSION,
  validateDirectAgentSigningResult,
} from "./adapter.mjs";

function invalid() {
  throw new Error("Direct agent signer failed safely.");
}

function payload(value) {
  if (typeof value !== "string" || value.length === 0 || !/^[A-Za-z0-9_-]+$/.test(value)) invalid();
  try {
    const bytes = Buffer.from(value, "base64url");
    if (bytes.toString("base64url") !== value || bytes.length > 512 * 1024) invalid();
    return JSON.parse(bytes.toString("utf8"));
  } catch {
    invalid();
  }
}

export async function runDirectAgentSignerCli(argv, {
  operations = createDirectAgentSignerOperations(),
} = {}) {
  if (argv.length === 1 && argv[0] === "--version") {
    return Object.freeze({
      schema: "clockchain.direct-agent-signer-cli-version/v1",
      version: DIRECT_AGENT_SIGNER_VERSION,
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
  } catch {
    invalid();
  }
  if (typeof values["state-dir"] !== "string" || !isAbsolute(values["state-dir"])) invalid();
  if (!Object.hasOwn(values, "payload-base64url")) invalid();
  return validateDirectAgentSigningResult(await operations.dispatch({
    operation,
    stateDir: values["state-dir"],
    payload: payload(values["payload-base64url"]),
  }));
}
