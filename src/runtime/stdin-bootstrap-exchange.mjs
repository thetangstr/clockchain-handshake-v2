import { createBootstrapExchangeContract } from "./bootstrap-exchange-contract.mjs";

const MAX_STDIN_BYTES = 256 * 1024;

async function oneJsonLine(stdin) {
  let body = "";
  for await (const chunk of stdin) {
    body += Buffer.from(chunk).toString("utf8");
    if (Buffer.byteLength(body) > MAX_STDIN_BYTES) throw new Error("too large");
  }
  const lines = body.split(/\r?\n/).filter((line) => line.length > 0);
  if (lines.length !== 1) throw new Error("lines");
  const parsed = JSON.parse(lines[0]);
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error("json");
  return parsed;
}

export function createStdinBootstrapExchange({ maxWaitMs = 30_000, role, runId, stdin, stdout }) {
  return createBootstrapExchangeContract({
    maxWaitMs,
    role,
    runId,
    transport: {
      async publishOwnDescriptor(descriptor) {
        stdout.write(`${JSON.stringify(descriptor)}\n`);
        return Object.freeze({ published: true });
      },
      async awaitPeerDescriptor() { return oneJsonLine(stdin); },
      async destroy() { return Object.freeze({ destroyed: true }); },
    },
  });
}
