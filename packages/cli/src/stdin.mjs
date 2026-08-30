export const HANDSHAKE_CLI_STDIN_MAX_BYTES = 1024 * 1024;
export const HANDSHAKE_CLI_STDIN_IDLE_TIMEOUT_MS = 5000;

function inputError() {
  return Object.assign(new Error("Handshake CLI input was rejected."), { code: "SCHEMA_INVALID" });
}

function assertFinitePositiveInteger(value) {
  if (!Number.isInteger(value) || value <= 0) throw inputError();
}

async function withIdleTimeout(promise, idleTimeoutMs) {
  let timeout;
  try {
    return await Promise.race([
      promise,
      new Promise((_, reject) => {
        timeout = setTimeout(() => reject(inputError()), idleTimeoutMs);
      }),
    ]);
  } finally {
    clearTimeout(timeout);
  }
}

export async function readHandshakeCliJsonInput(stream, options = {}) {
  const maxBytes = options.maxBytes ?? HANDSHAKE_CLI_STDIN_MAX_BYTES;
  const idleTimeoutMs = options.idleTimeoutMs ?? HANDSHAKE_CLI_STDIN_IDLE_TIMEOUT_MS;
  assertFinitePositiveInteger(maxBytes);
  assertFinitePositiveInteger(idleTimeoutMs);
  if (!stream || typeof stream[Symbol.asyncIterator] !== "function") throw inputError();
  if (typeof stream.setEncoding === "function") stream.setEncoding("utf8");

  let text = "";
  let bytes = 0;
  const iterator = stream[Symbol.asyncIterator]();
  try {
    while (true) {
      const { value, done } = await withIdleTimeout(iterator.next(), idleTimeoutMs);
      if (done) break;
      const chunk = String(value);
      bytes += Buffer.byteLength(chunk, "utf8");
      if (bytes > maxBytes) throw inputError();
      text += chunk;
    }
  } catch {
    if (typeof stream.destroy === "function") stream.destroy();
    throw inputError();
  }

  try {
    return text.trim().length === 0 ? {} : JSON.parse(text);
  } catch {
    throw inputError();
  }
}
