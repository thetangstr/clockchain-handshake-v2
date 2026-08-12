import { createBootstrapExchangeContract } from "./bootstrap-exchange-contract.mjs";

const MAX_STDIN_BYTES = 256 * 1024;

function oneJsonLine(stdin, signal) {
  return new Promise((resolve, reject) => {
    if (
      stdin === null || typeof stdin !== "object" || typeof stdin.on !== "function" || typeof stdin.off !== "function" ||
      signal === null || typeof signal !== "object" || typeof signal.addEventListener !== "function"
    ) {
      reject(new Error("input"));
      return;
    }
    let body = "";
    let settled = false;

    function cleanup() {
      stdin.off("data", onData);
      stdin.off("end", onEnd);
      stdin.off("error", onError);
      stdin.off("close", onClose);
      signal.removeEventListener("abort", onAbort);
    }

    function settle(callback, value) {
      if (settled) return;
      settled = true;
      cleanup();
      callback(value);
    }

    function onData(chunk) {
      body += Buffer.from(chunk).toString("utf8");
      if (Buffer.byteLength(body) > MAX_STDIN_BYTES) settle(reject, new Error("too large"));
    }

    function onEnd() {
      try {
        const lines = body.split(/\r?\n/).filter((line) => line.length > 0);
        if (lines.length !== 1) throw new Error("lines");
        const parsed = JSON.parse(lines[0]);
        if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error("json");
        settle(resolve, parsed);
      } catch (error) { settle(reject, error); }
    }

    function onError(error) { settle(reject, error); }
    function onClose() { if (!settled) settle(reject, new Error("closed")); }
    function onAbort() {
      settle(reject, new Error("aborted"));
      if (typeof stdin.destroy === "function" && stdin.destroyed !== true) stdin.destroy();
    }

    if (signal.aborted) return onAbort();
    stdin.on("data", onData);
    stdin.on("end", onEnd);
    stdin.on("error", onError);
    stdin.on("close", onClose);
    signal.addEventListener("abort", onAbort, { once: true });
  });
}

export function createStdinBootstrapExchange({ maxWaitMs = 30_000, role, runId, stdin, stdout }) {
  let activeRead = null;
  return createBootstrapExchangeContract({
    maxWaitMs,
    role,
    runId,
    transport: {
      async publishOwnDescriptor(descriptor) {
        stdout.write(`${JSON.stringify(descriptor)}\n`);
        return Object.freeze({ published: true });
      },
      async awaitPeerDescriptor({ signal }) {
        const controller = new AbortController();
        activeRead = controller;
        const abort = () => controller.abort();
        signal.addEventListener("abort", abort, { once: true });
        try { return await oneJsonLine(stdin, controller.signal); }
        finally {
          signal.removeEventListener("abort", abort);
          if (activeRead === controller) activeRead = null;
        }
      },
      async destroy() {
        activeRead?.abort();
        if (typeof stdin?.destroy === "function" && stdin.destroyed !== true) stdin.destroy();
        return Object.freeze({ destroyed: true });
      },
    },
  });
}
