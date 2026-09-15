// A foreign-agent decision author for the payee (provider) side of the handshake.
//
// The wire protocol binds the CONTENT of an acceptance cryptographically to the discovered
// proposal — it cannot be authored freely, and there is no DECLINE message. The one real
// degree of freedom a provider agent holds is therefore the go/no-go decision on a proposal.
// This module lets a locally hosted Hermes agent (GLM-5.3-flash by default, or another model)
// make that decision genuinely: it is handed a read-only view of the proposed terms, reasons
// over them, and returns { accept, reason }. roles-core proceeds to sign the acceptance only
// when the agent AFFIRMATIVELY accepts; any decline, error, or unparseable reply fails closed.
//
// No key, no chain, and no network beyond the local Hermes model call: this is offline-safe.

import { execFile } from "node:child_process";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);

// Friendly aliases → (provider, model) for `hermes -z`. Anything not listed is passed through
// as a raw model name on the default provider, so new models work without editing this map.
const DECIDER_MODELS = {
  "glm-5.3-flash": { provider: "zai", model: "glm-5.3-flash" },
  "kimi-k3": { provider: "zai", model: "kimi-k3" },
};

export function resolveDeciderModel(name) {
  return DECIDER_MODELS[name] ?? { provider: "zai", model: name };
}

function formatAmount(amount) {
  if (!amount || typeof amount !== "object") {
    return "unspecified";
  }
  return `${amount.currency ?? "?"} ${amount.value ?? "?"}`;
}

function formatAmounts(amountOptions) {
  if (!Array.isArray(amountOptions) || amountOptions.length === 0) {
    return "unspecified";
  }
  return amountOptions.map(formatAmount).join(", ");
}

function buildPrompt(context, payeeName) {
  return [
    `You are ${payeeName}, an autonomous service-provider agent deciding whether to accept an`,
    `agent-to-agent payment-authorization handshake. Accepting authorizes intent to transact`,
    `ONLY: no money moves, and you are not yet agreeing to perform any work.`,
    ``,
    `Proposed terms:`,
    `- Proposed payment amount: ${formatAmount(context.amount)}`,
    `- Amount option(s) the signed terms allow: ${formatAmounts(context.amountOptions)}`,
    `- Authorization window: closes ${context.windowMs ?? "unknown"} ms after the proposal anchors on-chain (ledger block time)`,
    `- Payer (buyer) agent id: ${context.payer?.agentId ?? "unknown"} (${context.payer?.address ?? "no address"})`,
    `- Your (payee) agent id: ${context.payee?.agentId ?? "unknown"}`,
    `- Protocol: ${context.protocol ?? "unknown"}`,
    `- Session: ${context.sessionId ?? "unknown"}`,
    ``,
    `Decide whether these terms are reasonable and safe to accept. Accept ordinary invoice-scale`,
    `terms from a registered counterparty; decline only if something is clearly wrong — an`,
    `implausible amount, a missing counterparty, or an unrecognized protocol.`,
    ``,
    `Reply with ONLY a compact JSON object and nothing else. No markdown, no prose, no code fence:`,
    `{"accept": true or false, "reason": "<one sentence, at most 140 characters>"}`,
  ].join("\n");
}

// Pull the first balanced JSON object out of the model's reply and validate its shape.
function parseDecision(raw) {
  if (typeof raw !== "string") return null;
  const match = raw.match(/\{[\s\S]*\}/);
  if (!match) return null;
  let obj;
  try {
    obj = JSON.parse(match[0]);
  } catch {
    return null;
  }
  if (obj === null || typeof obj !== "object" || typeof obj.accept !== "boolean") {
    return null;
  }
  return {
    accept: obj.accept,
    reason: typeof obj.reason === "string" ? obj.reason.trim() : "",
  };
}

/**
 * Build a decidePayee(context) function backed by a local Hermes model.
 *
 * @param {object} opts
 * @param {string} opts.provider   Hermes provider (e.g. "zai").
 * @param {string} opts.model      Model id (e.g. "glm-5.3-flash").
 * @param {string} [opts.payeeName] Display name used in the prompt.
 * @param {number} [opts.timeoutMs] Hard timeout for the model call.
 * @param {(line: string) => void} [opts.log] Sink for human-readable trace lines.
 * @returns {(context: object) => Promise<{accept: boolean, reason: string}>}
 */
export function makeAgentDecider({
  provider,
  model,
  payeeName = "Agent Clint",
  timeoutMs = 120_000,
  log = () => {},
} = {}) {
  return async function decidePayee(context) {
    const prompt = buildPrompt(context, payeeName);
    log(`${payeeName} (${provider}/${model}) is evaluating the proposal…`);
    let stdout;
    try {
      ({ stdout } = await execFileAsync(
        "hermes",
        ["-z", prompt, "--provider", provider, "-m", model, "-t", "", "--ignore-rules"],
        { timeout: timeoutMs, maxBuffer: 4 * 1024 * 1024 },
      ));
    } catch (error) {
      const detail = error?.killed ? `timed out after ${timeoutMs}ms` : error?.code ?? error?.message ?? "error";
      log(`${payeeName} could not reach ${model} (${detail}); failing closed — no acceptance.`);
      throw new Error("AGENT_DECISION_UNAVAILABLE");
    }
    const decision = parseDecision(stdout);
    if (!decision) {
      log(`${payeeName}'s ${model} reply was not a parseable decision; failing closed. Raw: ${String(stdout).trim().slice(0, 200)}`);
      throw new Error("AGENT_DECISION_UNPARSEABLE");
    }
    log(`${payeeName} decided ${decision.accept ? "ACCEPT" : "DECLINE"} — ${decision.reason || "(no reason given)"}`);
    return decision;
  };
}
