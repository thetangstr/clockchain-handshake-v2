import { execFile } from "node:child_process";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);
const MAX_DECIDER_STDOUT = 4096;

const DECIDER_MODELS = {
  "glm-5.3-flash": { provider: "zai", model: "glm-5.3-flash" },
  "kimi-k3": { provider: "zai", model: "kimi-k3" },
};

export function resolveDeciderModel(name) {
  return DECIDER_MODELS[name] ?? { provider: "zai", model: name };
}

function formatAmount(amount) {
  if (!amount || typeof amount !== "object") return "unspecified";
  return `${amount.currency ?? "?"} ${amount.value ?? "?"}`;
}

function formatAmounts(amountOptions) {
  if (!Array.isArray(amountOptions) || amountOptions.length === 0) return "unspecified";
  return amountOptions.map(formatAmount).join(", ");
}

export function buildAgentDecisionPrompt(context, payeeName = "Agent Clint") {
  return [
    `You are ${payeeName}, an autonomous service-provider agent deciding whether to accept an`,
    "agent-to-agent payment-authorization handshake. Accepting authorizes intent to transact",
    "ONLY: no money moves, and you are not yet agreeing to perform any work.",
    "",
    "Proposed terms:",
    `- Proposed payment amount: ${formatAmount(context.amount)}`,
    `- Amount option(s) the signed terms allow: ${formatAmounts(context.amountOptions)}`,
    `- Authorization window: closes ${context.windowMs ?? "unknown"} ms after the proposal anchors on-chain`,
    `- Payer agent id: ${context.payer?.agentId ?? "unknown"} (${context.payer?.address ?? "no address"})`,
    `- Payee agent id: ${context.payee?.agentId ?? "unknown"}`,
    `- Protocol: ${context.protocol ?? "unknown"}`,
    `- Session: ${context.sessionId ?? "unknown"}`,
    "",
    "Decline if the amount is implausible, the counterparty is missing, or the protocol is unrecognized.",
    "Reply with exactly this compact JSON shape and nothing else:",
    "{\"accept\":true,\"reason\":\"one single-line sentence up to 140 chars\"}",
  ].join("\n");
}

export function parseAgentDecision(raw) {
  if (typeof raw !== "string") return null;
  if (Buffer.byteLength(raw, "utf8") > MAX_DECIDER_STDOUT) return null;
  const trimmed = raw.trim();
  if (trimmed.length === 0) return null;
  let parsed;
  try {
    parsed = JSON.parse(trimmed);
  } catch {
    return null;
  }
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) return null;
  const keys = Object.keys(parsed).sort();
  if (keys.length !== 2 || keys[0] !== "accept" || keys[1] !== "reason") return null;
  if (typeof parsed.accept !== "boolean") return null;
  if (typeof parsed.reason !== "string") return null;
  if (parsed.reason !== parsed.reason.trim()) return null;
  if (parsed.reason.length === 0 || parsed.reason.length > 140) return null;
  if (/[\u0000-\u001f\u007f]/u.test(parsed.reason)) return null;
  if (JSON.stringify(parsed) !== trimmed) return null;
  return Object.freeze({ accept: parsed.accept, reason: parsed.reason });
}

export function makeAgentDecider({
  provider,
  model,
  payeeName = "Agent Clint",
  timeoutMs = 120_000,
  log = () => {},
  runHermes = execFileAsync,
} = {}) {
  return async function decidePayee(context) {
    const prompt = buildAgentDecisionPrompt(context, payeeName);
    log(`${payeeName} (${provider}/${model}) is evaluating the proposal...`);
    let stdout;
    try {
      const result = await runHermes(
        "hermes",
        ["-z", prompt, "--provider", provider, "-m", model, "-t", "", "--ignore-rules"],
        { timeout: timeoutMs, maxBuffer: MAX_DECIDER_STDOUT },
      );
      stdout = typeof result === "string" ? result : result?.stdout;
    } catch (error) {
      const detail = error?.killed ? `timed out after ${timeoutMs}ms` : error?.code ?? error?.message ?? "error";
      log(`${payeeName} could not reach ${model} (${detail}); failing closed.`);
      throw new Error("AGENT_DECISION_UNAVAILABLE");
    }
    const decision = parseAgentDecision(stdout);
    if (!decision) {
      log(`${payeeName}'s ${model} reply was not a valid decision; failing closed.`);
      throw new Error("AGENT_DECISION_UNPARSEABLE");
    }
    log(`${payeeName} decided ${decision.accept ? "ACCEPT" : "DECLINE"} - ${decision.reason}`);
    return decision;
  };
}
