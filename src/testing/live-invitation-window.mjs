const DEFAULT_MONITOR_URL = "http://44.249.47.220:8080/v1/sessions/current/snapshot";
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

function readySnapshot(value, nowMs, minRemainingMs) {
  if (
    value === null || typeof value !== "object" || Array.isArray(value) ||
    value.schema !== "clockchain.agent-handshake-snapshot/v2" ||
    typeof value.sessionId !== "string" || !UUID.test(value.sessionId) ||
    value.certificate !== null || value.failure !== null ||
    value.invitation === null || typeof value.invitation !== "object" || Array.isArray(value.invitation) ||
    value.invitation.createdAtMs !== null || value.invitation.responderClaimedAtMs !== null ||
    value.timing === null || typeof value.timing !== "object" || Array.isArray(value.timing) ||
    !Number.isSafeInteger(value.timing.invitationExpiresAtMs) ||
    !Number.isSafeInteger(value.timing.sessionDeadlineMs) ||
    value.timing.sessionDeadlineMs < value.timing.invitationExpiresAtMs ||
    value.timing.invitationExpiresAtMs - nowMs < minRemainingMs
  ) return null;
  return Object.freeze({
    invitationExpiresAtMs: value.timing.invitationExpiresAtMs,
    sessionId: value.sessionId,
  });
}

export async function waitForFreshInvitationWindow({
  fetchFn = fetch,
  minRemainingMs = 90_000,
  monitorUrl = DEFAULT_MONITOR_URL,
  now = Date.now,
  pollMs = 2_000,
  sleep = (delayMs) => new Promise((resolve) => setTimeout(resolve, delayMs)),
  timeoutMs = 15 * 60_000,
} = {}) {
  if (
    typeof fetchFn !== "function" || typeof now !== "function" || typeof sleep !== "function" ||
    typeof monitorUrl !== "string" || !monitorUrl.startsWith("http://44.249.47.220:8080/") ||
    !Number.isSafeInteger(minRemainingMs) || minRemainingMs < 30_000 || minRemainingMs > 120_000 ||
    !Number.isSafeInteger(pollMs) || pollMs < 250 || pollMs > 30_000 ||
    !Number.isSafeInteger(timeoutMs) || timeoutMs < pollMs || timeoutMs > 30 * 60_000
  ) throw new TypeError("Invalid invitation readiness configuration.");

  const deadlineMs = now() + timeoutMs;
  while (now() < deadlineMs) {
    try {
      const response = await fetchFn(monitorUrl, {
        cache: "no-store",
        signal: AbortSignal.timeout(Math.min(pollMs, 5_000)),
      });
      if (response?.ok === true) {
        const found = readySnapshot(await response.json(), now(), minRemainingMs);
        if (found !== null) return found;
      }
    } catch {}
    await sleep(pollMs);
  }
  throw new Error("Clockchain did not provide a fresh invitation window before the demo deadline.");
}
