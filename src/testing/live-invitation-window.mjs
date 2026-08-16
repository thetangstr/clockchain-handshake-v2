const DEFAULT_MONITOR_URL = "http://44.249.47.220:8080/v1/sessions/current/snapshot";
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const SHA = /^[0-9a-f]{40}$/;

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

function readyDiscovery(value, nowMs, minRemainingMs) {
  const invitationExpiresAtMs = typeof value?.invitationExpiresAtMs === "string"
    ? Number(value.invitationExpiresAtMs)
    : value?.invitationExpiresAtMs;
  if (
    value === null || typeof value !== "object" || Array.isArray(value) ||
    typeof value.sessionId !== "string" || !UUID.test(value.sessionId) ||
    typeof value.repositorySha !== "string" || !SHA.test(value.repositorySha) ||
    !Number.isSafeInteger(invitationExpiresAtMs) ||
    invitationExpiresAtMs - nowMs < minRemainingMs
  ) return null;
  return Object.freeze({ invitationExpiresAtMs, sessionId: value.sessionId });
}

function matchingUnusedFallback(value, sessionId) {
  const evidence = value?.evidence;
  return value !== null && typeof value === "object" && !Array.isArray(value) &&
    value.sessionId === sessionId && value.ok === true && value.discoverySet === true &&
    value.messageCount === 0 && value.lastSeq === "0" && value.paymentMoved === false &&
    evidence !== null && typeof evidence === "object" && !Array.isArray(evidence) &&
    Object.keys(evidence).sort().join(",") === "payee,payer" &&
    evidence.payer === false && evidence.payee === false &&
    Array.isArray(value.messages) && value.messages.length === 0;
}

export async function waitForFreshInvitationWindow({
  discoveryUrl = null,
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
    discoveryUrl !== null && (typeof discoveryUrl !== "string" || !discoveryUrl.startsWith("http://44.249.47.220:8080/")) ||
    typeof monitorUrl !== "string" || !monitorUrl.startsWith("http://44.249.47.220:8080/") ||
    !Number.isSafeInteger(minRemainingMs) || minRemainingMs < 30_000 || minRemainingMs > 120_000 ||
    !Number.isSafeInteger(pollMs) || pollMs < 250 || pollMs > 30_000 ||
    !Number.isSafeInteger(timeoutMs) || timeoutMs < pollMs || timeoutMs > 30 * 60_000
  ) throw new TypeError("Invalid invitation readiness configuration.");

  const deadlineMs = now() + timeoutMs;
  while (now() < deadlineMs) {
    try {
      if (discoveryUrl !== null) {
        const discoveryResponse = await fetchFn(discoveryUrl, {
          cache: "no-store",
          signal: AbortSignal.timeout(Math.min(pollMs, 5_000)),
        });
        if (discoveryResponse?.ok === true) {
          const discovery = readyDiscovery(await discoveryResponse.json(), now(), minRemainingMs);
          if (discovery !== null) {
            const monitorResponse = await fetchFn(monitorUrl, {
              cache: "no-store",
              signal: AbortSignal.timeout(Math.min(pollMs, 5_000)),
            });
            if (monitorResponse?.ok === true) {
              const monitor = await monitorResponse.json();
              const snapshot = readySnapshot(monitor, now(), minRemainingMs);
              if (snapshot?.sessionId === discovery.sessionId || matchingUnusedFallback(monitor, discovery.sessionId)) {
                return discovery;
              }
            }
          }
        }
        await sleep(pollMs);
        continue;
      }
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
