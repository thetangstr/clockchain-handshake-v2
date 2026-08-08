const LEDGER_TIMESTAMP = /^(\d{2})-(\d{2})-(\d{4})[_ ](\d{2}):(\d{2}):(\d{2}):(\d{3})(?: UTC)?$/u;

function boundedInteger(text, { min, max }) {
  const n = Number(text);
  return Number.isInteger(n) && n >= min && n <= max ? n : null;
}

export function issuedAtMsFromLedgerTimestamp(timestamp) {
  const raw = timestamp?.madMarzulloTime;
  if (typeof raw !== "string") {
    throw new TypeError("Clockchain timestamp did not include madMarzulloTime.");
  }
  const match = LEDGER_TIMESTAMP.exec(raw);
  if (!match) {
    throw new TypeError("Clockchain timestamp format is not supported.");
  }
  const [, dayText, monthText, yearText, hourText, minuteText, secondText, millisecondText] = match;
  const day = boundedInteger(dayText, { min: 1, max: 31 });
  const month = boundedInteger(monthText, { min: 1, max: 12 });
  const year = boundedInteger(yearText, { min: 1970, max: 9999 });
  const hour = boundedInteger(hourText, { min: 0, max: 23 });
  const minute = boundedInteger(minuteText, { min: 0, max: 59 });
  const second = boundedInteger(secondText, { min: 0, max: 59 });
  const millisecond = boundedInteger(millisecondText, { min: 0, max: 999 });
  if ([day, month, year, hour, minute, second, millisecond].some((value) => value === null)) {
    throw new TypeError("Clockchain timestamp contains an out-of-range field.");
  }
  const issuedAtMs = Date.UTC(year, month - 1, day, hour, minute, second, millisecond);
  const roundTrip = new Date(issuedAtMs);
  if (
    !Number.isSafeInteger(issuedAtMs) ||
    roundTrip.getUTCFullYear() !== year ||
    roundTrip.getUTCMonth() !== month - 1 ||
    roundTrip.getUTCDate() !== day ||
    roundTrip.getUTCHours() !== hour ||
    roundTrip.getUTCMinutes() !== minute ||
    roundTrip.getUTCSeconds() !== second ||
    roundTrip.getUTCMilliseconds() !== millisecond
  ) {
    throw new TypeError("Clockchain timestamp is not a safe UTC millisecond value.");
  }
  return issuedAtMs;
}

export function assertHandshakeRepositoryKey({ discovery, handshake }) {
  const expected = discovery?.operatorPublicKey;
  const actual = handshake?.body?.repositoryPublicKey;
  if (actual !== expected) {
    throw new Error("The signed terms name a different operator key than the invitation.");
  }
  return actual;
}

export function selectRequestorRoster(messages, previous = {}) {
  let identityReady = previous.identityReady ?? null;
  let partyReady = previous.partyReady ?? null;
  for (const message of messages ?? []) {
    if (message?.role !== "requestor") continue;
    if (message.kind === "identity_ready" && identityReady === null) {
      identityReady = message;
      partyReady = null;
      continue;
    }
    if (message.kind !== "party_ready" || identityReady === null || partyReady !== null) continue;
    const identityAddress = String(identityReady.body?.address ?? "").toLowerCase();
    const readyAddress = String(message.body?.address ?? "").toLowerCase();
    if (
      identityAddress &&
      readyAddress === identityAddress &&
      message.senderKey === identityReady.senderKey
    ) {
      partyReady = message;
    }
  }
  return { identityReady, partyReady, ready: identityReady !== null && partyReady !== null };
}
