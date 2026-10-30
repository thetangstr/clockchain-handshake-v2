// H-REQ-07: a clock that is re-read after every await that can take time must
// never be trusted to move backwards. A read that is not a safe integer, or
// that is lower than the previous read, throws: a caller relying on freshness
// fails closed instead of signing against a rolled-back time.

export class MonotonicClockError extends Error {
  constructor() {
    super("Clock read is not a monotonic safe integer.");
    this.name = "MonotonicClockError";
    this.category = "verification";
  }
}

export function monotonicClock(now) {
  if (typeof now !== "function") throw new MonotonicClockError();
  let previous = null;
  return Object.freeze({
    read() {
      const value = now();
      if (!Number.isSafeInteger(value) || (previous !== null && value < previous)) {
        throw new MonotonicClockError();
      }
      previous = value;
      return value;
    },
  });
}

// For a service that must keep answering: a read lower than an earlier one
// returns the earlier one, so freshness is never judged against a rolled-back
// time. A read that is not a safe integer throws.
export function nonDecreasingClock(now) {
  if (typeof now !== "function") throw new MonotonicClockError();
  let highest = null;
  return Object.freeze({
    read() {
      const value = now();
      if (!Number.isSafeInteger(value)) throw new MonotonicClockError();
      if (highest === null || value > highest) highest = value;
      return highest;
    },
  });
}
