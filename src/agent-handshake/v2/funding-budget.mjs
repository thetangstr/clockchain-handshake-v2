const ADDRESS = /^0x[0-9a-f]{40}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const HOUR_MS = 60 * 60 * 1000;
export const AGENT_HANDSHAKE_V2_SEAT_FUNDING_ETH = "0.01";
const SEAT_CENTS = 1;
const SESSION_CENTS = 2;
const HOUR_CENTS = 20;
const DAY_CENTS = 100;
export const AGENT_HANDSHAKE_V2_MAX_HOURLY_FUNDING_CENTS = 40;

export class FundingBudgetError extends Error {
  constructor() {
    super("Public identity funding budget is unavailable.");
    this.name = "FundingBudgetError";
    this.category = "capacity";
    this.code = "AGENT_HANDSHAKE_FUNDING_BUDGET";
  }
}

function invalid() {
  throw new FundingBudgetError();
}

function amountCents(value) {
  if (value === "0.02") return 2;
  if (value === AGENT_HANDSHAKE_V2_SEAT_FUNDING_ETH) return SEAT_CENTS;
  invalid();
}

function record(value) {
  if (
    value === null ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    Object.keys(value).length !== 4 ||
    !["address", "amountEth", "atMs", "sessionId"].every((key) => Object.hasOwn(value, key)) ||
    !ADDRESS.test(value.address) ||
    !UUID.test(value.sessionId) ||
    !Number.isSafeInteger(value.atMs) ||
    value.atMs < 0
  ) invalid();
  amountCents(value.amountEth);
  return Object.freeze({ ...value });
}

function utcDayStart(nowMs) {
  const date = new Date(nowMs);
  return Date.UTC(date.getUTCFullYear(), date.getUTCMonth(), date.getUTCDate());
}

export function createFundingBudget({
  alertDayCents = 80,
  alertHourCents = 16,
  load,
  maxHourCents = HOUR_CENTS,
  now = Date.now,
  onAlert = () => {},
  queueLimit = 16,
  save,
} = {}) {
  if (
    typeof load !== "function" ||
    typeof save !== "function" ||
    typeof now !== "function" ||
    typeof onAlert !== "function" ||
    !Number.isSafeInteger(maxHourCents) ||
    maxHourCents < SESSION_CENTS ||
    maxHourCents > AGENT_HANDSHAKE_V2_MAX_HOURLY_FUNDING_CENTS ||
    !Number.isSafeInteger(alertHourCents) ||
    alertHourCents < 1 ||
    alertHourCents > maxHourCents ||
    !Number.isSafeInteger(alertDayCents) ||
    alertDayCents < 1 ||
    alertDayCents > DAY_CENTS ||
    !Number.isSafeInteger(queueLimit) ||
    queueLimit < 1
  ) invalid();
  let tail = Promise.resolve();
  let queued = 0;

  async function reserve(input) {
    if (queued >= queueLimit) invalid();
    queued += 1;
    const previous = tail;
    let release;
    tail = new Promise((resolve) => { release = resolve; });
    await previous;
    try {
      const sessionId = input?.sessionId;
      const identityMode = input?.identityMode;
      const addresses = input?.addresses;
      if (
        !UUID.test(sessionId) ||
        !["required_fresh", "required_existing_or_fresh", "not_required"].includes(identityMode) ||
        !Array.isArray(addresses) ||
        addresses.some((address) => typeof address !== "string" || !ADDRESS.test(address)) ||
        new Set(addresses).size !== addresses.length ||
        (identityMode === "required_fresh" && addresses.length !== 2) ||
        (identityMode === "required_existing_or_fresh" && ![1, 2].includes(addresses.length)) ||
        (identityMode === "not_required" && addresses.length !== 0)
      ) invalid();
      if (addresses.length === 0) {
        return Object.freeze({ addresses: Object.freeze([]), totalEth: "0.00" });
      }
      const atMs = now();
      if (!Number.isSafeInteger(atMs) || atMs < 0) invalid();
      let existing;
      try {
        existing = (await load()).map(record);
      } catch {
        invalid();
      }
      if (
        existing.some((entry) =>
          entry.sessionId === sessionId &&
          addresses.includes(entry.address))
      ) invalid();
      const newCents = addresses.length * SEAT_CENTS;
      const sessionCents = existing
        .filter((entry) => entry.sessionId === sessionId)
        .reduce((sum, entry) => sum + amountCents(entry.amountEth), 0);
      const hourCents = existing
        .filter((entry) => entry.atMs > atMs - HOUR_MS)
        .reduce((sum, entry) => sum + amountCents(entry.amountEth), 0);
      const dayStart = utcDayStart(atMs);
      const dayCents = existing
        .filter((entry) => entry.atMs >= dayStart)
        .reduce((sum, entry) => sum + amountCents(entry.amountEth), 0);
      if (
        sessionCents + newCents > SESSION_CENTS ||
        hourCents + newCents > maxHourCents ||
        dayCents + newCents > DAY_CENTS
      ) invalid();
      const additions = addresses.map((address) => Object.freeze({
        address,
        amountEth: AGENT_HANDSHAKE_V2_SEAT_FUNDING_ETH,
        atMs,
        sessionId,
      }));
      try {
        await save([...existing, ...additions]);
        const nextHourCents = hourCents + newCents;
        const nextDayCents = dayCents + newCents;
        if (
          nextHourCents >= alertHourCents ||
          nextDayCents >= alertDayCents
        ) {
          onAlert(Object.freeze({
            dailyEth: (nextDayCents / 100).toFixed(2),
            hourlyEth: (nextHourCents / 100).toFixed(2),
          }));
        }
      } catch {
        invalid();
      }
      return Object.freeze({
        addresses: Object.freeze([...addresses]),
        totalEth: (addresses.length * SEAT_CENTS / 100).toFixed(2),
      });
    } finally {
      queued -= 1;
      release();
    }
  }

  return Object.freeze({ reserve });
}

export function createFileFundingBudgetStore({
  path,
  platform = process.platform,
} = {}) {
  if (
    typeof path !== "string" ||
    !isAbsolute(path) ||
    !path.endsWith(".jsonl")
  ) invalid();
  const parent = dirname(path);

  async function load() {
    try {
      const text = await readPrivateText({
        maxBytes: 64 * 1024,
        path,
        platform,
      });
      if (text.length === 0) return [];
      return text.trimEnd().split("\n").map((line) => record(JSON.parse(line)));
    } catch (error) {
      if (error?.code === "ENOENT") return [];
      invalid();
    }
  }

  async function save(next) {
    if (!Array.isArray(next)) invalid();
    const verifiedNext = next.map(record);
    await preparePrivateDirectory({ path: parent, platform });
    const current = await load();
    if (
      current.length >= verifiedNext.length ||
      current.some((entry, index) =>
        JSON.stringify(entry) !== JSON.stringify(verifiedNext[index]))
    ) invalid();
    const additions = verifiedNext.slice(current.length);
    let handle;
    try {
      handle = await open(
        path,
        fsConstants.O_WRONLY |
          fsConstants.O_APPEND |
          fsConstants.O_CREAT |
          (fsConstants.O_NOFOLLOW ?? 0),
        0o600,
      );
      if (platform !== "win32") await handle.chmod(0o600);
      const before = await handle.stat();
      if (!before.isFile() || before.isSymbolicLink() || before.nlink !== 1) invalid();
      const bytes = Buffer.from(
        additions.map((entry) => JSON.stringify(entry) + "\n").join(""),
        "utf8",
      );
      await handle.writeFile(bytes);
      await handle.sync();
      const after = await handle.stat();
      if (
        !after.isFile() ||
        after.nlink !== 1 ||
        (platform !== "win32" && (after.mode & 0o777) !== 0o600)
      ) invalid();
    } catch (error) {
      if (error instanceof FundingBudgetError) throw error;
      invalid();
    } finally {
      await handle?.close().catch(() => {});
    }
    const final = await lstat(path);
    if (
      !final.isFile() ||
      final.isSymbolicLink() ||
      final.nlink !== 1 ||
      (platform !== "win32" && (final.mode & 0o777) !== 0o600)
    ) invalid();
  }

  return Object.freeze({ load, save });
}
import { constants as fsConstants } from "node:fs";
import { lstat, open } from "node:fs/promises";
import { dirname, isAbsolute } from "node:path";

import {
  preparePrivateDirectory,
  readPrivateText,
} from "../../core/private-path.mjs";
