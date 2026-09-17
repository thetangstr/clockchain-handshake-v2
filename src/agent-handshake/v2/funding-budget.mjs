const ADDRESS = /^0x[0-9a-f]{40}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const HOUR_MS = 60 * 60 * 1000;
const SEAT_CENTS = 1;
const SESSION_CENTS = 2;
const HOUR_CENTS = 20;
const DAY_CENTS = 100;
// Bounded one-shot migration read: lets the store read and compact a legacy
// oversized ledger, then fail closed. Steady-state writes compact to the
// current day window, so the file stays far below this bound.
const LEDGER_MAX_BYTES = 1024 * 1024;

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
  // Records written by the pre-revert experimental build carry "0.02" per
  // seat; they still count toward the windows at their real spend. New
  // records are always written at "0.01" (SEAT_CENTS).
  if (value === "0.01") return SEAT_CENTS;
  if (value === "0.02") return 2;
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

// History is validated by record() (which accepts the legacy 0.02 seat
// denomination at its real value); only the just-reserved suffix must
// additionally carry the current 0.01 denomination, so historical rows stay
// readable without permitting new 0.02 writes.
function currentRecord(value) {
  const entry = record(value);
  if (entry.amountEth !== "0.01") invalid();
  return entry;
}

function utcDayStart(nowMs) {
  const date = new Date(nowMs);
  return Date.UTC(date.getUTCFullYear(), date.getUTCMonth(), date.getUTCDate());
}

export function createFundingBudget({
  alertDayCents = 80,
  alertHourCents = 16,
  load,
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
    !Number.isSafeInteger(alertHourCents) ||
    alertHourCents < 1 ||
    alertHourCents > HOUR_CENTS ||
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
        hourCents + newCents > HOUR_CENTS ||
        dayCents + newCents > DAY_CENTS
      ) invalid();
      const additions = addresses.map((address) => Object.freeze({
        address,
        amountEth: "0.01",
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
        totalEth: addresses.length === 1 ? "0.01" : "0.02",
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
  // A reserve always loads before it saves; the raw content observed then is
  // the concurrency basis the append must still match before it extends the
  // file, so an interleaved write can never be silently discarded.
  let basis;
  let basisRecords;

  async function readRaw() {
    try {
      return await readPrivateText({ maxBytes: LEDGER_MAX_BYTES, path, platform });
    } catch (error) {
      if (error?.code === "ENOENT") return null;
      invalid();
    }
  }

  async function load() {
    const raw = await readRaw();
    let records;
    try {
      // Strict JSONL framing: a non-empty ledger is exactly complete
      // newline-terminated records — no partial trailing record, no blank or
      // whitespace-only lines. Anything else fails closed.
      if (raw === null || raw.length === 0) {
        records = [];
      } else {
        if (!raw.endsWith("\n")) invalid();
        records = raw.slice(0, -1).split("\n").map((line) => {
          if (line.length === 0 || line.trim() !== line) invalid();
          return record(JSON.parse(line));
        });
      }
    } catch (error) {
      if (error instanceof FundingBudgetError) throw error;
      invalid();
    }
    basis = raw;
    basisRecords = records;
    return records;
  }

  async function syncParentDirectory() {
    if (platform === "win32") return;
    const directory = await open(
      parent,
      fsConstants.O_RDONLY | (fsConstants.O_DIRECTORY ?? 0),
    );
    try {
      await directory.sync();
    } finally {
      await directory.close().catch(() => {});
    }
  }

  async function save(next) {
    if (!Array.isArray(next) || basis === undefined) invalid();
    const verifiedNext = next.map(record);
    await preparePrivateDirectory({ path: parent, platform });
    if ((await readRaw()) !== basis) invalid();
    if (
      verifiedNext.length <= basisRecords.length ||
      verifiedNext.slice(0, basisRecords.length).some((entry, index) =>
        JSON.stringify(entry) !== JSON.stringify(basisRecords[index]))
    ) invalid();
    // The suffix is the fresh reservation: validate it against the current
    // denomination before anything is written. Historical prefix rows keep
    // their legacy 0.02 values.
    const additions = verifiedNext.slice(basisRecords.length).map(currentRecord);
    const appendBytes = Buffer.from(
      additions.map((entry) => JSON.stringify(entry) + "\n").join(""),
      "utf8",
    );
    const cutoff = Math.min(
      additions[0].atMs - HOUR_MS,
      utcDayStart(additions[0].atMs),
    );
    let compacted = false;
    if (Buffer.byteLength(basis ?? "", "utf8") + appendBytes.length > LEDGER_MAX_BYTES) {
      // Boundary path: appending would push the ledger past the bounded
      // read size, so the retained basis and the fresh reservation are
      // staged together and installed by a single atomic rename. The
      // reservation is durable at the rename — a crash before it leaves
      // the old ledger with no accepted reservation, a crash after it
      // leaves the compacted ledger containing the reservation. The byte
      // check immediately before rename keeps an interleaved writer
      // fail-closed, since nothing of ours was appended to lose.
      const compactedRecords = [
        ...basisRecords.filter(
          (entry) => entry.atMs >= cutoff || entry.sessionId === additions[0].sessionId,
        ),
        ...additions,
      ];
      const text = compactedRecords.map((entry) => JSON.stringify(entry) + "\n").join("");
      const tmp = `${path}.${randomUUID()}.tmp`;
      try {
        await writePrivateFile({ bytes: Buffer.from(text, "utf8"), path: tmp, platform });
        if ((await readRaw()) !== basis) invalid();
        await rename(tmp, path);
        await syncParentDirectory();
        if ((await readRaw()) !== text) invalid();
        basis = text;
        basisRecords = compactedRecords;
        compacted = true;
      } finally {
        await rm(tmp, { force: true }).catch(() => {});
      }
    }
    if (!compacted) {
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
        await handle.writeFile(appendBytes);
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
      // The accepted reservation is durable from this point on. Compaction
      // is best-effort: it replaces the file only while the on-disk bytes
      // still equal the just-appended basis, so an interleaved append is
      // skipped rather than overwritten, and any failure leaves the
      // append-only ledger authoritative instead of turning the reservation
      // into a failed write.
      basis = (basis ?? "") + appendBytes.toString("utf8");
      try {
        const authoritative = [...basisRecords, ...additions];
        const retained = authoritative.filter(
          (entry) => entry.atMs >= cutoff || entry.sessionId === additions[0].sessionId,
        );
        if (retained.length < authoritative.length) {
          const text = retained.map((entry) => JSON.stringify(entry) + "\n").join("");
          const tmp = `${path}.${randomUUID()}.tmp`;
          try {
            await writePrivateFile({ bytes: Buffer.from(text, "utf8"), path: tmp, platform });
            // Re-check the authoritative bytes immediately before rename: an
            // interleaved append since our fsync makes them differ from the
            // basis, so the staged file is dropped by the finally instead of
            // renaming over the other writer's reservation.
            if ((await readRaw()) === basis) {
              await rename(tmp, path);
              await syncParentDirectory();
              // Confirm the landed content through the secure reader before
              // accepting it as the new basis; on any mismatch the stale basis
              // stays so the next save still detects the drift and fails closed.
              if ((await readRaw()) === text) basis = text;
            }
          } finally {
            await rm(tmp, { force: true }).catch(() => {});
          }
        }
      } catch {}
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
import { randomUUID } from "node:crypto";
import { lstat, open, rename, rm } from "node:fs/promises";
import { dirname, isAbsolute } from "node:path";

import {
  preparePrivateDirectory,
  readPrivateText,
  writePrivateFile,
} from "../../core/private-path.mjs";
