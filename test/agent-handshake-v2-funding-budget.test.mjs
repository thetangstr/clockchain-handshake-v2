import assert from "node:assert/strict";
import { chmod, lstat, mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import {
  createFileFundingBudgetStore,
  createFundingBudget,
} from "../src/agent-handshake/v2/funding-budget.mjs";

const A = "0x" + "1".repeat(40);
const B = "0x" + "2".repeat(40);

test("required-fresh reserves both seats atomically before either transfer", async () => {
  let records = [];
  const budget = createFundingBudget({
    load: async () => records,
    save: async (next) => { records = structuredClone(next); },
    now: () => 1_000_000,
  });
  const reservation = await budget.reserve({
    addresses: [A, B],
    identityMode: "required_fresh",
    sessionId: "22222222-3333-4444-8555-666666666666",
  });
  assert.equal(reservation.totalEth, "0.02");
  assert.deepEqual(reservation.addresses, [A, B]);
  assert.equal(records.length, 2);
});

test("concurrent, duplicate, exhausted, and backpressured reservations fail without partial state", async () => {
  let records = [];
  const budget = createFundingBudget({
    load: async () => records,
    save: async (next) => { records = structuredClone(next); },
    now: () => 1_000_000,
    queueLimit: 1,
  });
  const sessionId = "22222222-3333-4444-8555-666666666666";
  const results = await Promise.allSettled([
    budget.reserve({ addresses: [A, B], identityMode: "required_fresh", sessionId }),
    budget.reserve({ addresses: [A, B], identityMode: "required_fresh", sessionId }),
  ]);
  assert.equal(results.filter(({ status }) => status === "fulfilled").length, 1);
  assert.equal(records.length, 2);
  await assert.rejects(() => budget.reserve({ addresses: [A, A], identityMode: "required_fresh", sessionId: "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee" }));
  assert.equal(records.length, 2);
});

test("restart state enforces rolling-hour and UTC-day ceilings", async () => {
  const now = Date.UTC(2026, 7, 10, 12, 0, 0);
  let records = Array.from({ length: 20 }, (_, index) => ({
    address: "0x" + (index + 10).toString(16).padStart(40, "0"),
    amountEth: "0.01",
    atMs: now - 1,
    sessionId: "00000000-0000-4000-8000-" + String(index).padStart(12, "0"),
  }));
  const before = structuredClone(records);
  const budget = createFundingBudget({
    load: async () => records,
    save: async (next) => { records = structuredClone(next); },
    now: () => now,
  });
  await assert.rejects(() => budget.reserve({
    addresses: [A, B],
    identityMode: "required_fresh",
    sessionId: "22222222-3333-4444-8555-666666666666",
  }));
  assert.deepEqual(records, before);
});

test("restart state accepts historical 0.02 seat reservations after funding policy changes", async () => {
  const now = Date.UTC(2026, 7, 16, 1, 0, 0);
  let records = [{
    address: "0x" + "3".repeat(40),
    amountEth: "0.02",
    atMs: now - (2 * 24 * 60 * 60 * 1000),
    sessionId: "11111111-2222-4333-8444-555555555555",
  }];
  const budget = createFundingBudget({
    load: async () => records,
    save: async (next) => { records = structuredClone(next); },
    now: () => now,
  });

  const reservation = await budget.reserve({
    addresses: [A, B],
    identityMode: "required_fresh",
    sessionId: "22222222-3333-4444-8555-666666666666",
  });

  assert.equal(reservation.totalEth, "0.02");
  assert.deepEqual(records.map(({ amountEth }) => amountEth), ["0.02", "0.01", "0.01"]);
});

test("funding budget emits threshold-only alerts without exposing reserved addresses", async () => {
  const now = Date.UTC(2026, 7, 10, 12, 0, 0);
  let records = Array.from({ length: 14 }, (_, index) => ({
    address: "0x" + (index + 10).toString(16).padStart(40, "0"),
    amountEth: "0.01",
    atMs: now - 1,
    sessionId: "00000000-0000-4000-8000-" + String(index).padStart(12, "0"),
  }));
  const alerts = [];
  const budget = createFundingBudget({
    load: async () => records,
    save: async (next) => { records = structuredClone(next); },
    now: () => now,
    alertHourCents: 16,
    alertDayCents: 80,
    onAlert: (value) => alerts.push(value),
  });
  await budget.reserve({
    addresses: [A, B],
    identityMode: "required_fresh",
    sessionId: "22222222-3333-4444-8555-666666666666",
  });
  assert.deepEqual(alerts, [{ dailyEth: "0.16", hourlyEth: "0.16" }]);
  assert.equal(JSON.stringify(alerts).includes(A), false);
  assert.equal(JSON.stringify(alerts).includes(B), false);
});

test("not-required reserves nothing and existing-or-fresh reserves only missing addresses", async () => {
  let records = [];
  const budget = createFundingBudget({ load: async () => records, save: async (next) => { records = next; } });
  assert.deepEqual(await budget.reserve({
    addresses: [],
    identityMode: "not_required",
    sessionId: "22222222-3333-4444-8555-666666666666",
  }), { addresses: [], totalEth: "0.00" });
  assert.equal((await budget.reserve({
    addresses: [A],
    identityMode: "required_existing_or_fresh",
    sessionId: "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
  })).totalEth, "0.01");
});

test("file store is restart-safe and remains mode 0600", async () => {
  const parent = await mkdtemp(join(tmpdir(), "funding-budget-"));
  await chmod(parent, 0o700);
  const path = join(parent, "ledger.jsonl");
  const firstStore = createFileFundingBudgetStore({ path });
  const first = createFundingBudget({ ...firstStore, now: () => 1_000_000 });
  await first.reserve({
    addresses: [A],
    identityMode: "required_existing_or_fresh",
    sessionId: "22222222-3333-4444-8555-666666666666",
  });
  const secondStore = createFileFundingBudgetStore({ path });
  const loaded = await secondStore.load();
  assert.equal(loaded.length, 1);
  assert.equal((await lstat(path)).mode & 0o777, 0o600);
  const second = createFundingBudget({ ...secondStore, now: () => 1_000_001 });
  await assert.rejects(() => second.reserve({
    addresses: [A],
    identityMode: "required_existing_or_fresh",
    sessionId: "22222222-3333-4444-8555-666666666666",
  }));
});
