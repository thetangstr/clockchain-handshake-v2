import assert from "node:assert/strict";
import { chmod, lstat, mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import {
  createFileFundingBudgetStore,
  createFundingBudget,
} from "../src/agent-handshake/v2/funding-budget.mjs";

const A = "0x" + "1".repeat(40);
const B = "0x" + "2".repeat(40);
const C = "0x" + "3".repeat(40);

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

test("oversized legacy ledger compacts on first reserve without relaxing hard limits", async () => {
  const parent = await mkdtemp(join(tmpdir(), "funding-budget-oversize-"));
  await chmod(parent, 0o700);
  const path = join(parent, "ledger.jsonl");
  const now = Date.UTC(2026, 7, 10, 12, 0, 0);
  const dayStart = Date.UTC(2026, 7, 10);
  const sessionId = "22222222-3333-4444-8555-666666666666";
  // Historical records older than today plus legacy "0.02" rows, padded past
  // the old 64 KiB read bound so the pre-fix store would have failed closed.
  const lines = [];
  let bytes = 0;
  for (let index = 0; bytes < 70 * 1024; index += 1) {
    const line = JSON.stringify({
      address: "0x" + (index + 16).toString(16).padStart(40, "0"),
      amountEth: index % 2 === 0 ? "0.01" : "0.02",
      atMs: dayStart - 86_400_000,
      sessionId: "00000000-0000-4000-8000-" + String(index % 4096).padStart(12, "0"),
    });
    lines.push(line);
    bytes += line.length + 1;
  }
  lines.push(JSON.stringify({ address: A, amountEth: "0.01", atMs: now - 60_000, sessionId: "99999999-8888-4777-8666-555555555555" }));
  lines.push(JSON.stringify({ address: A, amountEth: "0.01", atMs: now - 60_000, sessionId }));
  await writeFile(path, lines.join("\n") + "\n", { mode: 0o600 });

  const store = createFileFundingBudgetStore({ path });
  const budget = createFundingBudget({ ...store, now: () => now });
  const reservation = await budget.reserve({
    addresses: [B],
    identityMode: "required_existing_or_fresh",
    sessionId,
  });
  assert.equal(reservation.totalEth, "0.01");
  // Compacted to the retained set: yesterday's records are gone, today's
  // unrelated record and the same-session record survive, plus the addition.
  const compacted = (await readFile(path, "utf8")).trim().split("\n").map(JSON.parse);
  assert.equal(compacted.length, 3);
  assert.equal(compacted.filter((entry) => entry.atMs >= dayStart).length, 3);
  assert.equal((await lstat(path)).mode & 0o777, 0o600);
  // Same-session cap (0.02) is still enforced on the compacted ledger.
  const second = createFundingBudget({ ...store, now: () => now + 1 });
  await assert.rejects(() => second.reserve({
    addresses: [C],
    identityMode: "required_existing_or_fresh",
    sessionId,
  }));
});

test("compaction keeps prior-day records still inside the rolling hour", async () => {
  const parent = await mkdtemp(join(tmpdir(), "funding-budget-midnight-"));
  await chmod(parent, 0o700);
  const path = join(parent, "ledger.jsonl");
  // 00:30 UTC: the rolling hour reaches back to 23:30 of the previous day.
  const now = Date.UTC(2026, 7, 11, 0, 30, 0);
  const recentLastDay = {
    address: A,
    amountEth: "0.01",
    atMs: Date.UTC(2026, 7, 10, 23, 45, 0),
    sessionId: "99999999-8888-4777-8666-555555555555",
  };
  const staleLastDay = {
    address: B,
    amountEth: "0.01",
    atMs: Date.UTC(2026, 7, 10, 22, 0, 0),
    sessionId: "88888888-7777-4666-8555-444444444444",
  };
  await writeFile(
    path,
    [recentLastDay, staleLastDay].map((entry) => JSON.stringify(entry)).join("\n") + "\n",
    { mode: 0o600 },
  );
  const store = createFileFundingBudgetStore({ path });
  const budget = createFundingBudget({ ...store, now: () => now });
  await budget.reserve({
    addresses: [C],
    identityMode: "required_existing_or_fresh",
    sessionId: "22222222-3333-4444-8555-666666666666",
  });
  const compacted = (await readFile(path, "utf8")).trim().split("\n").map(JSON.parse);
  // The 23:45 record is inside the rolling hour and must survive; the 22:00
  // record is outside both windows and is pruned.
  assert.deepEqual(
    compacted.map((entry) => entry.address).sort(),
    [A, C].sort(),
  );
  // And the retained in-hour record still counts toward the hourly cap on the
  // next reserve: 2 retained + 18 top-up = 20 in-hour; a 21st is rejected.
  const hourTopUp = Array.from({ length: 18 }, (_, index) => ({
    address: "0x" + (index + 64).toString(16).padStart(40, "0"),
    amountEth: "0.01",
    atMs: now - 10_000,
    sessionId: "00000000-0000-4000-8000-" + String(index + 4096).padStart(12, "0"),
  }));
  await writeFile(
    path,
    [...compacted, ...hourTopUp].map((entry) => JSON.stringify(entry)).join("\n") + "\n",
    { mode: 0o600 },
  );
  const second = createFundingBudget({ ...createFileFundingBudgetStore({ path }), now: () => now + 1 });
  await assert.rejects(() => second.reserve({
    addresses: [B],
    identityMode: "required_existing_or_fresh",
    sessionId: "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
  }));
});

test("a malformed ledger line still fails closed rather than being silently dropped", async () => {
  const parent = await mkdtemp(join(tmpdir(), "funding-budget-unreadable-"));
  await chmod(parent, 0o700);
  const path = join(parent, "ledger.jsonl");
  await writeFile(path, '{"address":"0x' + 'f'.repeat(40) + '","amountEth":"9.99","atMs":1,"sessionId":"22222222-3333-4444-8555-666666666666"}\n', { mode: 0o600 });
  const budget = createFundingBudget({ ...createFileFundingBudgetStore({ path }), now: () => 1_000_000 });
  await assert.rejects(() => budget.reserve({
    addresses: [A],
    identityMode: "required_existing_or_fresh",
    sessionId: "22222222-3333-4444-8555-666666666666",
  }));
});

test("a direct store save cannot introduce a fresh 0.02 record", async () => {
  const parent = await mkdtemp(join(tmpdir(), "funding-budget-fresh-"));
  await chmod(parent, 0o700);
  const path = join(parent, "ledger.jsonl");
  const store = createFileFundingBudgetStore({ path });
  assert.deepEqual(await store.load(), []);
  // History may carry 0.02, but the saved suffix is validated by
  // currentRecord: a fresh 0.02 row must be rejected before any write.
  await assert.rejects(() => store.save([{
    address: A,
    amountEth: "0.02",
    atMs: 1_000_000,
    sessionId: "22222222-3333-4444-8555-666666666666",
  }]), /budget is unavailable/);
  assert.equal(await readFile(path, "utf8").catch(() => null), null);
});

test("a ledger without a complete newline-terminated tail fails closed", async () => {
  const parent = await mkdtemp(join(tmpdir(), "funding-budget-partial-"));
  await chmod(parent, 0o700);
  const path = join(parent, "ledger.jsonl");
  const good = JSON.stringify({
    address: A, amountEth: "0.01", atMs: 1,
    sessionId: "22222222-3333-4444-8555-666666666666",
  });
  const budget = () => createFundingBudget({ ...createFileFundingBudgetStore({ path }), now: () => 1_000_000 });
  const reserve = () => budget().reserve({
    addresses: [B],
    identityMode: "required_existing_or_fresh",
    sessionId: "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
  });
  for (const broken of [
    good,              // partial tail: no terminating newline
    `${good}\n\n`,     // trailing blank line
    `${good}\n \n`,    // trailing whitespace line
    `${good}\n${good.slice(0, 40)}`,  // truncated trailing record
  ]) {
    await writeFile(path, broken, { mode: 0o600 });
    await assert.rejects(reserve(), /budget is unavailable/);
  }
});

test("an append that would cross the bounded read size compacts the basis first", async () => {
  const parent = await mkdtemp(join(tmpdir(), "funding-budget-boundary-"));
  await chmod(parent, 0o700);
  const path = join(parent, "ledger.jsonl");
  const now = Date.now();
  const stale = now - 7 * 86_400_000;
  const old = JSON.stringify({
    address: A, amountEth: "0.01", atMs: stale,
    sessionId: "22222222-3333-4444-8555-666666666666",
  }) + "\n";
  const fresh = JSON.stringify({
    address: B, amountEth: "0.01", atMs: now,
    sessionId: "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
  }) + "\n";
  let content = "";
  while (Buffer.byteLength(content) + Buffer.byteLength(fresh) <= 1024 * 1024) {
    content += old;
  }
  const size = Buffer.byteLength(content);
  assert.ok(size <= 1024 * 1024 && size + Buffer.byteLength(fresh) > 1024 * 1024);
  await writeFile(path, content, { mode: 0o600 });
  const budget = createFundingBudget({ ...createFileFundingBudgetStore({ path }), now: () => now });
  await budget.reserve({
    addresses: [B],
    identityMode: "required_existing_or_fresh",
    sessionId: "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
  });
  const landed = await lstat(path);
  assert.ok(landed.size <= 1024 * 1024);
  assert.equal(landed.mode & 0o777, 0o600);
  // The ledger still loads and the reservation survived the compaction.
  assert.deepEqual(await createFileFundingBudgetStore({ path }).load(), [
    { address: B, amountEth: "0.01", atMs: now, sessionId: "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee" },
  ]);
});

test("a ledger beyond the bounded migration read still fails closed", async () => {
  const parent = await mkdtemp(join(tmpdir(), "funding-budget-toolarge-"));
  await chmod(parent, 0o700);
  const path = join(parent, "ledger.jsonl");
  const line = JSON.stringify({
    address: A, amountEth: "0.01", atMs: 1,
    sessionId: "22222222-3333-4444-8555-666666666666",
  }) + "\n";
  const repeats = Math.ceil((1024 * 1024 + line.length) / line.length);
  await writeFile(path, line.repeat(repeats), { mode: 0o600 });
  const budget = createFundingBudget({ ...createFileFundingBudgetStore({ path }), now: () => 1_000_000 });
  await assert.rejects(() => budget.reserve({
    addresses: [B],
    identityMode: "required_existing_or_fresh",
    sessionId: "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
  }), /budget is unavailable/);
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
