// roleAlreadySeated is the guard that lets a payer kit and a requestor kit share
// one session without knocking each other out. It must be role-aware: the
// original requestor guard tripped on ANY identity_ready, which was correct only
// while the requestor was the sole kit posting one. The moment a payer kit posts
// its own identity_ready, a role-blind guard makes every requestor abort against
// the payer's mere presence -- these tests pin that it does not.
import assert from "node:assert/strict";
import test from "node:test";

import { roleAlreadySeated } from "../src/roles/session.mjs";

const requestorSeat = { kind: "identity_ready", role: "requestor", seq: "1" };
const payerSeat = { kind: "identity_ready", role: "payer", seq: "1" };
const otherTraffic = { kind: "funding_record", role: "payer", seq: "2" };

test("an empty or missing message list seats nobody", () => {
  assert.equal(roleAlreadySeated([], "requestor"), false);
  assert.equal(roleAlreadySeated(undefined, "requestor"), false);
  assert.equal(roleAlreadySeated(null, "payer"), false);
});

test("a role sees only its OWN seat as taken", () => {
  // The whole point: the payer's presence must not lock out the requestor.
  assert.equal(roleAlreadySeated([payerSeat], "requestor"), false);
  assert.equal(roleAlreadySeated([requestorSeat], "payer"), false);
  // …and each still sees its own.
  assert.equal(roleAlreadySeated([requestorSeat], "requestor"), true);
  assert.equal(roleAlreadySeated([payerSeat], "payer"), true);
});

test("with both kits seated, each correctly sees itself taken and not the other's role", () => {
  const both = [payerSeat, requestorSeat, otherTraffic];
  assert.equal(roleAlreadySeated(both, "requestor"), true);
  assert.equal(roleAlreadySeated(both, "payer"), true);
});

test("only identity_ready counts as a seat, not other traffic from that role", () => {
  // A payer that has posted a funding_record but no identity_ready is not
  // seated as a payer -- seating is claimed by identity_ready alone.
  assert.equal(roleAlreadySeated([otherTraffic], "payer"), false);
});

test("a second agent of the same role is what actually trips it", () => {
  // The regression that motivated the original guard: two requestors.
  const firstRequestorAlreadyThere = [requestorSeat];
  assert.equal(
    roleAlreadySeated(firstRequestorAlreadyThere, "requestor"),
    true,
    "a second requestor must see the first one's seat and stop",
  );
});
