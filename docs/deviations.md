# Deviation register

Places where the build deliberately differs from the consensus plan
(`.omc/plans/ralplan-clockchain-bilateral-handshake-v2.md`). Each entry says what
the plan asked for, what was done instead, and why. Nothing here is a silent
change: if a deviation is not written down, it is a defect.

D1–D3 were recorded in the plan itself. D4 onward were found during M0.

---

## D1 — the 10-minute anchor window is NOT widened
**Plan/spec:** raise `EXPIRY_WINDOW_MS` (600 000 ms) to ≥ 30 minutes.
**Done instead:** left at exactly 600 000 ms; safety comes from sequencing.
**Why:** `expirySeconds` is a signed canonical field (`descriptor.mjs:22`, checked
at `:398` and `messages.mjs:462`) that feeds `dSession` and therefore every
Clockchain reference id. Changing it invalidates every ported canonical vector and
the three proven live runs' addressing. Instead, all human-paced waiting happens
*before* any anchor exists, and the in-window bound reserves the acknowledgment
write budget (`src/core/window.mjs`).

## D2 — the donor relay is rebuilt, not salvaged
**Plan/spec:** salvage route shapes from `coordination/relay.mjs`.
**Done instead:** rebuild (M1a).
**Why:** the donor relay is 2,294 lines bound to a 3,910-line storage module, with
one `/v1/` route literal. Its two load-bearing behaviours (sub-run identity
binding, per-run mandate selection) are re-encoded as tested invariants instead.

## D3 — `REORDERED` prior art
**Spec claimed:** the code collapses into `ANCHOR_UNVERIFIED`/`BINDING_MISMATCH`.
**Actual:** the donor's aggregate verifier has no such code at all; a working one
exists only in the unported watcher (`scripts/watch-bilateral-session.mjs:415`),
which is the reference for the M1a implementation in `src/verifier/run.mjs`.

---

## D4 — `payer-mandate.mjs` keeps the donor's weaker expiry rule
**Plan:** add a mandate construction guard (≥ 30-minute lifetime).
**Done instead:** the guard lives in `src/core/window.mjs` (`assertMandateLifetime`),
not in `payer-mandate.mjs`.
**Why:** `payer-mandate.mjs` is a **pure port** — byte-faithful, no behavioural
edits — and the donor fixtures it must keep validating use an 11-minute mandate.
v2 enforces the stronger rule where mandates are *constructed*, which is also the
only place that knows the discovery expiry it must outlast.

## D5 — three of the donor's 57 bare `fail()` sites were retagged
**Plan:** "the 57 bare `fail()` call sites are NOT retagged."
**Actual:** three became `MALFORMED` — two in `parseMarker`, one in the canonical-
form check inside `verifyPartyTriple`. All three are input-shape boundaries, which
is precisely the site family the plan assigns to `MALFORMED`.
**Still true:** the `fail()` **default parameter** remains `"FAILED"`, asserted by
test, so no internal verifier error is blamed on the counterparty.
*(Commit 8de4c18 overstated this as "not retagged"; corrected here.)*

## D6 — `repositorySha` is provenance, not the value the kit verifies
**Plan:** the kit verifies `git rev-parse HEAD === discovery.repositorySha`.
**Actual:** `release.json`'s `repositorySha` records the commit the manifest was
measured at. Committing the pin necessarily advances `HEAD` past it, so the value
can never be self-consistent. The discovery document published at session start
reads live `HEAD`; the value the kit verifies for integrity is
`kitManifestDigest`, which excludes `release.json` (and `.omc/`) precisely so that
it survives being committed.
**Affects:** M1a step 9 (discovery generation) must read live `HEAD`.

## D7 — two reason codes added to the frozen set
**Plan:** frozen public set of 14 codes.
**Added:** `REHEARSAL_NOT_AUTHORIZABLE` (a rehearsal sub-run reached the emission
gate) and `REHEARSAL_SUBJECT_MISMATCH` (`verifyRehearsal` was handed a stakeholder
run). Both describe conditions that did not exist when the set was frozen, because
the sub-run gate is a v2 addition. `scripts/check-invariants.sh` now enforces the
set in both directions, so a future unregistered code fails the gate.

## D8 — `src/constants.mjs` added to the port list
**Plan:** port list of 21 modules.
**Actual:** 22. `src/constants.mjs` (11 lines: chain id, ERC-8004 registry address,
RPC and Clockchain URLs) is imported by four ported modules and was not named in
the plan. Discovered by computing the import closure rather than reading the list.
