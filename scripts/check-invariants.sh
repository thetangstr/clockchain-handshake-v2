#!/usr/bin/env bash
# Structural invariants that a unit test cannot express, because they are claims
# about the whole tree rather than about one module's behaviour.
#
# Every check prints what it scanned, so a passing run is evidence rather than a
# silent green. Exits non-zero on any violation.
#
#   bash scripts/check-invariants.sh            # PENDING codes are informational
#   bash scripts/check-invariants.sh --strict   # PENDING codes are failures
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1

STRICT=0
[ "${1:-}" = "--strict" ] && STRICT=1
FAILURES=0
pass() { printf 'PASS  %s\n' "$1"; }
fail() { printf 'FAIL  %s\n' "$1"; FAILURES=$((FAILURES + 1)); }
info() { printf '      %s\n' "$1"; }

printf '\n== 1. AUTHORIZED containment ==\n'
# The literal may appear only at sites that are allowlisted BY NAME with a reason.
# Anything else means a component other than the verifier can speak the verdict.
#   src/core/verdict.mjs       the emission itself and its publication validator
#   src/core/evidence.mjs      AUTHORIZING_WORD_PATTERN — a BAN pattern, not an emission
#   src/monitor/**             display maps, rendered only from the signed publication
#   test/**                    tests
UNEXPECTED=$(grep -rl 'AUTHORIZED' src bin scripts 2>/dev/null \
  | grep -v '^src/core/verdict.mjs$' \
  | grep -v '^src/core/evidence.mjs$' \
  | grep -v '^src/monitor/' \
  | grep -v '^scripts/check-invariants.sh$' || true)
info "scanned: src/ bin/ scripts/"
if [ -n "$UNEXPECTED" ]; then
  fail "the AUTHORIZED literal appears outside the allowlist:"
  printf '        %s\n' $UNEXPECTED
else
  pass "AUTHORIZED appears only at allowlisted sites"
fi

# Exactly one place may ASSIGN the verdict outcome.
EMISSIONS=$(grep -c 'outcome: "AUTHORIZED"' src/core/verdict.mjs 2>/dev/null || echo 0)
if [ "$EMISSIONS" = "1" ]; then
  pass "exactly one emission site (src/core/verdict.mjs)"
else
  fail "expected exactly 1 emission site, found $EMISSIONS"
fi

# And it must be gated on the signed mandate's sub-run.
if grep -q 'subjectRun !== "stakeholder"' src/core/verdict.mjs 2>/dev/null; then
  pass "the emission is gated on subjectRun from the signed mandate"
else
  fail "the subjectRun gate is missing from the emission site"
fi

printf '\n== 2. No OS credential store ==\n'
# A locked macOS keychain killed a prior live run after every protocol step had
# already succeeded, and made the demo un-runnable on a server.
KEYCHAIN=$(grep -rniE 'find-generic-password|keychain|keytar|dpapi' src bin scripts 2>/dev/null \
  | grep -v 'check-invariants.sh' || true)
info "scanned: src/ bin/ scripts/ for find-generic-password|keychain|keytar|dpapi"
if [ -n "$KEYCHAIN" ]; then
  fail "OS credential-store reference found:"
  printf '        %s\n' "$KEYCHAIN"
else
  pass "no OS credential-store reference; secrets come from 0600 files or env only"
fi

printf '\n== 3. Human-paced wait sweep ==\n'
# Catch a NEW short bound on a HUMAN-paced wait. Machine-paced bounds are
# legitimately short and are allowlisted BY NAME with the reason:
#   clockchain.mjs HTTP/rate-limit bounds  — per-request, not per-handshake-step
#   MIN_POLL_INTERVAL_MS / MAX_POLL_DURATION_MS / WRITE_RETRY_BACKOFF_MS — runner internals
#   ACK_WRITE_BUDGET_MS / MIN_USABLE_POLL_MS — in-window reservation arithmetic
#   EXPIRY_WINDOW_MS — the signed 600s protocol constant (deliberately unchanged)
#   MAX_COMPLETION_DEADLINE_MS — per-call completion poll; the 120s term inside the
#     223.5s single-write ceiling that ACK_WRITE_BUDGET_MS reserves against
ALLOW='DEFAULT_REQUEST_TIMEOUT_MS|MAX_CONFIGURED_TIMEOUT_MS|MAX_RETRY_AFTER_MS|MAX_BACKOFF_DELAY_MS|MAX_TOTAL_RETRY_WAIT_MS|RATE_LIMIT_FLOOR_WAIT_MS|MIN_POLL_INTERVAL_MS|MAX_POLL_DURATION_MS|WRITE_RETRY_BACKOFF_MS|ACK_WRITE_BUDGET_MS|MIN_USABLE_POLL_MS|EXPIRY_WINDOW_MS|HUMAN_PACED_MINIMUM_MS|MAX_COMPLETION_DEADLINE_MS'
SHORT=$(grep -rnE '^(export )?const [A-Z_]*(TIMEOUT|DEADLINE|WINDOW|WAIT|POLL|EXPIR)[A-Z_]*_MS *=' src 2>/dev/null \
  | grep -vE "$ALLOW" || true)
info "scanned: src/ for (TIMEOUT|DEADLINE|WINDOW|WAIT|POLL|EXPIR)*_MS constants"
info "allowlisted machine-paced bounds: 14 names (see script comments for why)"
if [ -n "$SHORT" ]; then
  fail "unrecognised wait constant — classify it as human- or machine-paced:"
  printf '        %s\n' "$SHORT"
else
  pass "no unclassified wait constant"
fi

printf '\n== 4. Reason-code emission sites ==\n'
# Every frozen public code must be emittable somewhere, or a documented failure
# mode cannot actually be reported.
PENDING=0
for CODE in RENDEZVOUS_UNAVAILABLE EXPIRED MISSING DUPLICATE REORDERED MALFORMED \
            AMBIGUOUS_WRITE BINDING_MISMATCH ANCHOR_UNVERIFIED ROLE_ALREADY_BOUND \
            RATE_BLOCKED AMOUNT_UNRESOLVED FUNDING_REPLAYED FAILED; do
  if grep -rq "\"$CODE\"" src 2>/dev/null; then
    printf '      %-22s emitted\n' "$CODE"
  else
    case "$CODE" in
      REORDERED)
        printf '      %-22s PENDING (M1a: src/verifier/run.mjs order check)\n' "$CODE"
        PENDING=$((PENDING + 1)) ;;
      RENDEZVOUS_UNAVAILABLE|ROLE_ALREADY_BOUND|RATE_BLOCKED)
        printf '      %-22s PENDING (M1a: relay client)\n' "$CODE"
        PENDING=$((PENDING + 1)) ;;
      FUNDING_REPLAYED)
        printf '      %-22s PENDING (M1a: funding journal refusal path)\n' "$CODE"
        PENDING=$((PENDING + 1)) ;;
      *)
        fail "$CODE has no emission site and no milestone that owns it" ;;
    esac
  fi
done
if [ "$PENDING" -gt 0 ]; then
  if [ "$STRICT" = "1" ]; then
    fail "$PENDING reason code(s) still pending (--strict)"
  else
    info "$PENDING code(s) pending, each owned by a named later milestone"
  fi
else
  pass "every frozen reason code has an emission site"
fi

printf '\n== 5. Single version-identity source ==\n'
# Identity lives in release.json and is written only by release-pin.mjs.
PINS=$(grep -rlE '"repositorySha"[[:space:]]*:[[:space:]]*"[0-9a-f]{40}"' src bin scripts release.json 2>/dev/null \
  | grep -v '^release.json$' || true)
info "scanned: src/ bin/ scripts/ release.json for hardcoded 40-hex shas"
if [ -n "$PINS" ]; then
  fail "a commit sha is pinned outside release.json:"
  printf '        %s\n' "$PINS"
else
  pass "release.json is the only pin source"
fi

printf '\n== 6. paymentMoved ==\n'
MOVED=$(grep -rnE '"?paymentMoved"?[[:space:]]*:[[:space:]]*true' src bin scripts 2>/dev/null || true)
info "scanned: src/ bin/ scripts/"
if [ -n "$MOVED" ]; then
  fail "paymentMoved is set true outside test fixtures:"
  printf '        %s\n' "$MOVED"
else
  pass "paymentMoved is never true in shipped code"
fi

printf '\n== 7. Pure-port byte fidelity ==\n'
# The pure ports must still differ from the donor only in import specifiers.
if [ -d /Users/Kailor/conductor/workspaces/clockchain-handshake/riyadh-v3 ]; then
  if node scripts/port-pure.mjs --check >/tmp/port-check.txt 2>&1; then
    pass "all 16 pure modules still byte-faithful to the donor"
    info "$(tail -1 /tmp/port-check.txt)"
  else
    fail "a pure port has drifted from the donor:"
    sed 's/^/        /' /tmp/port-check.txt
  fi
else
  info "donor not present on this machine; skipping byte-fidelity check"
fi

printf '\n'
if [ "$FAILURES" -gt 0 ]; then
  printf 'RESULT: %d check(s) FAILED\n\n' "$FAILURES"
  exit 1
fi
printf 'RESULT: all structural invariants hold\n\n'
