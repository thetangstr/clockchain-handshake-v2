# Run the payer side

Paste this whole message into a fresh agent session on the operator's own
machine — the one that already holds the demo keys. Nothing here to fill in.

## What you need before starting

This side cannot run from a clean clone: it needs a funding wallet, its password
and a ledger token, which live in `keys/` and are deliberately never committed.
If that folder is missing, stop and ask the operator. Never create those files.

## What is going on

You are the side being asked to pay, and you will not consider payment until a
verified handshake is complete. Three receipts go onto a public ledger: your
terms, the other side's acceptance, and your acknowledgement. Then an
independent checker that took no part in the handshake re-examines all of it
from scratch. No money moves, and nothing here can move any.

## Do this, in order

1. Move into the existing checkout: cd ~/Documents/Projects/handshake
2. Run: node --version — it must report 22 or higher; stop if it does not.
3. Run: npm run preflight — all four checks must say OK. If any says FAIL,
   stop and read it out to the operator.
4. Run: npm run demo
5. It prints a block fenced by ====== lines. Send that whole block to the person
   asking to be paid, unedited, and send them nothing else — no key, no token,
   no session id. It also prints a monitor link; give that to the operator.
6. Leave the command running. It can sit quietly for minutes while the other
   side sets up, and that is expected, not a hang.

## While it runs

People are watching this live. As each stage prints, say what just happened in
plain business language — what was published, what the other side did, and what
is now on the record — based only on what you actually observe. Do not read from
a script; describe what is on the screen.

Do not announce success and do not name an outcome yourself. Read back the last
lines the command printed, word for word, and stop — they carry the checker's
decision, which is the only thing that decides anything here.
