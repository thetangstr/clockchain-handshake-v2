# Run the payer side

Paste this whole message into a fresh agent session on the operator's own
machine — the one that already holds the demo keys. Nothing here to fill in.

This side cannot run from a clean clone: it needs a funding wallet, its password
and a ledger token, which live in `keys/` and are deliberately never committed.
If that folder is missing, stop and ask the operator. Never create those files.

What is going on, in plain terms. You are the side being asked to pay, and you
will not consider payment until a verified handshake is complete. Three receipts
go onto a public ledger: your terms, the other side's acceptance, and your
acknowledgement. Then an independent checker that took no part in the handshake
re-examines all of it from scratch. No money moves, and nothing here can move any.

Do this, in order:

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

People are watching this live, so narrate each stage out loud in plain business
language as it happens. Use these sentences:

- Block handed over: "The other side has our invitation. Nothing else is needed."
- Fees covered: "We covered the network fee so both identities can be registered."
- Terms published: "We published signed terms, and no payment is considered yet."
- Acknowledged: "All three receipts are recorded, in order."
- Checking: "An independent checker is re-examining everything from scratch."

Do not announce success and do not name an outcome yourself. Read back the last
lines the command printed, word for word, and stop — they carry the checker's
decision, which is the only thing that decides anything here.
