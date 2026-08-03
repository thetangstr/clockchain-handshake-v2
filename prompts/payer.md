# Run the payer side

Paste this whole message into a fresh agent session **on the operator's own
machine** — the computer that already holds the demo keys.

This side cannot be run from a clean clone. It needs the funding wallet, its
password and a ledger token, which live in `keys/` and are deliberately never
committed. That is why there is no repository to fetch here: if `keys/` is
missing on this machine, stop and ask the operator. Never create those files
yourself.

What is going on, in plain terms. You are the side being asked to pay, and you
will not consider payment until a verified handshake is complete. Three receipts
go onto a public ledger: your terms, the other side's acceptance, and your
acknowledgement. Then an independent checker that took no part in the handshake
re-examines all of it from scratch. No money moves, and nothing here can move any.

Do this, in order:

1. Move into the existing checkout: cd ~/Documents/Projects/handshake
2. Run: node --version
   It must report 22 or higher. If not, install Node 22 and stop until it does.
3. Confirm all three of keys/funding-wallet.json, keys/funding.password and
   keys/clockchain.token exist. If any is missing, stop and ask the operator.
4. Run this exactly, as one command:

       CLOCKCHAIN_FUNDING_PASSWORD_FILE="$PWD/keys/funding.password" \
         node bin/operator.mjs --relay-url http://44.249.47.220:8080

5. Within a few seconds it prints a block fenced by `======` lines. That block is
   the complete message for the person asking to be paid. Send them that whole
   block, unedited, and send them nothing else — no key, no token, no session id.
6. It then prints a monitor link. Hand that to the operator for the screen.
7. Leave the command running. It can sit quietly for many minutes while the other
   side reads its prompt and sets up; that is expected, not a hang.

The link inside the block never changes between runs:

    http://44.249.47.220:8080/v1/discovery/current

So if the block does not appear, the other side can still be sent that line
together with the stakeholder prompt published at
https://clockchain-research.vercel.app/handshake/claude-v6

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
