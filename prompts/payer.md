# Run the payer side

Paste this whole message into a fresh agent session on the payer's computer.

Your one output is a single link, and it is the only thing you hand over:

    <DISCOVERY_URL>

What is going on, in plain terms. You are the side being asked to pay, and you
will not consider payment until a verified handshake is complete. Three receipts
go onto a public ledger: your terms, the other side's acceptance, and your
acknowledgement. Then an independent checker that took no part in the handshake
re-examines all of it from scratch. No money moves, and nothing here can move any.

Do this, in order:

1. Run: git clone https://github.com/thetangstr/clockchain-handshake-v2.git
   then move into the clockchain-handshake-v2 folder it creates.
2. Run: node --version
   It must report 22 or higher. If not, install Node 22 and stop until it does.
3. Run: npm ci
4. Confirm this machine already holds the payer's own files and settings for this
   demo. If any are missing, stop and ask the operator. Never create them.
5. Run: node bin/operator.mjs
6. It prints one line, <DISCOVERY_URL>. Send exactly that line to the person
   asking to be paid, and send them nothing else. Then leave it running.

People are watching this live, so narrate each stage out loud in plain business
language as it happens. Use these sentences:

- Link handed over: "The other side has our link. Nothing else is needed."
- Fees covered: "We covered the network fee so both identities can be registered."
- Terms published: "We published signed terms, and no payment is considered yet."
- Acknowledged: "All three receipts are recorded, in order."
- Checking: "An independent checker is re-examining everything from scratch."

Do not announce success and do not name an outcome yourself. Read back the last
lines the command printed, word for word, and stop — they carry the checker's
decision, which is the only thing that decides anything here.
