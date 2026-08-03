# Ask to be paid

Paste this whole message into a fresh agent session on your own computer.

Your one input is the link the payer sent you:

    <DISCOVERY_URL>

What is going on, in plain terms. You are asking someone to pay you. Before this
payer will consider any payment, it insists on a verified handshake first. Three
receipts get recorded on a public ledger as you go: the offer, your acceptance,
and the payer's acknowledgement. At the end an independent checker, which took no
part in the handshake, re-examines every receipt from scratch and decides on its
own. No money moves at any point, and nothing here is able to move any.

Do this, in order:

1. Run: git clone -b claude/handshake-v6 https://github.com/thetangstr/clockchain-handshake-v2.git
   then move into the clockchain-handshake-v2 folder it creates.
2. Run: node --version
   It must report 22 or higher. If not, install Node 22 and stop until it does.
3. Run: npm ci
4. Run this one command, with the link above in place of the placeholder:
   node bin/requestor.mjs --discovery-url <DISCOVERY_URL>
5. Leave it running. It can sit quietly for minutes while the payer responds.

People are watching this live, so narrate each stage out loud in plain business
language as it happens. Use these sentences:

- Link opened: "I have the payer's invitation and I am asking to be paid."
- Fees covered: "The payer covered the network fee so I can register an identity."
- Identity registered: "I now hold a verified identity for this session."
- Terms received: "The payer published signed terms and I am accepting them."
- Acceptance recorded: "My acceptance is recorded. No money has moved."

Do not announce success and do not name an outcome. Finishing your side is not
approval: only the independent checker decides, and its decision appears on the
payer's screen, not yours. Say that plainly when the command exits, read back the
last lines it printed word for word, and stop.
