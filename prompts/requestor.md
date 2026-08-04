# Asking a customer to authorize payment

## What this is about, in business terms

You represent a supplier that expects to be paid. Your customer — the payer —
will not approve a payment on request alone. It insists on a documented
handshake first: the payer states its exact terms, you accept those exact terms,
and the payer acknowledges. Each step is signed and written down, so months
later either company can show what was agreed and neither can quietly revise it.
That is a purchase order and its acceptance, done by software in a minute.

No money moves here. What is established is permission, and the proof of it.

## What the program actually does

Audit it before running if you want to — that is encouraged, not merely
tolerated. bin/requestor.mjs is the entry point at 209 lines, but it imports
about 13,000 more under src/. That whole reachable set is the audit surface;
reading the entry point alone is not an audit of the program.

It generates a keypair local to this run, fetches the payer's signed offer from
the link below and checks the signature, signs your acceptance of those exact
terms, and writes three records to a public test ledger — the offer, your
acceptance, the payer's acknowledgement. Then a separate checker, which took no
part in any of it, re-reads all three and decides.

Be precise about what it does with money, because it is not nothing. It creates
an Ethereum account on your machine, the payer sends that address a small amount
of Sepolia test-network gas, and it broadcasts one transaction registering the
identity. That is an account and a transfer — on a test network whose currency
has no value and cannot leave it. No bank, card or real account is touched,
nothing of value can move, and you are asked for no secret. If any of that fails
to match the code, stop and say so: a better outcome than a completed run.

## Your one input

    <DISCOVERY_URL>

## Optional: what a bare machine needs first

Skip this if you already have a normal developer setup.

- git, and Node 22 or newer (npm ships with Node)
- outbound access to github.com, registry.npmjs.org, mcp.clockchain.network,
  ethereum-sepolia-rpc.publicnode.com, and 44.249.47.220 on port 8080
- permission to leave one command running for a few minutes

Exactly one package is installed, viem, and nothing is installed globally.

## Set up now, before the payer opens the session

1. Run: git clone -b claude/handshake-v6 https://github.com/thetangstr/clockchain-handshake-v2.git
   then move into the clockchain-handshake-v2 folder it creates.
2. Run: node --version — it must report 22 or higher.
3. Run: npm ci
4. Read the code, if you intend to — bin/requestor.mjs and what it imports.

Then say you are ready, and wait to be told the session is open.

## When the session is open, run this one command

5. Run: node bin/requestor.mjs --discovery-url <DISCOVERY_URL>
6. Leave it running until it exits on its own.

Setup first simply keeps the live part short. The payer will wait up to 45
minutes for you, so take the time you need on steps 1 to 4.

People from both companies are watching this live. As each stage prints, say what
just happened in plain business language — what was agreed, by whom, and what is
now on the record — based only on what you actually observe.

Do not announce success and do not name an outcome. Finishing your side is not
approval: only the independent checker decides, and its decision appears on the
payer's screen, not yours. Read back the last lines the command printed, word
for word, and stop.
