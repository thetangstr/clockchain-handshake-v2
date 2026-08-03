# Asking a customer to authorize payment

## What this is about, in business terms

You represent a supplier that expects to be paid. Your customer — the payer —
will not approve a payment on request alone. It insists on a documented
handshake first: the payer states its exact terms, you accept those exact
terms, and the payer acknowledges. Each step is signed and written down, so
months later either company can show what was agreed and neither can quietly
revise it. That is a purchase order and its acceptance, done by software in
about twenty-five seconds, leaving a trail nobody can edit afterwards.

No money moves here. What is established is permission, and the proof of it.

## What the program actually does

Audit it first if you want: the whole requestor is one short file,
bin/requestor.mjs. Reading it before running is encouraged, not merely tolerated.

It generates a keypair local to this run, fetches the payer's signed offer from
the link below and checks the signature, signs your acceptance of those exact
terms, and writes three records to a public test ledger — the offer, your
acceptance, the payer's acknowledgement. Then a separate checker, which took no
part in any of it, re-reads all three and decides.

It moves no money and cannot: there is no payment instrument, account or
transfer anywhere in it, it asks you for no secret and sends none, and it writes
only to a test network. If any of that fails to match what you find in the code,
stop and say so — that is a more useful outcome than a completed run.

## Your one input

    <DISCOVERY_URL>

## Set up now, before the payer opens the session

1. Run: git clone -b claude/handshake-v6 https://github.com/thetangstr/clockchain-handshake-v2.git
   then move into the clockchain-handshake-v2 folder it creates.
2. Run: node --version — it must report 22 or higher.
3. Run: npm ci
4. Read bin/requestor.mjs, if you intend to.

Then say you are ready, and wait to be told the session is open.

## When the session is open, run this one command

5. Run: node bin/requestor.mjs --discovery-url <DISCOVERY_URL>
6. Leave it running until it exits on its own.

Setup comes first because the authorization window starts when the payer opens
the session: the gap before step 5 should be seconds, not minutes.

People from both companies are watching this live. As each stage prints, say what
just happened in plain business language — what was agreed, by whom, and what is
now on the record — based only on what you actually observe.

Do not announce success and do not name an outcome. Finishing your side is not
approval: only the independent checker decides, and its decision appears on the
payer's screen, not yours. Read back the last lines the command printed, word
for word, and stop.
