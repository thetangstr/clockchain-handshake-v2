# Authorizing a customer's payment request

## What this is about, in business terms

You represent the side being asked to pay. Do not approve payment on request
alone. This run asks you to publish exact terms, wait for the requestor to
accept those exact terms, then acknowledge that acceptance. Each step is signed
and written down so the agreement can be checked later.

No money moves here. What is established is permission, and the proof of it.

## What the program actually does

Audit it before running if you want to. bin/payer.mjs is the entry point, but it
imports shared code under src/. That reachable set is the audit surface.

It generates a keypair local to this run, fetches the hosted Clockchain session
invitation from the link below and checks it, registers a Sepolia test-network
identity using gas supplied by the host, signs your payment terms, records the
payer side of the handshake, uploads evidence, and checks the host's signed
closing certificate.

This is a single-validator testnet, not mainnet or court-grade evidence. It
does not touch any bank, card, mainnet wallet, real account, or secret of yours.
If the code appears to do more than that, stop and say so.

## Your one input

    <DISCOVERY_URL>

## Optional: what a bare machine needs first

Skip this if you already have a normal developer setup.

- git, and Node 22 or higher (npm ships with Node)
- outbound access to github.com, registry.npmjs.org, mcp.clockchain.network,
  ethereum-sepolia-rpc.publicnode.com, and 44.249.47.220 on port 8080
- permission to leave one command running for a few minutes

Exactly one package is installed, viem, and nothing is installed globally.

## Set up now, before the host opens the session

1. Run: git clone -b claude/handshake-v6 https://github.com/thetangstr/clockchain-handshake-v2.git
   then move into the clockchain-handshake-v2 folder it creates.
2. Run: node --version — it must report 22 or higher.
3. Run: npm ci
4. Read the code, if you intend to — bin/payer.mjs and what it imports.

Then say you are ready, and wait to be told the session is open.

## When the session is open, run this one command

5. Run: node bin/payer.mjs --discovery-url <DISCOVERY_URL>
6. Leave it running until it exits on its own.

Setup first simply keeps the live part short. The hosted Clockchain session will
wait up to 45 minutes for both sides, so take the time you need on steps 1 to 4.

Do not announce success and do not name an outcome. Finishing your side is not
approval: only the independent checker decides. If the signed certificate
arrives, read back the last lines the command printed, word for word, and stop.
