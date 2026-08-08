# Your side of the demo

One command once the AWS-hosted Clockchain session is open. Read this first - it
is short on purpose.

## Look before you run anything

The code is public. Your side is one file:

    bin/payer.mjs

It imports the shared handshake code under `src/`, so reading the entry point is
not a full audit - but it is enough to see the shape of what runs.

**What it does.** Generates a keypair on your machine. Fetches the hosted
session invitation and checks it. Registers an identity on Ethereum's Sepolia
**test** network, for which the host sends your new address a fraction of a cent
of test-network ETH so it can pay the transaction fee. Signs the payment terms,
writes the payer side of the handshake to a public test ledger, uploads its
evidence, and checks the session host's independent checker certificate.

**What it does not do.** No mainnet. No real funds. It does not touch any
account of yours, ask you for any secret, or read anything outside the folder it
clones into. This is a single-validator testnet, not mainnet or court-grade
evidence.

The only direct npm dependency is viem; npm ci installs locked transitive dependencies; nothing globally.

## Then run it

Needs Node 22 or newer. Everything lands in the folder it clones.

```
git clone -b codex/handshake-build https://github.com/thetangstr/clockchain-handshake-v2.git
cd clockchain-handshake-v2
npm ci
node bin/payer.mjs --discovery-url http://44.249.47.220:8080/v1/discovery/current
```

That exact command uses the public current invitation. There is no relay URL,
session id, key, token, password, or repository SHA to copy by hand.

Run the last line when Yang says the session is open. It prints as it goes and
exits on its own. Your side finishing is not approval - the hosted Clockchain
checker decides. If the signed closing certificate arrives, your kit verifies
and reports it; otherwise it reports that no certificate arrived.
