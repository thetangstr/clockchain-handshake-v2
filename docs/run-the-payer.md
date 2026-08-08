# Your side of the demo

One command, about a minute once the session is open. Read this first - it is
short on purpose.

## Look before you run anything

The code is public. Your side is one file:

    bin/payer.mjs

It imports the shared handshake code under `src/`, so reading the entry point is
not a full audit - but it is enough to see the shape of what runs.

**What it does.** Generates a keypair on your machine. Fetches the host session
invitation and checks it. Registers an identity on Ethereum's Sepolia
**test** network, for which the host sends your new address a fraction of a cent
of test-network ETH so it can pay the transaction fee. Signs the payment terms,
writes the payer side of the handshake to a public test ledger, uploads its
evidence, and checks the host's signed closing certificate.

**What it does not do.** No mainnet. No real funds. It does not touch any
account of yours, ask you for any secret, or read anything outside this repo
checkout. One npm dependency, `viem`, is pinned by lockfile.

## Then run it

Needs Node 22 or newer. This assumes a prepared repo checkout with dependencies
already installed. Git is only needed if you are getting that checkout yourself.
Run this from that checkout:

```
node bin/payer.mjs --discovery-url http://44.249.47.220:8080/v1/discovery/current
```

Run that when Yang says the session is open. It prints as it goes and exits on
its own. Your side finishing is not approval - the host runs the independent
checker. If the signed closing certificate arrives, your kit verifies and
reports it; otherwise it reports that no certificate arrived.
