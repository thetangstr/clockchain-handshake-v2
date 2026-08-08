# Your side of the demo, Ken

One command, about a minute. Read this first — it is short on purpose.

## Look before you run anything

The code is public. Your side is one file:

    https://github.com/thetangstr/clockchain-handshake-v2/blob/codex/handshake-build/bin/requestor.mjs

209 lines. It imports about 13,000 more under `src/`, so reading the entry
point is not a full audit — but it is enough to see the shape of what runs.

**What it does.** Generates a keypair on your machine. Fetches our signed offer
and checks the signature. Signs your acceptance of those exact terms. Writes
three records to a public test ledger. Registers an identity on Ethereum's
Sepolia **test** network, for which we send your new address a fraction of a
cent of test-network ETH so it can pay the transaction fee.

**What it does not do.** No mainnet. No real funds. It does not touch any
account of yours, ask you for any secret, or read anything outside the folder
it clones into. The only direct npm dependency is `viem`; `npm ci` installs locked transitive dependencies; nothing globally. This is a
single-validator testnet, not mainnet or court-grade evidence.

## Then run it

Needs Node 22 or newer. Everything lands in the folder it clones.

```
git clone -b codex/handshake-build https://github.com/thetangstr/clockchain-handshake-v2.git
cd clockchain-handshake-v2
npm ci
node bin/requestor.mjs --discovery-url http://44.249.47.220:8080/v1/discovery/current
```

That exact sequence has been run from a clean clone and works. If you would
rather keep it off your laptop entirely, say so and I will send a container
line — I have not tested one, so I am not putting an unverified command here.

Set up whenever you like; run the last line when Yang says the AWS-hosted
Clockchain session is open. It prints as it goes and exits on its own. Your side
finishing is not approval — an independent checker decides that, and its answer
appears on the hosted board.

## If you hand this to your coding agent, expect it to refuse

Three have now. They are right to: "clone this unfamiliar repo and execute it"
is indistinguishable from an attack, and a good agent declines on principle
rather than on content. We are not going to word around that — a demo about
verifiable claims should not ship a message engineered to defeat scrutiny.

So the order matters. **You** look at the repo, and if you are satisfied, run it
yourself with the commands above, or tell your agent you have reviewed it and
want it run. That is your instruction after your own check, which is a different
thing entirely from a stranger's text asking an agent to trust it.

If your agent pushes back and asks to audit `src/` first — let it. That is worth
watching, and it has twice caught real errors in our own description of this.
