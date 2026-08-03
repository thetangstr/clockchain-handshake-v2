# Running the demo

One page. Read it once before the dry run, keep it open during the demo.

**What the audience is about to see:** two AI agents, on two different machines,
negotiate permission to make a payment. They never trust each other and they never
trust the network between them. Every step is recorded on a public ledger, and at
the end an independent checker re-reads all the evidence from scratch and decides.
**No money moves at any point.**

---

## 1. Before you start (5 minutes)

Run these three checks. If any fails, fix it before the audience is in the room.

```bash
cd ~/Documents/Projects/handshake
```

**Check 1 — the relay is alive.** This is the mailbox the two agents talk through.

```bash
curl -s http://44.249.47.220:8080/healthz
```

Expect: `{"ok":true,"paymentMoved":false,"sessions":N}`
If it fails, see *Relay is down* in Troubleshooting.

**Check 2 — the treasury can pay for gas.**

```bash
CLOCKCHAIN_FUNDING_PASSWORD_FILE="$PWD/keys/funding.password" node -e '
const { openFundingWallet } = await import("./src/core/funding/wallet.mjs");
const w = await openFundingWallet({ keystorePath: process.env.PWD + "/keys/funding-wallet.json" });
console.log("treasury unlocked:", w.metadata.fundingAddress);'
```

Expect: `treasury unlocked: 0x157a377e4181f3f87c7f6efed5ddc340ccc00dce`

**Check 3 — we can write to the ledger.**

```bash
ls -l keys/clockchain.token
```

Expect a file. If it is missing or the run later fails with a rate-limit message,
see *Cannot get a ledger token* in Troubleshooting.

---

## 2. The run (about 4 minutes)

**You do not need to type any of this.** Ask Claude Code (in the session you're
already in) to "start the operator" and it runs the command and watches the output.
The commands are written out only so you can see what is happening, and so someone
else could run it without me.

Your actual job during the demo is three things: hand the stakeholder one block,
read the narration in section 3, and run the live check in section 5.

### Terminal 1 — the operator

```bash
cd ~/Documents/Projects/handshake
CLOCKCHAIN_FUNDING_PASSWORD_FILE="$PWD/keys/funding.password" \
  node bin/operator.mjs --relay-url http://44.249.47.220:8080
```

It prints a **complete, ready-to-send block**: the stakeholder's prompt with this
run's URL already filled in. It looks like this:

```
======================================================================
SEND THIS WHOLE BLOCK TO THE STAKEHOLDER. They paste it as-is —
there is nothing for them to fill in or edit.
======================================================================

# Ask to be paid
...
    http://44.249.47.220:8080/v1/discovery/1d943555-...
...
```

**Copy that whole block and send it however you like** — Slack, email, chat. The
stakeholder pastes it into a fresh agent session and does nothing else. They never
type a URL, substitute a placeholder, or receive a key, password, or session id.

(If you'd rather send just the link, it's the URL inside the block — but sending
the whole block is one less thing to go wrong in front of an audience.)

**Put the audience page on the projector.** Same session id, different path:

```
http://44.249.47.220:8080/monitor/<SESSION_ID>
```

It updates itself as the run proceeds: a plain-English timeline, "no money has
moved" in every state, and the three receipts as they land. The verdict box stays
empty until the independent verifier has actually decided — it cannot show an
outcome early, by construction.

### Terminal 2 — the stakeholder

On *their* machine: paste the block you sent into a fresh Claude Code / Codex /
Hermes session. That is their entire involvement.

To drive it yourself in a dry run, the same thing by hand:

```bash
ssh -i ~/.ssh/handshake-relay.pem ubuntu@44.249.47.220 \
  "cd /opt/handshake/app && node bin/requestor.mjs --discovery-url <THE_URL>"
```

Then watch both terminals.

---

## 3. What to say while it runs

The steps appear in this order. The sentence in the right column is what to say out
loud — it is also roughly what the screen prints, so you can just read along.

| What appears | What to say |
|---|---|
| *Starting a payment-authorization session* | "A session is open. Nothing has been agreed and no money will move." |
| *A requestor appeared and asked to be paid* | "That's the other agent, on a different machine. It just asked to be paid." |
| *Covering testnet gas... identity #NNNN* | "Each side registers a fresh public identity. We pay the network fee for that — that's the only money involved, and it's testnet." |
| *Signed payment terms published* | "The payer publishes its terms, signed. It will not just pay on request." |
| *The requestor submitted a signed payment request* | "The other side signs its own request against those exact terms. We can't forge that — we don't have its key." |
| *Opening the authorization window* | "Now the clock starts. Everything from here is machine-speed." |
| *All three steps are recorded* | "Proposed, accepted, acknowledged — three receipts on the ledger, in order." |
| *The requestor's evidence has arrived* | "Each side sends its own evidence. The mailbox in between can't read or change it." |
| *An independent verifier is re-checking* | "Now a separate process re-reads everything from scratch. It trusts nothing that came before." |
| **Verifier outcome: AUTHORIZED** | "Authorized. And note what that means: permission was established and proven — no payment was made." |

Then point at the last three lines:

```
  proposal        block 2705531  ledger 5b46121a-...
  acceptance      block 2705552  ledger 9a8b271c-...
  acknowledgment  block 2705574  ledger d958486c-...
```

**"Anyone can check these. Watch."** — and run the next section live.

---

## 4. The moment that lands: prove it to a skeptic

This is the strongest part of the demo. Do it live.

```bash
node -e '
const { createMcpClient } = await import("./src/core/clockchain.mjs");
const { readFile } = await import("node:fs/promises");
const token = (await readFile("keys/clockchain.token","utf8")).trim();
const c = createMcpClient({ token });
for (const h of [2705531, 2705552, 2705574]) {
  const b = await c.getBlock({ height: h });
  console.log("block", b.blockHeight, "recorded at", b.blockTime);
}'
```

Substitute the block numbers your run printed. Say:

> "These block numbers go up, and the timestamps go up. That ordering *is* the
> claim — the payer proposed before the requestor accepted, and the requestor
> accepted before the payer acknowledged. You don't have to take my word for it;
> that's a public read anyone in this room could run."

---

## 5. If something goes wrong

Every failure prints a plain sentence and a named reason. **A stopped run is not a
broken demo** — it is the system refusing to claim something it cannot prove.
Say that out loud; it is the actual point.

| It says | What happened | What to do |
|---|---|---|
| `EXPIRED` | The 600-second window closed before all three steps finished | Say "it refused to certify a run it couldn't complete in time." Start a fresh run. |
| `MISSING` | Evidence never arrived from the other side | Check the stakeholder's terminal for an error. Rerun. |
| `RENDEZVOUS_UNAVAILABLE` | The ledger is unreachable | Do not start a run. See below. |
| `MALFORMED` | Something arrived in the wrong shape | Rerun. If it repeats, use the fallback in section 6. |
| `ROLE_ALREADY_BOUND` | Two requestors tried to join one session | Start a fresh session; one stakeholder per session. |

**Relay is down.**

```bash
ssh -i ~/.ssh/handshake-relay.pem ubuntu@44.249.47.220 \
  "sudo systemctl restart handshake-relay && sleep 2 && curl -s localhost:8080/healthz"
```

**Cannot get a ledger token.** Token minting is rate-limited to 10/hour per IP, and
rehearsals burn that quota. The relay machine has its own quota:

```bash
ssh -i ~/.ssh/handshake-relay.pem ubuntu@44.249.47.220 \
  "cd /opt/handshake/app && node -e 'const M=await import(\"./src/core/clockchain.mjs\");process.stdout.write(await M.mintDemoToken({}))'" \
  > keys/clockchain.token && chmod 600 keys/clockchain.token
```

**The ledger itself is down.** Don't start. Show the receipts from a previous run
(`runs/*.json`) and re-verify those live using section 4 — reads usually work even
when writes are throttled. Reschedule the live segment.

---

## 6. Fallback: run the whole thing on one machine

If the two-machine path misbehaves and you need a guaranteed result:

```bash
CLOCKCHAIN_FUNDING_PASSWORD_FILE="$PWD/keys/funding.password" \
  node scripts/run-local-demo.mjs
```

Same protocol, same real ledger, same independent verifier, both roles in one
process. It is a weaker story (you can't say "two machines") but it is the same
proof. Takes about 3 minutes.

---

## 7. Questions you will get, and honest answers

**"Did money move?"**
No. Never. Every record says so explicitly. The only funds involved are testnet
coins covering the network fee to register identities.

**"So what was actually authorized?"**
Permission, not payment. The payer agreed terms, the requestor accepted those exact
terms, the payer acknowledged, and an independent checker confirmed all three
happened in order and match. That's an audit trail for a decision.

**"Couldn't you have faked this?"**
The two sides hold different keys on different machines. The operator cannot
produce the requestor's signature — it never has that key. And the receipts are on
a ledger you can read yourself.

**"Is this production ready?"**
No, and I'd be wary of anyone who said yes. This is a single-validator testnet, not
mainnet. It's a demonstration that the evidence trail works, not a hardened system.

**"What if a step fails?"**
It stops and says why, in plain language, with a named reason. It never guesses and
never reports success it cannot prove. You saw the vocabulary in section 5.

**"Why is there a server in the middle if they don't trust each other?"**
It's a mailbox, nothing more. It never checks a signature and holds no authority —
it just moves sealed envelopes so neither machine has to accept incoming
connections. Tampering would be detected immediately, because everything that
matters is signed and anchored.

---

## 8. What this demo does and does not prove

**Does:** two independent agents can establish and prove mutual authorization, with
every step independently verifiable by a third party who trusts neither of them.

**Does not:** move money, run on mainnet, provide legal or court-grade evidence, or
survive a determined adversary. It is a testnet demonstration of an evidence trail.

Being straight about this is not a weakness in the pitch. The entire subject is
verifiable claims — overclaiming here would undercut the point.
