import { readFile } from "node:fs/promises";
import { createPublicClient, http } from "viem";
import { sepolia } from "viem/chains";
const R = "/Users/Kailor/Documents/Projects/handshake";
const { verifyBilateralAuthorization } = await import(`${R}/src/core/verdict.mjs`);
const { createMcpClient } = await import(`${R}/src/core/clockchain.mjs`);
const { ERC8004_ABI } = await import(`${R}/src/core/registration.mjs`);
const { RPC_URL } = await import(`${R}/src/core/constants.mjs`);

const session = JSON.parse(await readFile(`${R}/runs/session-994701ab-18e5-4a54-97e3-41376f4cf8b8.json`, "utf8"));
const token = (await readFile(`${R}/keys/clockchain.token`, "utf8")).trim();
const pub = createPublicClient({ chain: sepolia, transport: http(RPC_URL) });

console.log("An independent verifier is re-checking every piece of evidence from scratch.\n");
const verdict = await verifyBilateralAuthorization({
  clockchain: createMcpClient({ token }),
  descriptorEnvelope: session.descriptorEnvelope,
  mandateEnvelope: session.mandateEnvelope,
  ownerOf: ({ agentId, registry }) =>
    pub.readContract({ abi: ERC8004_ABI, address: registry, args: [BigInt(agentId)], functionName: "ownerOf" }),
  payerDirectory: session.payerDirectory,
  payeeDirectory: "/tmp/collected/payee",
  requestEnvelope: session.requestEnvelope,
  repositoryPublicKeyResolver: async () => session.repositoryPublicKey,
});
console.log("Verifier outcome:", verdict.outcome);
console.log("No money moved:", verdict.paymentMoved === false);
for (const t of verdict.transitions ?? []) console.log(`  ${t.kind}  block ${t.blockHeight}  ledger ${t.ledgerId}`);
