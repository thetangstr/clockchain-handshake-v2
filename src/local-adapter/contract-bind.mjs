// sign_agent_contract_bind — the adapter's second (and only other) local tool.
//
// The agent-contract server (clockchain-developer-tools packages/mcp-server,
// src/agent-contract) late-binds a `*` bearer token to a handshake party only
// when the caller proves possession of that party's handshake session key:
// an EIP-191 signature over sha256(canonicalJson(statement)) for the strict
// seven-key `agent-contract.bind/v1` statement, recovering to
// certificate.result.parties[side].sessionKeyAddress. That key is the
// per-session secp256k1 wallet the pinned helper created under
// ${TMPDIR}/.clockchain/handshakes/<sessionId>/<role>/wallet.json — so only
// this adapter's uid can produce the proof, and it must never become a
// generic signing oracle. See the SECURITY section of docs/local-adapter.md.

import { createHash } from "node:crypto";

// --- canonical JSON: byte-for-byte port of the contract server -------------
//
// Port of clockchain-developer-tools packages/mcp-server
// src/agent-contract/canonical.ts canonicalJson/canonicalDigest (object keys
// sorted recursively by UTF-16 code unit, no insignificant whitespace,
// JSON.stringify string/number encoding, undefined/function/symbol object
// members dropped, the same members refused in arrays and at top level).
// Parity is proven by test/fixtures/agent-contract-canonical-digest-vectors.json
// (a verbatim copy of the server's own vectors) — keep this byte-compatible.
// The adapter's own canonicalBytes (src/core/canonical.mjs) is a different,
// stricter profile and is deliberately NOT used for the bind preimage.

export function contractCanonicalJson(value) {
  const canon = (v) => {
    if (v === null) return "null";
    switch (typeof v) {
      case "number":
        if (!Number.isFinite(v)) throw new Error("canonicalJson: non-finite number");
        return JSON.stringify(v);
      case "boolean":
      case "string":
        return JSON.stringify(v);
      case "object": {
        if (Array.isArray(v)) {
          return `[${v.map((item) => {
            if (item === undefined || typeof item === "function" || typeof item === "symbol") {
              throw new Error("canonicalJson: unrepresentable array member");
            }
            return canon(item);
          }).join(",")}]`;
        }
        return `{${Object.keys(v)
          .filter((k) => v[k] !== undefined && typeof v[k] !== "function" && typeof v[k] !== "symbol")
          .sort()
          .map((k) => `${JSON.stringify(k)}:${canon(v[k])}`)
          .join(",")}}`;
      }
      default:
        throw new Error(`canonicalJson: unrepresentable type ${typeof v}`);
    }
  };
  return canon(value);
}

/** sha256 of the contract canonical JSON, `0x`-prefixed lowercase hex. */
export function contractCanonicalDigest(value) {
  return `0x${createHash("sha256").update(contractCanonicalJson(value), "utf8").digest("hex")}`;
}
