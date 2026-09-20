// Node-version preflight for the stdio entry. bin/clockchain-local-adapter.mjs
// imports this module (and constants.mjs) statically, runs the gate, and only
// then dynamically imports the rest of the adapter — static imports are
// hoisted, so a plain top-level `if` would never run ahead of them. Because
// this file loads before the gate on every Node version, it must use only
// long-stable syntax (no post-ES2019 constructs) and have no side effects.

import { AGENT_HANDSHAKE_HELPER_NODE_MAJOR } from "../agent-handshake/v2/constants.mjs";

const REQUIRED_MAJOR = Number.parseInt(AGENT_HANDSHAKE_HELPER_NODE_MAJOR, 10);

// Accepts a major ("24", 24) or a full version string ("24.6.0"); anything
// unparseable is unsupported — fail closed.
export function isSupportedNodeVersion(major) {
  const value = typeof major === "number" ? major : Number.parseInt(String(major), 10);
  return Number.isSafeInteger(value) && value >= REQUIRED_MAJOR;
}

export function unsupportedNodeVersionMessage(found) {
  const version = found === undefined ? process.versions.node : String(found);
  return (
    `clockchain-local-adapter requires Node.js >= ${AGENT_HANDSHAKE_HELPER_NODE_MAJOR} ` +
    `(found v${version}). Install Node ${AGENT_HANDSHAKE_HELPER_NODE_MAJOR}+ from ` +
    `https://nodejs.org or via your version manager (nvm/fnm/volta), then ` +
    `restart your MCP client.`
  );
}
