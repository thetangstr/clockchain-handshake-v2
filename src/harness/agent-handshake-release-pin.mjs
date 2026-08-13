import { readFileSync } from "node:fs";

const SHA256 = /^[0-9a-f]{64}$/;
const PREFIX = "https://github.com/thetangstr/clockchain-handshake-v2/releases/download/v2.1.3/";

function loadPin() {
  let pin;
  try {
    pin = JSON.parse(readFileSync(new URL("../../release/agent-handshake/pin.json", import.meta.url), "utf8"));
  } catch {
    throw new Error("Agent handshake release pin is invalid.");
  }
  if (
    pin?.version !== "2.1.3" || pin.allowedAssetPrefix !== PREFIX || !SHA256.test(pin.manifestDigest) ||
    !Array.isArray(pin.hostRoots) || pin.hostRoots.length < 1
  ) throw new Error("Agent handshake release pin is invalid.");
  return Object.freeze({
    allowedAssetPrefix: pin.allowedAssetPrefix,
    manifestDigest: pin.manifestDigest,
    version: pin.version,
  });
}

export const AGENT_HANDSHAKE_RELEASE_PIN = loadPin();
