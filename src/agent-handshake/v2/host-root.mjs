import { createPrivateKey, createPublicKey } from "node:crypto";

import { readPrivateText } from "../../core/private-path.mjs";
import { rawEd25519PublicKey } from "./host-key-certificate.mjs";

const KEY_ID = /^[a-z0-9][a-z0-9-]{0,63}$/;

export class HostRootConfigurationError extends Error {
  constructor() {
    super("Clockchain host root configuration is invalid.");
    this.name = "HostRootConfigurationError";
    this.category = "configuration";
    this.code = "HOST_ROOT_CONFIGURATION_INVALID";
  }
}

function invalid() {
  throw new HostRootConfigurationError();
}

export async function loadHostRoot({
  env = process.env,
  readPrivate = readPrivateText,
} = {}) {
  if (
    typeof env !== "object" ||
    typeof readPrivate !== "function" ||
    Object.hasOwn(env, "CLOCKCHAIN_HOST_ROOT_PRIVATE_KEY") ||
    !KEY_ID.test(env.CLOCKCHAIN_HOST_ROOT_KEY_ID ?? "") ||
    typeof env.CLOCKCHAIN_HOST_ROOT_KEY_FILE !== "string" ||
    !env.CLOCKCHAIN_HOST_ROOT_KEY_FILE.startsWith("/")
  ) invalid();
  let privateKeyPem;
  let privateKey;
  try {
    privateKeyPem = await readPrivate({
      maxBytes: 4096,
      path: env.CLOCKCHAIN_HOST_ROOT_KEY_FILE,
    });
    privateKey = createPrivateKey(privateKeyPem);
  } catch {
    invalid();
  }
  if (privateKey.asymmetricKeyType !== "ed25519") invalid();
  return Object.freeze({
    keyId: env.CLOCKCHAIN_HOST_ROOT_KEY_ID,
    privateKeyPem,
    publicKey: rawEd25519PublicKey(createPublicKey(privateKey)),
  });
}
