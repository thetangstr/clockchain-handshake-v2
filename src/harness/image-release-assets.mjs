import { lstat, readFile } from "node:fs/promises";
import { isAbsolute, join, resolve } from "node:path";

const RELEASE_PREFIX = "https://github.com/thetangstr/clockchain-handshake-v2/releases/download/v2.1.3/";
const ASSETS = Object.freeze(new Set(["manifest.json", "clockchain-agent-handshake.cjs"]));

function fail() {
  throw new Error("Image release asset read failed safely.");
}

export function createImageReleaseAssetFetch(root) {
  if (typeof root !== "string" || !isAbsolute(root) || resolve(root) !== root) fail();
  return async function imageReleaseAssetFetch(url) {
    if (typeof url !== "string" || !url.startsWith(RELEASE_PREFIX)) fail();
    const name = url.slice(RELEASE_PREFIX.length);
    if (!ASSETS.has(name)) fail();
    const path = join(root, name);
    let stat;
    let bytes;
    try {
      stat = await lstat(path);
      if (!stat.isFile() || stat.isSymbolicLink() || stat.size < 1 || stat.size > 1024 * 1024) fail();
      bytes = await readFile(path);
    } catch (error) {
      if (error?.message === "Image release asset read failed safely.") throw error;
      fail();
    }
    return Object.freeze({ ok: true, arrayBuffer: async () => bytes });
  };
}
