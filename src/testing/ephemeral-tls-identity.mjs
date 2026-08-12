import { createHash, X509Certificate } from "node:crypto";
import { execFile as nodeExecFile } from "node:child_process";
import { chmod, lstat, mkdir, readFile, rm } from "node:fs/promises";
import { isIP } from "node:net";
import { isAbsolute, join, resolve } from "node:path";
import { promisify } from "node:util";

const ERROR = "Ephemeral TLS identity failed safely.";
const HOSTNAME = /^(?:[a-z0-9-]+\.)*(?:task\.local|internal|local)$/;

function fail() { throw new Error(ERROR); }
function sanitize(error) { if (error?.message === ERROR) throw error; fail(); }

function cleanPath(value) {
  if (typeof value !== "string" || !isAbsolute(value)) fail();
  const clean = resolve(value);
  if (clean === "/" || clean.length < 8) fail();
  return clean;
}

function subjectAlternativeName(hostname) {
  if (HOSTNAME.test(hostname)) return Object.freeze({ openssl: `DNS:${hostname}`, x509: `DNS:${hostname}` });
  if (isIP(hostname) !== 4) fail();
  const octets = hostname.split(".").map(Number);
  const privateAddress =
    octets[0] === 10 ||
    (octets[0] === 172 && octets[1] >= 16 && octets[1] <= 31) ||
    (octets[0] === 192 && octets[1] === 168);
  if (!privateAddress) fail();
  return Object.freeze({ openssl: `IP:${hostname}`, x509: `IP Address:${hostname}` });
}

function digestCertificate(certificate) {
  try { return createHash("sha256").update(new X509Certificate(certificate).raw).digest("hex"); }
  catch { fail(); }
}

export async function createEphemeralTlsIdentity(options = {}) {
  try {
    const descriptors = Object.getOwnPropertyDescriptors(options);
    const allowed = ["execFileImpl", "hostname", "opensslPath", "root"];
    const keys = Reflect.ownKeys(descriptors);
    if (keys.some((key) => typeof key !== "string" || !allowed.includes(key))) fail();
    for (const key of ["hostname", "opensslPath", "root"]) {
      if (descriptors[key]?.enumerable !== true || !Object.hasOwn(descriptors[key], "value")) fail();
    }
    const hostname = descriptors.hostname.value;
    const opensslPath = cleanPath(descriptors.opensslPath.value);
    const root = cleanPath(descriptors.root.value);
    const execFileImpl = descriptors.execFileImpl?.value ?? promisify(nodeExecFile);
    if (typeof hostname !== "string" || typeof execFileImpl !== "function") fail();
    const san = subjectAlternativeName(hostname);

    await mkdir(root, { mode: 0o700, recursive: false });
    await chmod(root, 0o700);
    const rootStat = await lstat(root);
    if (!rootStat.isDirectory() || rootStat.isSymbolicLink() || (rootStat.mode & 0o777) !== 0o700) fail();
    const keyPath = join(root, "tls-private-key.pem");
    const certificatePath = join(root, "tls-certificate.pem");
    try {
      await execFileImpl(opensslPath, [
        "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-sha256", "-nodes",
        "-keyout", keyPath, "-out", certificatePath, "-days", "1", "-subj", `/CN=${hostname}`,
        "-addext", `subjectAltName=${san.openssl}`,
      ], { windowsHide: true });
    } catch { fail(); }
    await chmod(keyPath, 0o600);
    await chmod(certificatePath, 0o600);
    const [privateKey, certificate] = await Promise.all([
      readFile(keyPath, "utf8"),
      readFile(certificatePath, "utf8"),
    ]);
    const cert = new X509Certificate(certificate);
    if (
      !privateKey.includes("-----BEGIN PRIVATE KEY-----") || cert.publicKey.asymmetricKeyType !== "ec" ||
      cert.publicKey.asymmetricKeyDetails?.namedCurve !== "prime256v1" ||
      !cert.subjectAltName?.split(", ").includes(san.x509)
    ) fail();
    const certificateSha256 = digestCertificate(certificate);
    let destroyed = false;
    return Object.freeze({
      schema: "clockchain.ephemeral-tls-identity/v1",
      certificate,
      certificatePath,
      certificateSha256,
      keyPath,
      privateKey,
      publicEvidence() {
        if (destroyed) fail();
        return Object.freeze({
          schema: "clockchain.ephemeral-tls-identity-evidence/v1",
          certificateSha256,
          hostname,
        });
      },
      async destroy() {
        if (destroyed) fail();
        const current = await lstat(root);
        if (
          !current.isDirectory() || current.isSymbolicLink() ||
          current.dev !== rootStat.dev || current.ino !== rootStat.ino
        ) fail();
        destroyed = true;
        await rm(root, { recursive: true, force: false });
        return Object.freeze({ destroyed: true });
      },
    });
  } catch (error) { sanitize(error); }
}
