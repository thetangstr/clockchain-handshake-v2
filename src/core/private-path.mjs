import { execFile as execFileCallback } from "node:child_process";
import { constants as fsConstants } from "node:fs";
import {
  chmod,
  lstat,
  mkdir,
  open,
  unlink,
} from "node:fs/promises";
import { dirname, isAbsolute, join, parse, resolve } from "node:path";
import { promisify } from "node:util";

const execFileAsync = promisify(execFileCallback);
const SUPPORTED_PLATFORMS = Object.freeze(["darwin", "linux", "win32"]);
const MAX_PATH_BYTES = 32_768;
const DEFAULT_MAX_FILE_BYTES = 1_048_576;
const CONTROL_CHARACTER_PATTERN = /[\u0000-\u001f\u007f]/;

function fail() {
  throw new Error("Private path operation failed safely.");
}

function sanitize(error) {
  if (error?.message === "Private path operation failed safely.") throw error;
  fail();
}

function normalizedPath(value) {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    Buffer.byteLength(value, "utf8") > MAX_PATH_BYTES ||
    CONTROL_CHARACTER_PATTERN.test(value) ||
    !isAbsolute(value) ||
    resolve(value) !== value ||
    parse(value).root === value
  ) {
    fail();
  }
  return value;
}

function fileSystem(value) {
  if (value === undefined) {
    return Object.freeze({ chmod, lstat, mkdir, open, unlink });
  }
  if (value === null || typeof value !== "object" || Array.isArray(value)) fail();
  const required = ["chmod", "lstat", "mkdir", "open", "unlink"];
  if (required.some((name) => typeof value[name] !== "function")) fail();
  return value;
}

function platform(value) {
  if (!SUPPORTED_PLATFORMS.includes(value)) fail();
  return value;
}

function ownedByCurrentUser(stats, activePlatform) {
  if (activePlatform === "win32" || typeof process.getuid !== "function") return true;
  return stats.uid === process.getuid();
}

function validDirectory(stats, activePlatform) {
  return (
    stats.isDirectory() &&
    !stats.isSymbolicLink() &&
    ownedByCurrentUser(stats, activePlatform) &&
    (activePlatform === "win32" || (stats.mode & 0o777) === 0o700)
  );
}

function validFile(stats, activePlatform, { expectedSize, maxBytes }) {
  return (
    stats.isFile() &&
    !stats.isSymbolicLink() &&
    stats.nlink === 1 &&
    ownedByCurrentUser(stats, activePlatform) &&
    (activePlatform === "win32" || (stats.mode & 0o777) === 0o600) &&
    stats.size > 0 &&
    stats.size <= maxBytes &&
    (expectedSize === undefined || stats.size === expectedSize)
  );
}

function validEmptyFile(stats, activePlatform) {
  return (
    stats.isFile() &&
    !stats.isSymbolicLink() &&
    stats.nlink === 1 &&
    ownedByCurrentUser(stats, activePlatform) &&
    (activePlatform === "win32" || (stats.mode & 0o777) === 0o600) &&
    stats.size === 0
  );
}

function sameNodeIdentity(left, right) {
  return (
    left.dev === right.dev &&
    left.ino === right.ino
  );
}

function sameFileIdentity(left, right) {
  return (
    sameNodeIdentity(left, right) &&
    left.size === right.size
  );
}

async function defaultRunIcacls({ action, kind, path }) {
  if (
    !["secure-and-verify", "verify"].includes(action) ||
    !["directory", "file"].includes(kind)
  ) {
    fail();
  }
  const systemRoot = process.env.SystemRoot ?? process.env.SYSTEMROOT;
  if (typeof systemRoot !== "string" || !isAbsolute(systemRoot)) fail();
  const powershell = join(
    systemRoot,
    "System32",
    "WindowsPowerShell",
    "v1.0",
    "powershell.exe",
  );
  const icacls = join(systemRoot, "System32", "icacls.exe");
  if (action === "secure-and-verify") {
    const { stdout: sidOutput } = await execFileAsync(
      powershell,
      [
        "-NoLogo",
        "-NoProfile",
        "-NonInteractive",
        "-Command",
        "[Console]::Out.Write([System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value)",
      ],
      { encoding: "utf8", maxBuffer: 4_096, windowsHide: true },
    );
    const sid = sidOutput.trim();
    if (!/^S-1-[0-9-]+$/.test(sid)) fail();
    const inheritance = kind === "directory" ? "(OI)(CI)F" : "F";
    await execFileAsync(
      icacls,
      [
        path,
        "/inheritance:r",
        "/grant:r",
        `*${sid}:${inheritance}`,
        `*S-1-5-18:${inheritance}`,
        "/c",
        "/q",
      ],
      { encoding: "utf8", maxBuffer: 16_384, windowsHide: true },
    );
  }
  const verificationScript = [
    "$ErrorActionPreference='Stop'",
    "$acl=Get-Acl -LiteralPath $args[0]",
    "$me=[System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value",
    "$system='S-1-5-18'",
    "if(-not $acl.AreAccessRulesProtected){exit 20}",
    "$rules=@($acl.Access)",
    "if($rules.Count -lt 2){exit 21}",
    "$seenMe=$false",
    "$seenSystem=$false",
    "foreach($rule in $rules){",
    "$sid=$rule.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value",
    "if($sid -eq $me){$seenMe=$true}elseif($sid -eq $system){$seenSystem=$true}else{exit 22}",
    "if($rule.IsInherited -or $rule.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow){exit 23}",
    "if(($rule.FileSystemRights -band [System.Security.AccessControl.FileSystemRights]::FullControl) -ne [System.Security.AccessControl.FileSystemRights]::FullControl){exit 24}",
    "}",
    "if(-not $seenMe -or -not $seenSystem){exit 25}",
  ].join(";");
  await execFileAsync(
    powershell,
    ["-NoLogo", "-NoProfile", "-NonInteractive", "-Command", verificationScript, path],
    { encoding: "utf8", maxBuffer: 4_096, windowsHide: true },
  );
  return true;
}

async function enforceWindowsAcl({ action, kind, path, runIcacls }) {
  const runner = runIcacls ?? defaultRunIcacls;
  if (typeof runner !== "function") fail();
  if (await runner({ action, kind, path }) !== true) fail();
}

export async function preparePrivateDirectory({
  fileSystem: fileSystemOverride,
  path: inputPath,
  platform: inputPlatform = process.platform,
  runIcacls,
} = {}) {
  try {
    const activePlatform = platform(inputPlatform);
    const target = normalizedPath(inputPath);
    const fs = fileSystem(fileSystemOverride);
    let created = false;
    try {
      await fs.mkdir(target, { mode: 0o700, recursive: false });
      created = true;
    } catch (error) {
      if (error?.code !== "EEXIST") throw error;
    }
    if (created && activePlatform !== "win32") await fs.chmod(target, 0o700);
    const stats = await fs.lstat(target);
    if (!validDirectory(stats, activePlatform)) fail();
    if (activePlatform === "win32") {
      await enforceWindowsAcl({
        action: created ? "secure-and-verify" : "verify",
        kind: "directory",
        path: target,
        runIcacls,
      });
      const afterAcl = await fs.lstat(target);
      if (!validDirectory(afterAcl, activePlatform) || !sameNodeIdentity(stats, afterAcl)) fail();
    }
    return Object.freeze({ created, path: target });
  } catch (error) {
    sanitize(error);
  }
  fail();
}

export async function readPrivateText({
  fileSystem: fileSystemOverride,
  maxBytes = DEFAULT_MAX_FILE_BYTES,
  path: inputPath,
  platform: inputPlatform = process.platform,
  runIcacls,
} = {}) {
  try {
    const activePlatform = platform(inputPlatform);
    const target = normalizedPath(inputPath);
    const fs = fileSystem(fileSystemOverride);
    if (!Number.isSafeInteger(maxBytes) || maxBytes < 1 || maxBytes > DEFAULT_MAX_FILE_BYTES) fail();
    const before = await fs.lstat(target);
    if (!validFile(before, activePlatform, { maxBytes })) fail();
    if (activePlatform === "win32") {
      await enforceWindowsAcl({
        action: "verify",
        kind: "file",
        path: target,
        runIcacls,
      });
    }
    const handle = await fs.open(target, fsConstants.O_RDONLY | (fsConstants.O_NOFOLLOW ?? 0));
    try {
      const opened = await handle.stat();
      if (!validFile(opened, activePlatform, { maxBytes }) || !sameFileIdentity(before, opened)) fail();
      return await handle.readFile("utf8");
    } finally {
      await handle.close();
    }
  } catch (error) {
    if (error?.code === "ENOENT") throw error;
    sanitize(error);
  }
  fail();
}

async function closeHandle(handle) {
  if (handle !== undefined) {
    await handle.close().catch(() => {});
  }
}

async function syncHandle(handle) {
  if (typeof handle?.sync === "function") {
    await handle.sync().catch(() => {});
  }
}

async function pinParentDirectory({ activePlatform, fs, parent, runIcacls }) {
  await preparePrivateDirectory({
    fileSystem: fs,
    path: parent,
    platform: activePlatform,
    runIcacls,
  });
  const before = await fs.lstat(parent);
  if (!validDirectory(before, activePlatform)) fail();
  if (activePlatform === "win32") {
    return { handle: undefined, stats: before };
  }

  const flags =
    fsConstants.O_RDONLY |
    (fsConstants.O_DIRECTORY ?? 0) |
    (fsConstants.O_NOFOLLOW ?? 0);
  const handle = await fs.open(parent, flags);
  try {
    const opened = await handle.stat();
    if (!validDirectory(opened, activePlatform) || !sameNodeIdentity(before, opened)) fail();
    return { handle, stats: opened };
  } catch (error) {
    await closeHandle(handle);
    throw error;
  }
}

async function verifyPinnedParent({
  activePlatform,
  fs,
  parent,
  parentHandle,
  parentStats,
}) {
  const current = await fs.lstat(parent);
  if (!validDirectory(current, activePlatform) || !sameNodeIdentity(parentStats, current)) fail();
  if (parentHandle !== undefined) {
    const opened = await parentHandle.stat();
    if (!validDirectory(opened, activePlatform) || !sameNodeIdentity(parentStats, opened)) fail();
  }
}

function sameWritableTarget(opened, checked, activePlatform, { expectedSize }) {
  const valid =
    expectedSize === 0
      ? validEmptyFile(checked, activePlatform)
      : validFile(checked, activePlatform, {
          expectedSize,
          maxBytes: expectedSize,
        });
  return valid && sameNodeIdentity(opened, checked);
}

async function unlinkCreatedTarget({
  activePlatform,
  fs,
  parent,
  parentHandle,
  parentStats,
  target,
  targetStats,
}) {
  try {
    await verifyPinnedParent({
      activePlatform,
      fs,
      parent,
      parentHandle,
      parentStats,
    });
    const currentTarget = await fs.lstat(target);
    if (
      currentTarget.isFile() &&
      !currentTarget.isSymbolicLink() &&
      sameNodeIdentity(targetStats, currentTarget)
    ) {
      await fs.unlink(target);
      await syncHandle(parentHandle);
    }
  } catch {
    // Leaving an empty or private partial is safer than unlinking through a stale path.
  }
}

export async function writePrivateFile({
  bytes: inputBytes,
  fileSystem: fileSystemOverride,
  path: inputPath,
  platform: inputPlatform = process.platform,
  runIcacls,
} = {}) {
  let handle;
  let parentHandle;
  let parentStats;
  let targetStats;
  let target;
  let parent;
  try {
    const activePlatform = platform(inputPlatform);
    target = normalizedPath(inputPath);
    parent = dirname(target);
    const fs = fileSystem(fileSystemOverride);
    if (
      !(Buffer.isBuffer(inputBytes) || inputBytes instanceof Uint8Array) ||
      inputBytes.byteLength < 1 ||
      inputBytes.byteLength > DEFAULT_MAX_FILE_BYTES
    ) {
      fail();
    }
    const bytes = Buffer.from(inputBytes);
    ({ handle: parentHandle, stats: parentStats } =
      await pinParentDirectory({
        activePlatform,
        fs,
        parent,
        runIcacls,
      }));
    await verifyPinnedParent({
      activePlatform,
      fs,
      parent,
      parentHandle,
      parentStats,
    });
    handle = await fs.open(
      target,
      fsConstants.O_WRONLY |
        fsConstants.O_CREAT |
        fsConstants.O_EXCL |
        (fsConstants.O_NOFOLLOW ?? 0),
      0o600,
    );
    if (activePlatform !== "win32") await handle.chmod(0o600);
    if (activePlatform === "win32") {
      await enforceWindowsAcl({
        action: "secure-and-verify",
        kind: "file",
        path: target,
        runIcacls,
      });
    }
    targetStats = await handle.stat();
    const emptyStats = await fs.lstat(target);
    if (
      !validEmptyFile(targetStats, activePlatform) ||
      !sameWritableTarget(targetStats, emptyStats, activePlatform, { expectedSize: 0 })
    ) {
      fail();
    }
    await verifyPinnedParent({
      activePlatform,
      fs,
      parent,
      parentHandle,
      parentStats,
    });
    await handle.writeFile(bytes);
    await handle.sync();
    const writtenStats = await handle.stat();
    if (
      !validFile(writtenStats, activePlatform, {
        expectedSize: bytes.length,
        maxBytes: bytes.length,
      }) ||
      !sameNodeIdentity(targetStats, writtenStats)
    ) {
      fail();
    }
    await handle.close();
    handle = undefined;
    if (activePlatform === "win32") {
      await enforceWindowsAcl({
        action: "verify",
        kind: "file",
        path: target,
        runIcacls,
      });
    }
    const finalStats = await fs.lstat(target);
    if (
      !validFile(finalStats, activePlatform, { expectedSize: bytes.length, maxBytes: bytes.length }) ||
      !sameNodeIdentity(targetStats, finalStats)
    ) {
      fail();
    }
    await verifyPinnedParent({
      activePlatform,
      fs,
      parent,
      parentHandle,
      parentStats,
    });
    await syncHandle(parentHandle);
    await closeHandle(parentHandle);
    parentHandle = undefined;
    return Object.freeze({ path: target, size: bytes.length });
  } catch (error) {
    const activePlatform = SUPPORTED_PLATFORMS.includes(inputPlatform)
      ? inputPlatform
      : process.platform;
    const fs = fileSystemOverride === undefined
      ? Object.freeze({ chmod, lstat, mkdir, open, unlink })
      : fileSystemOverride;
    await closeHandle(handle);
    if (targetStats !== undefined && target !== undefined && parent !== undefined) {
      await unlinkCreatedTarget({
        activePlatform,
        fs,
        parent,
        parentHandle,
        parentStats,
        target,
        targetStats,
      });
    }
    await closeHandle(parentHandle);
    sanitize(error);
  }
  fail();
}
