import assert from "node:assert/strict";
import {
  chmod,
  link,
  lstat,
  mkdir,
  mkdtemp,
  open,
  readFile,
  rename,
  rm,
  symlink,
  unlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { test } from "node:test";

import {
  preparePrivateDirectory,
  readPrivateText,
  writePrivateFile,
} from "../src/core/private-path.mjs";

async function temporaryRoot(t) {
  const root = await mkdtemp(join(tmpdir(), "clockchain-private-path-"));
  t.after(() => rm(root, { force: true, recursive: true }));
  return root;
}

async function readOptional(path) {
  try {
    return await readFile(path, "utf8");
  } catch (error) {
    if (error?.code === "ENOENT") return "";
    throw error;
  }
}

function privateFileSystem(overrides = {}) {
  return {
    chmod,
    link,
    lstat,
    mkdir,
    open,
    unlink,
    ...overrides,
  };
}

async function swapParentToSymlink({
  redirectedParent,
  displacedParent,
  originalParent,
}) {
  await rename(originalParent, displacedParent);
  await symlink(redirectedParent, originalParent);
}

async function assertNoSecretRedirected(redirectedParent, secret) {
  const redirectedText = await readOptional(join(redirectedParent, "secret"));
  assert.equal(redirectedText.includes(secret), false);
  assert.equal(redirectedText.includes(secret.toString("hex")), false);
}

test("POSIX private paths create exact modes and refuse overwrite", async (t) => {
  const root = await temporaryRoot(t);
  const directory = join(root, "state");
  const target = join(directory, "secret.json");

  await preparePrivateDirectory({ path: directory, platform: "darwin" });
  await writePrivateFile({
    bytes: Buffer.from('{"secret":"value"}\n'),
    path: target,
    platform: "darwin",
  });

  assert.equal((await lstat(directory)).mode & 0o777, 0o700);
  assert.equal((await lstat(target)).mode & 0o777, 0o600);
  assert.equal(await readPrivateText({ path: target, platform: "darwin" }), '{"secret":"value"}\n');
  await assert.rejects(
    writePrivateFile({
      bytes: Buffer.from("replacement"),
      path: target,
      platform: "darwin",
    }),
    /Private path operation failed safely/,
  );
  assert.equal(await readFile(target, "utf8"), '{"secret":"value"}\n');
});

test("private writes create the final target directly without linking a temporary file", async (t) => {
  const root = await temporaryRoot(t);
  const directory = join(root, "state");
  const target = join(directory, "secret");

  await preparePrivateDirectory({ path: directory, platform: "darwin" });
  await writePrivateFile({
    bytes: Buffer.from("secret"),
    fileSystem: privateFileSystem({
      async link() {
        throw new Error("writePrivateFile must not link private data");
      },
    }),
    path: target,
    platform: "darwin",
  });

  assert.equal(await readFile(target, "utf8"), "secret");
});

test("POSIX private paths reject permissive directories, symlinks, and hard-linked files", async (t) => {
  const root = await temporaryRoot(t);
  const permissive = join(root, "permissive");
  await preparePrivateDirectory({ path: permissive, platform: "darwin" });
  await chmod(permissive, 0o755);
  await assert.rejects(
    preparePrivateDirectory({ path: permissive, platform: "darwin" }),
    /Private path operation failed safely/,
  );

  const real = join(root, "real");
  const linkedDirectory = join(root, "linked-directory");
  await preparePrivateDirectory({ path: real, platform: "darwin" });
  await symlink(real, linkedDirectory);
  await assert.rejects(
    preparePrivateDirectory({ path: linkedDirectory, platform: "darwin" }),
    /Private path operation failed safely/,
  );

  const file = join(real, "file");
  const secondLink = join(real, "file-link");
  await writeFile(file, "secret", { mode: 0o600 });
  await link(file, secondLink);
  await assert.rejects(
    readPrivateText({ path: file, platform: "darwin" }),
    /Private path operation failed safely/,
  );
});

test("Windows private paths require ACL enforcement for directories and final files before reading", async (t) => {
  const root = await temporaryRoot(t);
  const directory = join(root, "state");
  const target = join(directory, "secret.json");
  const calls = [];
  const runIcacls = async (input) => {
    calls.push(input);
    return true;
  };

  await preparePrivateDirectory({ path: directory, platform: "win32", runIcacls });
  await writePrivateFile({
    bytes: Buffer.from("private"),
    path: target,
    platform: "win32",
    runIcacls,
  });
  assert.equal(
    await readPrivateText({ path: target, platform: "win32", runIcacls }),
    "private",
  );

  assert.equal(calls.some((entry) => entry.kind === "directory" && entry.path === directory), true);
  assert.equal(calls.some((entry) => entry.action === "secure-and-verify" && entry.kind === "file" && entry.path === target), true);
  assert.equal(calls.some((entry) => entry.action === "verify" && entry.kind === "file" && entry.path === target), true);
});

test("Windows private paths fail closed on ACL failure and reparse points", async (t) => {
  const root = await temporaryRoot(t);
  const directory = join(root, "state");
  await assert.rejects(
    preparePrivateDirectory({
      path: directory,
      platform: "win32",
      runIcacls: async () => {
        throw new Error("localized acl output with private path");
      },
    }),
    (error) => {
      assert.match(error.message, /Private path operation failed safely/);
      assert.equal(error.message.includes("localized acl output"), false);
      assert.equal(error.message.includes(directory), false);
      return true;
    },
  );

  const real = join(root, "real");
  const linkedDirectory = join(root, "junction");
  await preparePrivateDirectory({
    path: real,
    platform: "win32",
    runIcacls: async () => true,
  });
  await symlink(real, linkedDirectory);
  await assert.rejects(
    preparePrivateDirectory({
      path: linkedDirectory,
      platform: "win32",
      runIcacls: async () => true,
    }),
    /Private path operation failed safely/,
  );
});

test("private reads reject a file identity change between path check and open handle", async (t) => {
  const root = await temporaryRoot(t);
  const directory = join(root, "state");
  const target = join(directory, "secret");
  await preparePrivateDirectory({ path: directory, platform: "darwin" });
  await writeFile(target, "secret", { mode: 0o600 });

  await assert.rejects(
    readPrivateText({
      fileSystem: {
        chmod,
        link,
        lstat,
        mkdir,
        async open(...arguments_) {
          const handle = await open(...arguments_);
          return {
            close: (...args) => handle.close(...args),
            readFile: (...args) => handle.readFile(...args),
            async stat() {
              const stats = await handle.stat();
              return new Proxy(stats, {
                get(targetStats, property, receiver) {
                  if (property === "ino") return targetStats.ino + 1;
                  return Reflect.get(targetStats, property, receiver);
                },
              });
            },
          };
        },
        unlink,
      },
      path: target,
      platform: "darwin",
    }),
    /Private path operation failed safely/,
  );
});

test("private writes do not redirect secret bytes when the parent is swapped after pinning", async (t) => {
  const root = await temporaryRoot(t);
  const originalParent = join(root, "state");
  const redirectedParent = join(root, "redirected");
  const displacedParent = join(root, "state-displaced");
  const target = join(originalParent, "secret");
  const secret = Buffer.from("parent-pinned-secret");
  let swapped = false;

  await preparePrivateDirectory({ path: originalParent, platform: "darwin" });
  await preparePrivateDirectory({ path: redirectedParent, platform: "darwin" });

  await assert.rejects(
    writePrivateFile({
      bytes: secret,
      fileSystem: privateFileSystem({
        async open(...args) {
          if (!swapped) {
            swapped = true;
            await swapParentToSymlink({
              redirectedParent,
              displacedParent,
              originalParent,
            });
          }
          return await open(...args);
        },
      }),
      path: target,
      platform: "darwin",
    }),
    /Private path operation failed safely/,
  );

  await assertNoSecretRedirected(redirectedParent, secret);
});

test("private writes keep secret bytes on the opened target when the parent is swapped before write", async (t) => {
  const root = await temporaryRoot(t);
  const originalParent = join(root, "state");
  const redirectedParent = join(root, "redirected");
  const displacedParent = join(root, "state-displaced");
  const target = join(originalParent, "secret");
  const secret = Buffer.from("opened-target-secret");
  let swapped = false;

  await preparePrivateDirectory({ path: originalParent, platform: "darwin" });
  await preparePrivateDirectory({ path: redirectedParent, platform: "darwin" });

  await assert.rejects(
    writePrivateFile({
      bytes: secret,
      fileSystem: privateFileSystem({
        async open(...args) {
          const handle = await open(...args);
          return {
            chmod: (...handleArgs) => handle.chmod(...handleArgs),
            close: (...handleArgs) => handle.close(...handleArgs),
            stat: (...handleArgs) => handle.stat(...handleArgs),
            sync: (...handleArgs) => handle.sync(...handleArgs),
            async writeFile(...handleArgs) {
              if (!swapped) {
                swapped = true;
                await swapParentToSymlink({
                  redirectedParent,
                  displacedParent,
                  originalParent,
                });
              }
              return await handle.writeFile(...handleArgs);
            },
          };
        },
      }),
      path: target,
      platform: "darwin",
    }),
    /Private path operation failed safely/,
  );

  await assertNoSecretRedirected(redirectedParent, secret);
  assert.equal(
    (await readOptional(join(displacedParent, "secret"))).includes(secret.toString()),
    true,
  );
});

test("private writes fail closed when the parent is swapped before final verification", async (t) => {
  const root = await temporaryRoot(t);
  const originalParent = join(root, "state");
  const redirectedParent = join(root, "redirected");
  const displacedParent = join(root, "state-displaced");
  const target = join(originalParent, "secret");
  const secret = Buffer.from("final-verify-secret");
  let wroteSecret = false;
  let swapped = false;

  await preparePrivateDirectory({ path: originalParent, platform: "darwin" });
  await preparePrivateDirectory({ path: redirectedParent, platform: "darwin" });

  await assert.rejects(
    writePrivateFile({
      bytes: secret,
      fileSystem: privateFileSystem({
        async lstat(path) {
          if (path === target && wroteSecret && !swapped) {
            swapped = true;
            await swapParentToSymlink({
              redirectedParent,
              displacedParent,
              originalParent,
            });
          }
          return await lstat(path);
        },
        async open(...args) {
          const handle = await open(...args);
          return {
            chmod: (...handleArgs) => handle.chmod(...handleArgs),
            close: (...handleArgs) => handle.close(...handleArgs),
            stat: (...handleArgs) => handle.stat(...handleArgs),
            sync: (...handleArgs) => handle.sync(...handleArgs),
            async writeFile(...handleArgs) {
              const result = await handle.writeFile(...handleArgs);
              wroteSecret = true;
              return result;
            },
          };
        },
      }),
      path: target,
      platform: "darwin",
    }),
    /Private path operation failed safely/,
  );

  await assertNoSecretRedirected(redirectedParent, secret);
  assert.equal(dirname(target), originalParent);
});
