export const ACP_VERSION_PINS = Object.freeze({
  claude: Object.freeze({
    packageName: "@agentclientprotocol/claude-agent-acp",
    version: "0.66.0",
    integrity: "sha512-BwalxKsxZzHZGEs+X9hV3biErLE7PHWoao2hmyP3QBWXxvMHbc1F1tzDE95ZA47Fle+KBYf2gKpgy1MJ+ZmVlw==",
    executableName: "claude-agent-acp",
  }),
  codex: Object.freeze({
    packageName: "@agentclientprotocol/codex-acp",
    version: "1.1.14",
    integrity: "sha512-6JKLbGYH0/Gcz788U6KnljwSdNvUnXOyjJDOgsWsbwmXbxn/BXH+urF5AciACdgq13+KgAP9O96Kp6h33BgyKg==",
    executableName: "codex-acp",
  }),
});

function fail() {
  throw new Error("ACP version pin validation failed safely.");
}

function exactRootDependency(lock, pin) {
  const root = lock?.packages?.[""];
  const value = root?.dependencies?.[pin.packageName];
  if (value !== pin.version) fail();
}

function exactLockedPackage(lock, pin) {
  const item = lock?.packages?.[`node_modules/${pin.packageName}`];
  if (item === null || typeof item !== "object" || Array.isArray(item)) fail();
  if (item.version !== pin.version || item.integrity !== pin.integrity) fail();
  if (item.bin?.[pin.executableName] === undefined) fail();
}

export function assertAcpPackageLockPins(lock) {
  if (lock === null || typeof lock !== "object" || Array.isArray(lock)) fail();
  for (const pin of Object.values(ACP_VERSION_PINS)) {
    exactRootDependency(lock, pin);
    exactLockedPackage(lock, pin);
  }
  return true;
}
