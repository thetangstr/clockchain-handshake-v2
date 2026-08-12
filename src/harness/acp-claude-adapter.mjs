import { createAcpHarnessAdapter } from "./acp-codex-adapter.mjs";
import { ACP_VERSION_PINS } from "./version-pins.mjs";

export function createAcpClaudeHarnessAdapter(options = {}) {
  return createAcpHarnessAdapter({
    ...options,
    harness: "claude",
    pin: ACP_VERSION_PINS.claude,
  });
}
