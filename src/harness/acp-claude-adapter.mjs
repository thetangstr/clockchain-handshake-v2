import { createPinnedAcpHarnessAdapter } from "./acp-codex-adapter.mjs";
import { ACP_VERSION_PINS } from "./version-pins.mjs";

export function createAcpClaudeHarnessAdapter(options = {}) {
  return createPinnedAcpHarnessAdapter(options, "claude", ACP_VERSION_PINS.claude);
}
