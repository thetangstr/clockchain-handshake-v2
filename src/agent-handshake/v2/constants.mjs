export const AGENT_HANDSHAKE_V2_PROTOCOL = "clockchain.agent-handshake/v2";
export const AGENT_HANDSHAKE_V2_POLICY_SCHEMA = "clockchain.agent-handshake-policy/v1";
export const AGENT_HANDSHAKE_V2_MCP_ORIGIN = "https://mcp.clockchain.network";
export const AGENT_HANDSHAKE_V2_SEPOLIA_CHAIN = "eip155:11155111";
export const AGENT_HANDSHAKE_V2_REGISTRY_ADDRESS =
  "0x8004a818bfb912233c491871b3d84c89a494bd9e";
export const AGENT_HANDSHAKE_V2_IDENTITY_MODES = Object.freeze([
  "required_fresh",
  "required_existing_or_fresh",
  "not_required",
]);
export const AGENT_HANDSHAKE_V2_ROLES = Object.freeze([
  "initiator",
  "responder",
]);
export const AGENT_HANDSHAKE_V2_MAX_VALID_FOR_SECONDS = 90n;

// The one place the released helper version is declared. The distribution tag,
// the release asset URL prefix, the npm fallback version, the manifest version
// the verifier accepts, and the helperVersion the agent CLI expects in signing
// requests are all derived from this — they may not drift apart, because the
// published release embeds the same value in every surface.
export const AGENT_HANDSHAKE_HELPER_VERSION = "2.1.8";
export const AGENT_HANDSHAKE_HELPER_NODE_MAJOR = "24";
export const AGENT_HANDSHAKE_RELEASE_TAG = `v${AGENT_HANDSHAKE_HELPER_VERSION}`;
export const AGENT_HANDSHAKE_RELEASE_ASSET_PREFIX =
  `https://github.com/thetangstr/clockchain-handshake-v2/releases/download/${AGENT_HANDSHAKE_RELEASE_TAG}/`;

// The published @d4d.group/local-adapter npm package version. Deliberately NOT
// in lockstep with AGENT_HANDSHAKE_HELPER_VERSION: the adapter is a client
// wrapper that floats independently (bugfix/doc/scrub releases) while the
// vendored helper pin inside stays at the helper release above. The publish
// workflow asserts tag == this version and vendored pin == helper version.
export const LOCAL_ADAPTER_VERSION = "2.1.9";
