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
