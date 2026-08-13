export const REQUIRED_PARTY_PROGRESS_TYPES = Object.freeze([
  "a2a.listener.ready",
  "a2a.invitation.received",
  "agent.starting",
  "certificate.verified",
]);

export const ACP_TRACE_TO_PARTY_PROGRESS = Object.freeze(new Map([
  ["acp.process.launch", "agent.client.started"],
  ["acp.initialize", "agent.client.connected"],
  ["acp.session.new", "agent.session.ready"],
  ["acp.model.pinned", "agent.model.ready"],
  ["acp.tool_call", "agent.tool.called"],
  ["acp.tool_call_update", "agent.tool.updated"],
  ["acp.permission.authorized", "agent.action.authorized"],
  ["acp.permission.denied", "agent.action.denied"],
  ["acp.retained_action.registered", "agent.action.registered"],
  ["acp.handshake.continue", "agent.handshake.continued"],
  ["acp.prompt.end_turn", "agent.completed"],
]));

export const ACP_PARTY_PROGRESS_TYPES = Object.freeze([...new Set(ACP_TRACE_TO_PARTY_PROGRESS.values())]);
export const PARTY_PROGRESS_TYPES = Object.freeze([...REQUIRED_PARTY_PROGRESS_TYPES, ...ACP_PARTY_PROGRESS_TYPES]);
