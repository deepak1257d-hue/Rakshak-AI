"""
AEGIS Agent Tool Allowlists
Strictly regulates which agent node is authorized to invoke which tools.
Enforces the principle of least privilege across the multi-agent graph.
"""

from typing import Dict, List, Set

# Strict per-agent tool allowlists
AGENT_TOOL_ALLOWLISTS: Dict[str, Set[str]] = {
    # Planner agent only formulates and revises the audit plan; zero tool execution privileges.
    "planner": set(),

    # Executor agent is authorized to dispatch scoped, non-destructive active scanner MCP tools.
    "executor": {
        "nmap_port_scan",
        "nmap_service_probe",
        "zap_baseline_scan",
        "nuclei_scan",
        "trivy_scan"
    },

    # Untrusted parser agent performs deterministic sanitization and schema coercion only.
    "parser": set(),

    # Verifier agent checks empirical evidence and cross-checks reachability proofs.
    "verifier": set(),

    # System reasoning agent synthesizes remediation code patches; must never touch raw tools.
    "reasoning": set(),

    # Reporter agent aggregates findings and formats executive reports.
    "reporter": set()
}

class ToolAuthorizationError(Exception):
    """Raised when an agent attempts to invoke a tool outside its declared allowlist."""
    pass

def check_agent_tool_permission(agent_name: str, tool_name: str) -> bool:
    """
    Validates whether the specified agent is authorized to invoke the given tool.
    """
    agent_key = agent_name.lower().strip()
    allowed_tools = AGENT_TOOL_ALLOWLISTS.get(agent_key, set())
    return tool_name in allowed_tools

def enforce_agent_tool_permission(agent_name: str, tool_name: str) -> None:
    """
    Enforces that an agent has authorization to invoke a tool, raising ToolAuthorizationError otherwise.
    """
    if not check_agent_tool_permission(agent_name, tool_name):
        raise ToolAuthorizationError(
            f"SECURITY POLICY VIOLATION: Agent '{agent_name}' is NOT authorized to execute tool '{tool_name}'. "
            f"Allowed tools for '{agent_name}': {list(AGENT_TOOL_ALLOWLISTS.get(agent_name.lower(), []))}"
        )
