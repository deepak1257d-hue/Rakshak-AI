"""
AEGIS MCP Unified Client & Server Registry
Provides a unified interface for LangGraph agents and backend services to invoke MCP tools.
"""

import json
import logging
from typing import Dict, Any, List, Optional
from mcp.server.mcpserver import MCPServer
from app.mcp.servers.nmap_server import nmap_mcp
from app.mcp.servers.zap_server import zap_mcp
from app.mcp.servers.nuclei_server import nuclei_mcp
from app.mcp.servers.trivy_server import trivy_mcp
from app.mcp.servers.github_server import github_mcp

logger = logging.getLogger(__name__)

class MCPRegistry:
    """Registry managing all active MCP servers within AEGIS."""
    def __init__(self):
        self._servers: Dict[str, MCPServer] = {
            "nmap": nmap_mcp,
            "zap": zap_mcp,
            "nuclei": nuclei_mcp,
            "trivy": trivy_mcp,
            "github": github_mcp
        }

    def get_server(self, name: str) -> Optional[MCPServer]:
        return self._servers.get(name.lower())

    async def list_tools(self) -> Dict[str, List[Dict[str, Any]]]:
        """Returns schemas of all tools registered across all MCP servers."""
        inventory = {}
        for s_name, server in self._servers.items():
            tool_list = await server.list_tools()
            inventory[s_name] = [
                {
                    "name": t.name,
                    "description": t.description,
                    "input_schema": t.input_schema
                }
                for t in tool_list
            ]
        return inventory

    async def call_tool(self, server_name: str, tool_name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """
        Dispatches a tool call to the specified MCP server.
        Unpacks and normalizes the response into a python dict.
        """
        server = self.get_server(server_name)
        if not server:
            return {
                "status": "ERROR",
                "error": f"MCP Server '{server_name}' not found. Available servers: {list(self._servers.keys())}"
            }

        try:
            result = await server.call_tool(tool_name, arguments)
            
            # If structured_content is populated:
            if getattr(result, "structured_content", None) is not None:
                data = result.structured_content
                if isinstance(data, dict) and "result" in data and len(data) == 1:
                    return data["result"]
                return data

            # Otherwise extract text from content array
            if getattr(result, "content", None) and len(result.content) > 0:
                first_content = result.content[0]
                text_val = getattr(first_content, "text", "")
                try:
                    return json.loads(text_val)
                except json.JSONDecodeError:
                    return {"status": "ERROR", "error": "MCP tool returned a non-JSON text response."}

            return {"status": "ERROR", "error": "MCP tool returned no structured result."}
        except Exception as e:
            logger.error(f"Error calling MCP tool {server_name}.{tool_name}: {e}")
            return {
                "status": "ERROR",
                "server": server_name,
                "tool": tool_name,
                "error": str(e)
            }

mcp_registry = MCPRegistry()
