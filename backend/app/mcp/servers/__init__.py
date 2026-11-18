"""AEGIS MCP Server instances."""
from app.mcp.servers.nmap_server import nmap_mcp
from app.mcp.servers.zap_server import zap_mcp
from app.mcp.servers.nuclei_server import nuclei_mcp
from app.mcp.servers.trivy_server import trivy_mcp
from app.mcp.servers.github_server import github_mcp

__all__ = ["nmap_mcp", "zap_mcp", "nuclei_mcp", "trivy_mcp", "github_mcp"]
