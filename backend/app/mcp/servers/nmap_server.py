"""
AEGIS Nmap MCP Server
Exposes typed Nmap port scanning & service detection tools through Python MCP SDK.
Enforces target ownership verification and scope limits before any network interaction.
"""

import asyncio
import shutil
import logging
from typing import Dict, Any, Optional
from mcp.server.mcpserver import MCPServer
from app.mcp.guardrails import enforce_active_scan_guardrails

logger = logging.getLogger(__name__)

nmap_mcp = MCPServer("aegis-nmap-server")

def check_cli_available() -> Optional[str]:
    return shutil.which("nmap")

@nmap_mcp.tool()
async def nmap_port_scan(
    target: str,
    ports: str = "top-100",
    scan_mode: str = "service_version",
    max_duration_seconds: int = 60,
    rate_limit: int = 100
) -> Dict[str, Any]:
    """
    Executes a scoped Nmap port scan and service version audit.
    Requires ownership verification of target in AEGIS database.
    Rejects destructive options, enforces rate limits and max execution window.
    """
    # 1. Guardrail Gatekeeper Check
    allowed, guard_details = await enforce_active_scan_guardrails(
        target=target,
        parameters={"ports": ports, "scan_mode": scan_mode},
        max_duration_seconds=max_duration_seconds,
        rate_limit=rate_limit,
        max_rate_allowed=100
    )
    if not allowed:
        return guard_details

    clean_target = guard_details["target"]
    duration = guard_details["duration_seconds"]
    effective_rate = guard_details["rate_limit"]

    # 2. Run only a real Nmap binary; missing tools are reported as unavailable.
    nmap_bin = check_cli_available()

    if nmap_bin:
        # Build safe, non-destructive CLI command
        port_arg = "-F" if ports == "top-100" else f"-p{ports}"
        cmd = [
            nmap_bin,
            "-sV",
            "-Pn",
            "--max-rate", str(effective_rate),
            port_arg,
            clean_target
        ]
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=duration)
            raw_output = stdout.decode("utf-8", errors="replace")
            if proc.returncode != 0:
                return {
                    "status": "ERROR",
                    "execution_mode": f"REAL (Binary: {nmap_bin})",
                    "error": stderr.decode("utf-8", errors="replace") or f"Nmap exited with status {proc.returncode}."
                }
            return {
                "status": "SUCCESS",
                "execution_mode": f"REAL (Binary: {nmap_bin})",
                "target": clean_target,
                "ports_requested": ports,
                "raw_output": raw_output,
                "open_ports": _parse_nmap_text(raw_output),
                "duration_seconds": duration,
                "scope_enforced": {
                    "rate_limit": effective_rate,
                    "max_duration": duration,
                    "destructive_mode": False
                }
            }
        except asyncio.TimeoutError:
            proc.kill()
            return {
                "status": "TIMEOUT",
                "execution_mode": f"REAL (Binary: {nmap_bin})",
                "error": f"Nmap scan timed out after {duration} seconds."
            }
        except Exception as e:
            return {
                "status": "ERROR",
                "execution_mode": f"REAL (Binary: {nmap_bin})",
                "error": str(e)
            }

    return {
        "status": "UNAVAILABLE",
        "execution_mode": "UNAVAILABLE",
        "target": clean_target,
        "error": "Nmap is not installed; no scan was performed."
    }

@nmap_mcp.tool()
async def nmap_service_probe(
    target: str,
    port: int,
    max_duration_seconds: int = 30
) -> Dict[str, Any]:
    """
    Probes a specific port on an ownership-verified target to retrieve service banner.
    """
    allowed, guard_details = await enforce_active_scan_guardrails(
        target=target,
        parameters={"port": port},
        max_duration_seconds=max_duration_seconds,
        max_rate_allowed=50
    )
    if not allowed:
        return guard_details

    clean_target = guard_details["target"]
    nmap_bin = check_cli_available()

    if nmap_bin:
        cmd = [nmap_bin, "-sV", "-p", str(port), clean_target]
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=max_duration_seconds)
            raw = stdout.decode("utf-8", errors="replace")
            if proc.returncode != 0:
                return {
                    "status": "ERROR",
                    "execution_mode": f"REAL (Binary: {nmap_bin})",
                    "error": stderr.decode("utf-8", errors="replace") or f"Nmap exited with status {proc.returncode}."
                }
            return {
                "status": "SUCCESS",
                "execution_mode": f"REAL (Binary: {nmap_bin})",
                "target": clean_target,
                "port": port,
                "raw_output": raw
            }
        except Exception as e:
            return {"status": "ERROR", "error": str(e)}

    return {
        "status": "UNAVAILABLE",
        "execution_mode": "UNAVAILABLE",
        "target": clean_target,
        "port": port,
        "error": "Nmap is not installed; no service probe was performed."
    }

def _parse_nmap_text(output: str) -> list:
    open_ports = []
    for line in output.splitlines():
        if "/tcp" in line and "open" in line:
            parts = line.split()
            port = parts[0]
            service = parts[2] if len(parts) > 2 else "unknown"
            version = " ".join(parts[3:]) if len(parts) > 3 else ""
            open_ports.append({"port": port, "state": "open", "service": service, "version": version})
    return open_ports

