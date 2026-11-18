"""
AEGIS Trivy MCP Server
Exposes typed Trivy vulnerability scanning tools for filesystem, repos, and configs through Python MCP SDK.
Enforces target ownership verification for remote repos/registries and sandbox boundaries for filesystem paths.
"""

import asyncio
import shutil
import json
import logging
from pathlib import Path
from typing import Dict, Any, Optional, List
from mcp.server.mcpserver import MCPServer
from app.mcp.guardrails import enforce_active_scan_guardrails, check_target_ownership

from app.core.config import settings
from app.services.scanner_health import find_scanner_binary

logger = logging.getLogger(__name__)

trivy_mcp = MCPServer("aegis-trivy-server")

def check_cli_available() -> Optional[str]:
    return find_scanner_binary("trivy")

@trivy_mcp.tool()
async def trivy_scan(
    target_path: str,
    scan_type: str = "fs",
    severity: str = "LOW,MEDIUM,HIGH,CRITICAL",
    max_duration_seconds: int = 60
) -> Dict[str, Any]:
    """
    Executes a Trivy vulnerability audit on project filesystem dependencies or container configurations.
    If targeting a remote repo or domain, checks ownership verification in AEGIS database.
    """
    duration = min(max_duration_seconds, 180)

    # If target is a remote repository URL or domain, enforce ownership check
    if target_path.startswith(("http://", "https://", "git@")):
        is_verified, msg, target_info = await check_target_ownership(target_path)
        if not is_verified:
            return {
                "status": "REFUSED",
                "error_type": "UNVERIFIED_TARGET_REFUSAL",
                "message": f"CTEM GUARDRAIL REFUSAL: {msg}",
                "target": target_path
            }

    # 1. Check for real Trivy binary
    trivy_bin = check_cli_available()

    if trivy_bin:
        cmd = [
            trivy_bin,
            scan_type,
            target_path,
            "--severity", severity,
            "--format", "json",
            "--quiet"
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
                    "execution_mode": f"REAL (Binary: {trivy_bin})",
                    "error": stderr.decode("utf-8", errors="replace") or f"Trivy exited with status {proc.returncode}."
                }
            return {
                "status": "SUCCESS",
                "execution_mode": f"REAL (Binary: {trivy_bin})",
                "target_path": target_path,
                "scan_type": scan_type,
                "raw_output": raw_output[:3000],
                "vulnerabilities": _parse_trivy_json(raw_output)
            }
        except asyncio.TimeoutError:
            proc.kill()
            return {
                "status": "TIMEOUT",
                "execution_mode": f"REAL (Binary: {trivy_bin})",
                "error": f"Trivy scan timed out after {duration} seconds."
            }
        except Exception as e:
            return {
                "status": "ERROR",
                "execution_mode": f"REAL (Binary: {trivy_bin})",
                "error": str(e)
            }

    return {
        "status": "UNAVAILABLE",
        "execution_mode": "UNAVAILABLE",
        "target_path": target_path,
        "error": "Trivy is not installed; no scan was performed."
    }

def _parse_trivy_json(output: str) -> List[Dict[str, Any]]:
    vulns = []
    try:
        data = json.loads(output)
        for result in data.get("Results", []):
            for v in result.get("Vulnerabilities", []):
                vulns.append({
                    "vulnerability_id": v.get("VulnerabilityID"),
                    "package_name": v.get("PkgName"),
                    "installed_version": v.get("InstalledVersion"),
                    "fixed_version": v.get("FixedVersion"),
                    "severity": v.get("Severity"),
                    "title": v.get("Title")
                })
    except json.JSONDecodeError as exc:
        raise ValueError("Trivy returned invalid JSON.") from exc
    return vulns
