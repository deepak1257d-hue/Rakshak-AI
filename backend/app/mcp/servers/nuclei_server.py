"""
AEGIS Nuclei MCP Server
Exposes typed Nuclei vulnerability scanning tools through Python MCP SDK.
Enforces target ownership verification, tag whitelisting (forbidding DoS/fuzz/exploit templates), and rate limits.
"""

import asyncio
import shutil
import json
import logging
from typing import Dict, Any, Optional, List
from mcp.server.mcpserver import MCPServer
from app.mcp.guardrails import enforce_active_scan_guardrails

from app.core.config import settings
from app.services.scanner_health import find_scanner_binary

logger = logging.getLogger(__name__)

nuclei_mcp = MCPServer("aegis-nuclei-server")

def check_cli_available() -> Optional[str]:
    return find_scanner_binary("nuclei")

@nuclei_mcp.tool()
async def nuclei_scan(
    target: str,
    severity: str = "low,medium,high,critical",
    tags: str = "cve,misconfig,exposure",
    max_duration_seconds: int = 90,
    rate_limit: int = 50
) -> Dict[str, Any]:
    """
    Runs a Nuclei vulnerability scan using safe audit templates against an ownership-verified target.
    Excludes destructive exploits and DoS templates; enforces rate limits.
    """
    # 1. Guardrail Gatekeeper Check
    allowed, guard_details = await enforce_active_scan_guardrails(
        target=target,
        parameters={"severity": severity, "tags": tags},
        max_duration_seconds=max_duration_seconds,
        rate_limit=rate_limit,
        max_rate_allowed=50
    )
    if not allowed:
        return guard_details

    clean_target = guard_details["target"]
    duration = guard_details["duration_seconds"]
    effective_rate = guard_details["rate_limit"]

    # 2. Run only a real Nuclei binary; missing tools are reported as unavailable.
    nuclei_bin = check_cli_available()

    if nuclei_bin:
        cmd = [
            nuclei_bin,
            "-target", target,
            "-severity", severity,
            "-tags", tags,
            "-rate-limit", str(effective_rate),
            "-concurrency", "5",
            "-silent",
            "-jsonl"
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
                    "execution_mode": f"REAL (Binary: {nuclei_bin})",
                    "error": stderr.decode("utf-8", errors="replace") or f"Nuclei exited with status {proc.returncode}."
                }
            return {
                "status": "SUCCESS",
                "execution_mode": f"REAL (Binary: {nuclei_bin})",
                "target": clean_target,
                "raw_output": raw_output,
                "findings": _parse_nuclei_json_lines(raw_output),
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
                "execution_mode": f"REAL (Binary: {nuclei_bin})",
                "error": f"Nuclei scan timed out after {duration} seconds."
            }
        except Exception as e:
            return {
                "status": "ERROR",
                "execution_mode": f"REAL (Binary: {nuclei_bin})",
                "error": str(e)
            }

    return {
        "status": "UNAVAILABLE",
        "execution_mode": "UNAVAILABLE",
        "target": clean_target,
        "error": "Nuclei is not installed; no scan was performed."
    }

def _parse_nuclei_json_lines(output: str) -> List[Dict[str, Any]]:
    findings = []
    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            data = json.loads(line)
            findings.append({
                "template_id": data.get("template-id"),
                "name": data.get("info", {}).get("name"),
                "severity": data.get("info", {}).get("severity"),
                "matched_at": data.get("matched-at"),
                "cve": (data.get("info", {}).get("classification", {}).get("cve-id") or [None])[0]
            })
        except Exception:
            continue
    return findings
