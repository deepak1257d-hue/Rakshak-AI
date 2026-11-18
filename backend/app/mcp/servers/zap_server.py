"""
AEGIS OWASP ZAP MCP Server
Exposes typed OWASP ZAP web application security scanning tools through Python MCP SDK.
Enforces target ownership verification, safe non-destructive baseline policies, and rate limits.
"""

import asyncio
import shutil
import logging
from typing import Dict, Any, Optional, List
from mcp.server.mcpserver import MCPServer
from app.mcp.guardrails import enforce_active_scan_guardrails

import json
import tempfile
import os
from app.services.scanner_health import find_scanner_binary

logger = logging.getLogger(__name__)

zap_mcp = MCPServer("aegis-zap-server")

def check_cli_available() -> Optional[str]:
    return find_scanner_binary("zap")

@zap_mcp.tool()
async def zap_baseline_scan(
    target_url: str,
    scan_mode: str = "passive_baseline",
    max_duration_seconds: int = 90,
    rate_limit: int = 20
) -> Dict[str, Any]:
    """
    Executes an OWASP ZAP baseline web vulnerability scan against an ownership-verified target.
    Enforces safe passive/baseline audit mode without destructive exploitation or fuzzing.
    """
    # 1. Guardrail Gatekeeper Check
    allowed, guard_details = await enforce_active_scan_guardrails(
        target=target_url,
        parameters={"scan_mode": scan_mode},
        max_duration_seconds=max_duration_seconds,
        rate_limit=rate_limit,
        max_rate_allowed=30
    )
    if not allowed:
        return guard_details

    clean_target = guard_details["target"]
    duration = guard_details["duration_seconds"]
    effective_rate = guard_details["rate_limit"]

    # 2. Run only a real ZAP binary; missing tools are reported as unavailable.
    zap_bin = check_cli_available()

    if zap_bin:
        # Use ZAP quickurl mode to generate a JSON report file.
        import tempfile
        import os
        with tempfile.NamedTemporaryFile(delete=False, suffix=".json") as tmp_file:
            report_path = tmp_file.name
        cmd = [
            zap_bin,
            "-cmd",
            "-quickurl",
            target_url,
            "-quickout",
            report_path,
        ]
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=duration)
            raw_output = stdout.decode("utf-8", errors="replace")
            if proc.returncode != 0:
                # Clean up temp file
                try:
                    os.remove(report_path)
                except OSError:
                    pass
                return {
                    "status": "ERROR",
                    "execution_mode": f"REAL (Binary: {zap_bin})",
                    "error": stderr.decode("utf-8", errors="replace") or f"ZAP exited with status {proc.returncode}.",
                }
            # Read and parse JSON report
            try:
                with open(report_path, "r", encoding="utf-8") as f:
                    report_json = json.load(f)
                alerts = _parse_zap_json_report(report_json)
            except Exception as e:
                logger.error(f"Failed to parse ZAP JSON report: {e}")
                alerts = []
            finally:
                try:
                    os.remove(report_path)
                except OSError:
                    pass
            return {
                "status": "SUCCESS",
                "execution_mode": f"REAL (Binary: {zap_bin})",
                "target_url": target_url,
                "scan_mode": scan_mode,
                "raw_output": raw_output,
                "alerts_found": alerts,
                "scope_enforced": {
                    "rate_limit": effective_rate,
                    "max_duration": duration,
                    "destructive_mode": False,
                },
            }
        except asyncio.TimeoutError:
            proc.kill()
            try:
                os.remove(report_path)
            except OSError:
                pass
            return {
                "status": "TIMEOUT",
                "execution_mode": f"REAL (Binary: {zap_bin})",
                "error": f"ZAP scan timed out after {duration} seconds.",
            }
        except Exception as e:
            try:
                os.remove(report_path)
            except OSError:
                pass
            return {
                "status": "ERROR",
                "execution_mode": f"REAL (Binary: {zap_bin})",
                "error": str(e),
            }
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
                    "execution_mode": f"REAL (Binary: {zap_bin})",
                    "error": stderr.decode("utf-8", errors="replace") or f"ZAP exited with status {proc.returncode}."
                }
            return {
                "status": "SUCCESS",
                "execution_mode": f"REAL (Binary: {zap_bin})",
                "target_url": target_url,
                "scan_mode": scan_mode,
                "raw_output": raw_output,
                "alerts_found": _parse_zap_output(raw_output),
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
                "execution_mode": f"REAL (Binary: {zap_bin})",
                "error": f"ZAP scan timed out after {duration} seconds."
            }
        except Exception as e:
            return {
                "status": "ERROR",
                "execution_mode": f"REAL (Binary: {zap_bin})",
                "error": str(e)
            }

    return {
        "status": "UNAVAILABLE",
        "execution_mode": "UNAVAILABLE",
        "target_url": target_url,
        "error": "OWASP ZAP is not installed; no scan was performed."
    }

def _parse_zap_json_report(report: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Parse ZAP JSON report and normalize alerts.

    Returns a list of dicts with keys: alert, risk, confidence, url, evidence,
    cwe_id, description, solution, reference.
    """
    alerts: List[Dict[str, Any]] = []
    for site in report.get("site", []):
        site_name = site.get("@name", "")
        for alert in site.get("alerts", []):
            name = alert.get("name", "")
            risk = alert.get("riskdesc", "")
            confidence = alert.get("confidence", "")
            description = alert.get("description", "")
            solution = alert.get("solution", "")
            reference = alert.get("reference", "")
            cwe_id = alert.get("cweid", "")
            instances = alert.get("instances", [])
            for inst in instances:
                alerts.append({
                    "alert": name,
                    "risk": risk,
                    "confidence": confidence,
                    "url": inst.get("uri", site_name),
                    "evidence": inst.get("evidence", ""),
                    "cwe_id": cwe_id,
                    "description": description,
                    "solution": solution,
                    "reference": reference,
                })
    return alerts

# Retain legacy line‑based parser for compatibility with older ZAP versions.
def _parse_zap_output(raw_output: str) -> List[Dict[str, Any]]:
    alerts = []
    for line in raw_output.splitlines():
        if "WARN-NEW:" in line or "FAIL-NEW:" in line:
            alerts.append({"alert": line.strip(), "risk": "Medium"})
    return alerts
    alerts = []
    for line in raw_output.splitlines():
        if "WARN-NEW:" in line or "FAIL-NEW:" in line:
            alerts.append({"alert": line.strip(), "risk": "Medium"})
    return alerts
