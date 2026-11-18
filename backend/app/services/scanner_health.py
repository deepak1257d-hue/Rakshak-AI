"""
AEGIS Security Scanners Health and Binary Detection Utility.
Checks installation status, paths, versions, and configurations for:
- Nmap
- OWASP ZAP
- Nuclei
- Trivy
Safe subprocess execution, structured output capture, and installation guidance.
"""

import asyncio
import os
import shutil
import re
from typing import Dict, Any, Optional
from app.core.config import settings

def find_scanner_binary(tool_name: str) -> Optional[str]:
    """Find absolute path for a scanner binary using settings overrides or PATH lookup."""
    tool = tool_name.lower()
    if tool == "nmap":
        return shutil.which("nmap")
    elif tool in ("zap", "owasp-zap", "owasp_zap"):
        if settings.ZAP_PATH and os.path.isfile(settings.ZAP_PATH):
            return settings.ZAP_PATH
        for candidate in ["zap.bat", "zap.sh", "zap-baseline.py", "zap-cli", "zap"]:
            found = shutil.which(candidate)
            if found:
                return found
    elif tool == "nuclei":
        if settings.NUCLEI_PATH and os.path.isfile(settings.NUCLEI_PATH):
            return settings.NUCLEI_PATH
        for candidate in ["nuclei.exe", "nuclei"]:
            found = shutil.which(candidate)
            if found:
                return found
    elif tool == "trivy":
        if settings.TRIVY_PATH and os.path.isfile(settings.TRIVY_PATH):
            return settings.TRIVY_PATH
        for candidate in ["trivy.exe", "trivy"]:
            found = shutil.which(candidate)
            if found:
                return found
    return None

async def get_scanner_version(tool_name: str, binary_path: str) -> Optional[str]:
    """Safely invokes scanner binary with version flag and extracts clean version string."""
    tool = tool_name.lower()
    arg = "-version" if tool == "nuclei" else "--version" if tool in ("trivy", "nmap") else "-version"
    try:
        proc = await asyncio.create_subprocess_exec(
            binary_path,
            arg,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=5.0)
        output = (stdout.decode("utf-8", errors="replace") + " " + stderr.decode("utf-8", errors="replace")).strip()
        match = re.search(r"(\d+\.\d+(\.\d+)?)", output)
        return match.group(1) if match else output.splitlines()[0][:40]
    except Exception:
        return None

async def check_all_scanners() -> Dict[str, Any]:
    """
    Checks health and installation status of all security scanners.
    Returns structured status, binary paths, versions, and installation guides.
    """
    scanners = {
        "nmap": {
            "name": "Nmap Network Scanner",
            "category": "Port Scanning & Service Fingerprinting",
            "install_guide": {
                "windows": "winget install Insecure.Nmap or download from https://nmap.org/download.html",
                "linux": "sudo apt-get install -y nmap"
            }
        },
        "zap": {
            "name": "OWASP ZAP",
            "category": "Web Application DAST Baseline",
            "install_guide": {
                "windows": "winget install OWASP.ZAP or download installer from https://www.zaproxy.org/download/",
                "linux": "sudo apt-get install -y zaproxy or docker pull zaproxy/zap-stable"
            }
        },
        "nuclei": {
            "name": "ProjectDiscovery Nuclei",
            "category": "CVE & Misconfiguration Template Engine",
            "install_guide": {
                "windows": "winget install ProjectDiscovery.Nuclei or go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
                "linux": "sudo apt install nuclei or binary release from https://github.com/projectdiscovery/nuclei/releases"
            }
        },
        "trivy": {
            "name": "Aqua Security Trivy",
            "category": "Software Composition Analysis (SCA) & Container Audit",
            "install_guide": {
                "windows": "winget install AquaSecurity.Trivy or scoop install trivy",
                "linux": "sudo apt-get install -y trivy or binary from https://github.com/aquasecurity/trivy/releases"
            }
        }
    }

    results = {}
    total_installed = 0

    for key, info in scanners.items():
        bin_path = find_scanner_binary(key)
        installed = bin_path is not None
        version = None
        if installed:
            version = await get_scanner_version(key, bin_path)
            total_installed += 1

        results[key] = {
            "name": info["name"],
            "category": info["category"],
            "installed": installed,
            "binary_path": bin_path,
            "version": version,
            "install_guide": info["install_guide"],
            "status": "READY" if installed else "UNAVAILABLE"
        }

    return {
        "total_scanners": len(scanners),
        "installed_count": total_installed,
        "all_ready": total_installed == len(scanners),
        "scanners": results
    }
