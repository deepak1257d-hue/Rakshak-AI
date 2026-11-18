"""
AEGIS Untrusted Parser Agent Node
Takes raw, potentially hostile scanner outputs, neutralizes prompt-injection payloads,
and coerces data strictly into Pydantic models (SanitizedFindingSchema).
Raw scanner output terminates here and never reaches the System Reasoning agent.
"""

import re
import logging
from typing import Dict, Any, List
from app.workflow.state import AgentWorkflowState, SanitizedFindingSchema
from app.models.domain import SeverityLevel
from app.core.tracing import aegis_tracer

logger = logging.getLogger(__name__)

# Known prompt-injection signatures and control markers
PROMPT_INJECTION_PATTERNS = [
    r"(?i)system\s*instruction\s*:",
    r"(?i)system\s*override\s*:",
    r"(?i)ignore\s+(all\s+)?previous\s+instructions?",
    r"(?i)you\s+are\s+now\s+in\s+developer\s+mode",
    r"(?i)you\s+are\s+now\s+(dan|an\s+unrestricted)\b",
    r"(?i)<\|im_start\|>",
    r"(?i)<\|im_end\|>",
    r"(?i)<\s*system_instruction\s*>",
    r"(?i)<\s*/\s*system_instruction\s*>",
    r"(?i)disregard\s+(all\s+)?(prior|previous)\s+directives?",
    r"(?i)forget\s+(all\s+)?(previous\s+)?instructions?",
    r"(?i)assistant\s*:",
    r"(?i)human\s*:",
    r"(?i)\[\s*(system|instruction)\s*\]",
    r"(?i)override\s+(all\s+)?safety\s+filters?"
]

def sanitize_untrusted_text(text: str, max_chars: int = 1000) -> str:
    """
    Strips prompt-injection payloads and neutralizes hostile markup/control sequences.
    """
    if not text:
        return ""
    sanitized = str(text)
    for pattern in PROMPT_INJECTION_PATTERNS:
        sanitized = re.sub(pattern, "[REDACTED_PROMPT_INJECTION]", sanitized)

    # Strip dangerous HTML/script tags
    sanitized = re.sub(r"(?i)<script.*?>.*?</script>", "[STRIPPED_SCRIPT]", sanitized)
    # Neutralize unbalanced markdown backticks
    sanitized = sanitized.replace("```", "'''")

    return sanitized[:max_chars].strip()

async def parser_node(state: AgentWorkflowState) -> Dict[str, Any]:
    """
    Parser Node:
    - Reads raw_tool_outputs from state.
    - Sanitizes any untrusted scanner stdout/responses.
    - Strictly coerces all discoveries into SanitizedFindingSchema Pydantic objects.
    - Traced via Langfuse with latency, token usage, and cost estimation.
    """
    raw_outputs = state.get("raw_tool_outputs", [])
    target = state.get("target", "")
    scan_id = state.get("scan_id")
    workspace_id = state.get("workspace_id")
    trace_id = state.get("trace_id") or aegis_tracer.get_or_create_trace_id(scan_id)
    parsed_findings: List[SanitizedFindingSchema] = []
    audit_trail = list(state.get("audit_trail", []))

    async with aegis_tracer.trace_agent_step(
        trace_id=trace_id,
        step_name="untrusted_parsing_sanitization",
        agent_name="UntrustedParser",
        scan_id=scan_id,
        target=target,
        workspace_id=workspace_id,
        input_data={"raw_outputs_count": len(raw_outputs)}
    ) as trace_ctx:
        for item in raw_outputs:
            tool_name = item.get("tool_name", "unknown")
            out = item.get("output", {})
            raw_text = str(out.get("raw_output", out.get("result", "")))
            evidence_hash = SanitizedFindingSchema.compute_hash(raw_text)

            # 1. Parse Nmap tool outputs
            if "nmap" in tool_name:
                open_ports = out.get("open_ports", [])
                for p in open_ports:
                    port_str = p.get("port", "")
                    service = p.get("service", "unknown")
                    version = sanitize_untrusted_text(p.get("version", ""))
                    has_evidence = bool(port_str and "open" in p.get("state", "open"))

                    parsed_findings.append(
                        SanitizedFindingSchema(
                            tool_name=tool_name,
                            finding_title=f"Exposed Service ({service}) on Port {port_str}",
                            target=target,
                            severity=SeverityLevel.HIGH if "ssh" in service.lower() else SeverityLevel.MEDIUM,
                            cve_id="CVE-2024-6387" if "openssh 8." in version.lower() else None,
                            evidence=sanitize_untrusted_text(f"Port {port_str} open, service: {service}, banner: {version}"),
                            endpoint_or_port=port_str,
                            has_evidence=has_evidence,
                            raw_evidence_hash=evidence_hash
                        )
                    )

            # 2. Parse Nuclei tool outputs
            elif "nuclei" in tool_name:
                findings_list = out.get("findings", [])
                for f in findings_list:
                    name = sanitize_untrusted_text(f.get("name", "Misconfiguration Detected"))
                    cve = f.get("cve")
                    matched = sanitize_untrusted_text(f.get("matched_at", target))
                    sev_raw = (f.get("severity") or "medium").upper()
                    sev = SeverityLevel.CRITICAL if sev_raw == "CRITICAL" else SeverityLevel.HIGH if sev_raw == "HIGH" else SeverityLevel.MEDIUM

                    parsed_findings.append(
                        SanitizedFindingSchema(
                            tool_name=tool_name,
                            finding_title=name,
                            target=target,
                            severity=sev,
                            cve_id=cve,
                            evidence=sanitize_untrusted_text(f"Matched at {matched}. Description: {f.get('description', '')}"),
                            endpoint_or_port=matched,
                            has_evidence=bool(matched),
                            raw_evidence_hash=evidence_hash
                        )
                    )

            # 3. Parse ZAP tool outputs
            elif "zap" in tool_name:
                alerts = out.get("alerts_found", [])
                for a in alerts:
                    alert_title = sanitize_untrusted_text(a.get("alert", "Web Application Alert"))
                    url = sanitize_untrusted_text(a.get("url", target))
                    ev = sanitize_untrusted_text(a.get("evidence", ""))
                    parsed_findings.append(
                        SanitizedFindingSchema(
                            tool_name=tool_name,
                            finding_title=alert_title,
                            target=target,
                            severity=SeverityLevel.LOW if "low" in str(a.get("risk", "")).lower() else SeverityLevel.MEDIUM,
                            cve_id=None,
                            evidence=sanitize_untrusted_text(f"Alert at {url}: {ev}"),
                            endpoint_or_port=url,
                            has_evidence=bool(ev or url),
                            raw_evidence_hash=evidence_hash
                        )
                    )

            # 4. Parse Trivy tool outputs
            elif "trivy" in tool_name:
                vulns = out.get("vulnerabilities", [])
                for v in vulns:
                    pkg = sanitize_untrusted_text(v.get("package_name", ""))
                    cve = v.get("vulnerability_id")
                    title = sanitize_untrusted_text(v.get("title", f"Vulnerable dependency in {pkg}"))
                    parsed_findings.append(
                        SanitizedFindingSchema(
                            tool_name=tool_name,
                            finding_title=title,
                            target=target,
                            severity=SeverityLevel.CRITICAL if v.get("severity") == "CRITICAL" else SeverityLevel.HIGH,
                            cve_id=cve,
                            evidence=sanitize_untrusted_text(f"Package {pkg} version {v.get('installed_version')} vulnerable to {cve}"),
                            endpoint_or_port=pkg,
                            has_evidence=bool(cve and pkg),
                            raw_evidence_hash=evidence_hash
                        )
                    )

        audit_trail.append({
            "agent": "UntrustedParser",
            "action": "SANITIZED_AND_PARSED",
            "raw_outputs_processed": len(raw_outputs),
            "sanitized_findings_count": len(parsed_findings),
            "prompt_injection_guardrail": "ENFORCED"
        })

        trace_ctx["output_data"] = {
            "sanitized_findings_count": len(parsed_findings),
            "guardrail": "ENFORCED"
        }

        return {
            "parsed_findings": [f.model_dump() for f in parsed_findings],
            "audit_trail": audit_trail,
            "trace_id": trace_id,
            "trace_url": aegis_tracer.get_trace_url(trace_id),
            "status": "PARSED_AND_SANITIZED"
        }
