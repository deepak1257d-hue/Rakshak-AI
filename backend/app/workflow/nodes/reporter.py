"""
AEGIS Reporter Agent Node
Compiles verified security findings, reasoned remediation plans, and CTEM risk scores
into a comprehensive executive and technical security report.
"""

import logging
from datetime import datetime
from typing import Dict, Any, List
from app.workflow.state import AgentWorkflowState
from app.core.tracing import aegis_tracer

logger = logging.getLogger(__name__)

async def reporter_node(state: AgentWorkflowState) -> Dict[str, Any]:
    """
    Reporter Node:
    - Gathers verified findings and reasoned remediation diffs.
    - Computes aggregate exposure metrics.
    - Generates final audit report structure.
    - Exports Langfuse trace URL and telemetry metrics directly in report output.
    """
    target = state.get("target", "")
    insights = state.get("reasoned_insights", [])
    verified_findings = state.get("verified_findings", [])
    plan = state.get("plan", {})
    audit_trail = list(state.get("audit_trail", []))
    scan_id = state.get("scan_id")
    workspace_id = state.get("workspace_id")
    trace_id = state.get("trace_id") or aegis_tracer.get_or_create_trace_id(scan_id)
    trace_url = aegis_tracer.get_trace_url(trace_id)

    async with aegis_tracer.trace_agent_step(
        trace_id=trace_id,
        step_name="audit_report_synthesis",
        agent_name="ReporterAgent",
        scan_id=scan_id,
        target=target,
        workspace_id=workspace_id,
        input_data={"insights_count": len(insights)}
    ) as trace_ctx:
        # Calculate severity distributions
        severity_breakdown = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        scores: List[int] = []

        for ins in insights:
            sev = ins.get("severity", "MEDIUM")
            severity_breakdown[sev] = severity_breakdown.get(sev, 0) + 1
            score = ins.get("score")
            score_source = (ins.get("score_breakdown") or {}).get("score_source")
            if score is not None and score_source == "CURATED_CVE_CVSS_V3_1_BASE_CATALOG":
                scores.append(score)

        avg_score = int(sum(scores) / len(scores)) if scores else None
        max_score = max(scores) if scores else None

        execution_summary = plan.get("execution_summary") or {}
        is_partial = execution_summary.get("status") == "EXECUTION_PARTIAL_COMPLETED" or execution_summary.get("failed_count", 0) > 0
        final_status = "PARTIAL_COMPLETED" if is_partial else "COMPLETED"

        # Finalize telemetry metrics
        trace_metrics = aegis_tracer.finalize_trace(trace_id, status=final_status)

        final_report = {
            "target": target,
            "assessment_timestamp": datetime.utcnow().isoformat(),
            "status": final_status,
            "is_partial": is_partial,
            "trace_id": trace_id,
            "trace_url": trace_url,
            "trace_metrics": trace_metrics,
            "total_findings": len(insights),
            "severity_breakdown": severity_breakdown,
            "max_risk_score": max_score,
            "average_risk_score": avg_score,
            "risk_score_basis": (
                "CURATED_CVE_CVSS_V3_1_BASE_CATALOG" if scores else "UNAVAILABLE"
            ),
            "risk_score_scope": (
                "Scores are scaled CVSS base scores only; no environmental modifiers are applied."
            ),
            "findings": insights,
            "total_phases_executed": len(plan.get("phases", [])),
            "execution_summary": execution_summary,
            "verification_loops_performed": state.get("verification_loops", 0),
            "posture_status": (
                "UNSCORED" if max_score is None else
                "HIGH_CVSS_BASE_SCORE" if max_score >= 80 else
                "MODERATE_CVSS_BASE_SCORE" if max_score >= 60 else
                "LOW_CVSS_BASE_SCORE"
            )
        }

        audit_trail.append({
            "agent": "Reporter",
            "action": "FINAL_REPORT_SYNTHESIZED",
            "total_findings": len(insights),
            "status": final_status,
            "is_partial": is_partial,
            "trace_url": trace_url,
            "posture_status": final_report["posture_status"]
        })

        trace_ctx["output_data"] = {
            "findings": len(insights),
            "max_risk_score": max_score,
            "trace_url": trace_url
        }

        return {
            "final_report": final_report,
            "audit_trail": audit_trail,
            "trace_id": trace_id,
            "trace_url": trace_url,
            "trace_metrics": trace_metrics,
            "status": "COMPLETED"
        }
