"""
AEGIS Planner Agent Node
Formulates structured audit plans and dynamically revises them based on intermediate scan discoveries.
"""

import logging
from typing import Dict, Any, List
from app.workflow.state import AgentWorkflowState, AuditPlan, ScanPhase
from app.core.tracing import aegis_tracer

logger = logging.getLogger(__name__)

async def planner_node(state: AgentWorkflowState) -> Dict[str, Any]:
    """
    Planner Node:
    - Generates structured AuditPlan if none exists.
    - Revises plan when new surface exposures are detected or verification loops request additional evidence.
    - Traced with Langfuse tags (scan_id, target, workspace_id), latency, and token metrics.
    """
    target = state.get("target", "")
    existing_plan_data = state.get("plan")
    verification_loops = state.get("verification_loops", 0)
    audit_trail = list(state.get("audit_trail", []))
    scan_id = state.get("scan_id")
    workspace_id = state.get("workspace_id")
    trace_id = state.get("trace_id") or aegis_tracer.get_or_create_trace_id(scan_id)

    async with aegis_tracer.trace_agent_step(
        trace_id=trace_id,
        step_name="plan_formulation",
        agent_name="PlannerAgent",
        scan_id=scan_id,
        target=target,
        workspace_id=workspace_id,
        input_data={"target": target, "has_existing_plan": bool(existing_plan_data), "verification_loops": verification_loops}
    ) as trace_ctx:
        if not existing_plan_data:
            # Formulate initial multi-stage CTEM audit plan
            phases = [
                ScanPhase(
                    phase_name="Network & Port Service Discovery",
                    tool_name="nmap_port_scan",
                    server_name="nmap",
                    parameters={"ports": "3000,8000", "scan_mode": "service_version"},
                    purpose="Identify exposed network ports and running daemon version banners."
                ),
                ScanPhase(
                    phase_name="Vulnerability & Misconfiguration Audit",
                    tool_name="nuclei_scan",
                    server_name="nuclei",
                    parameters={"severity": "low,medium,high,critical", "tags": "cve,misconfig,exposure"},
                    purpose="Audit for known CVEs, outdated headers, and web misconfigurations."
                ),
                ScanPhase(
                    phase_name="Web Baseline Security Analysis",
                    tool_name="zap_baseline_scan",
                    server_name="zap",
                    parameters={"scan_mode": "passive_baseline"},
                    purpose="Verify passive HTTP security controls (HSTS, CSP, Cookies, CSRF)."
                )
            ]

            plan = AuditPlan(
                target=target,
                strategy="Deterministic External Attack Surface Management (EASM)",
                phases=phases,
                revision_count=0,
                notes="Initial automated CTEM assessment plan."
            )

            audit_trail.append({
                "agent": "Planner",
                "action": "PLAN_CREATED",
                "phases_count": len(phases),
                "revision": 0
            })

            result = {
                "plan": plan.model_dump(),
                "audit_trail": audit_trail,
                "trace_id": trace_id,
                "trace_url": aegis_tracer.get_trace_url(trace_id),
                "status": "PLAN_FORMULATED"
            }
            trace_ctx["output_data"] = {"strategy": plan.strategy, "phases": len(phases)}
            return result

        # Plan Revision Logic
        existing_plan = AuditPlan(**existing_plan_data)
        revised_phases = list(existing_plan.phases)

        # If verification loop requested additional evidence for a specific port or finding:
        if state.get("needs_reverification", False):
            revised_phases.append(
                ScanPhase(
                    phase_name=f"Targeted Service Probe [Loop #{verification_loops}]",
                    tool_name="nmap_service_probe",
                    server_name="nmap",
                    parameters={"port": 22},
                    purpose="Acquire concrete service banner evidence to verify unproven finding."
                )
            )
            existing_plan.revision_count += 1
            existing_plan.phases = revised_phases
            existing_plan.notes = f"Plan revised in verification loop #{verification_loops} to collect missing evidence."

            audit_trail.append({
                "agent": "Planner",
                "action": "PLAN_REVISED",
                "reason": f"Verification loop #{verification_loops} requested targeted service probe",
                "revision": existing_plan.revision_count
            })

        result = {
            "plan": existing_plan.model_dump(),
            "audit_trail": audit_trail,
            "trace_id": trace_id,
            "trace_url": aegis_tracer.get_trace_url(trace_id),
            "status": "PLAN_ACTIVE"
        }
        trace_ctx["output_data"] = {"revision": existing_plan.revision_count, "phases": len(existing_plan.phases)}
        return result

