"""
AEGIS Verifier Agent Node
Validates that each discovered finding contains verifiable empirical evidence (reachability proof,
service banner, response snippet, or CVE identifier).
Enforces loop bounds (maximum 2 verification cycles) when routing back to Executor for evidence collection.
"""

import logging
from typing import Dict, Any, List
from app.workflow.state import AgentWorkflowState, SanitizedFindingSchema, VerifiedFindingSchema
from app.core.tracing import aegis_tracer

logger = logging.getLogger(__name__)

MAX_VERIFICATION_LOOPS = 2

async def verifier_node(state: AgentWorkflowState) -> Dict[str, Any]:
    """
    Verifier Node:
    - Inspects each SanitizedFindingSchema for concrete technical evidence.
    - If findings lack evidence and verification_loops < MAX_VERIFICATION_LOOPS:
      triggers re-execution / targeted probe by setting needs_reverification=True.
    - If max loops reached: drops unverified findings and allows confirmed findings to proceed.
    - Traced with Langfuse tags and latency metrics.
    """
    parsed_findings_raw = state.get("parsed_findings", [])
    current_loops = state.get("verification_loops", 0)
    audit_trail = list(state.get("audit_trail", []))
    scan_id = state.get("scan_id")
    target = state.get("target", "")
    workspace_id = state.get("workspace_id")
    trace_id = state.get("trace_id") or aegis_tracer.get_or_create_trace_id(scan_id)

    async with aegis_tracer.trace_agent_step(
        trace_id=trace_id,
        step_name="empirical_evidence_verification",
        agent_name="VerifierAgent",
        scan_id=scan_id,
        target=target,
        workspace_id=workspace_id,
        input_data={"findings_to_verify": len(parsed_findings_raw), "loop": current_loops}
    ) as trace_ctx:
        verified_findings: List[VerifiedFindingSchema] = []
        unverified_count = 0

        for item in parsed_findings_raw:
            finding = SanitizedFindingSchema(**item)
            ev = (finding.evidence or "").strip()

            # Evidence validation criteria:
            # 1. Non-empty evidence snippet
            # 2. Must cite an open port, HTTP status/header, or CVE reference
            has_concrete_proof = (
                len(ev) >= 10 and
                ("port" in ev.lower() or "cve" in ev.lower() or "matched" in ev.lower() or "alert" in ev.lower())
            )

            if has_concrete_proof:
                verified_findings.append(
                    VerifiedFindingSchema(
                        id=finding.id,
                        tool_name=finding.tool_name,
                        finding_title=finding.finding_title,
                        target=finding.target,
                        severity=finding.severity,
                        cve_id=finding.cve_id,
                        evidence=finding.evidence,
                        endpoint_or_port=finding.endpoint_or_port,
                        reachability_verified=True,
                        verification_status="VERIFIED_WITH_EVIDENCE",
                        verification_notes="Empirical scanner evidence verified."
                    )
                )
            else:
                unverified_count += 1
                if current_loops < MAX_VERIFICATION_LOOPS:
                    # Request re-verification loop
                    verified_findings.append(
                        VerifiedFindingSchema(
                            id=finding.id,
                            tool_name=finding.tool_name,
                            finding_title=finding.finding_title,
                            target=finding.target,
                            severity=finding.severity,
                            cve_id=finding.cve_id,
                            evidence=finding.evidence,
                            endpoint_or_port=finding.endpoint_or_port,
                            reachability_verified=False,
                            verification_status="UNVERIFIED_PENDING_PROBE",
                            verification_notes=f"Missing concrete proof. Queued for verification loop #{current_loops + 1}."
                        )
                    )
                else:
                    # Discard finding after exceeding max loops
                    verified_findings.append(
                        VerifiedFindingSchema(
                            id=finding.id,
                            tool_name=finding.tool_name,
                            finding_title=finding.finding_title,
                            target=finding.target,
                            severity=finding.severity,
                            cve_id=finding.cve_id,
                            evidence=finding.evidence,
                            endpoint_or_port=finding.endpoint_or_port,
                            reachability_verified=False,
                            verification_status="DISCARDED_NO_EVIDENCE",
                            verification_notes=f"Discarded: Unable to verify proof within {MAX_VERIFICATION_LOOPS} verification cycles."
                        )
                    )

        # Determine whether we should route back to Executor
        needs_retry = (unverified_count > 0) and (current_loops < MAX_VERIFICATION_LOOPS)
        new_loop_count = current_loops + 1 if needs_retry else current_loops

        audit_trail.append({
            "agent": "Verifier",
            "action": "EVIDENCE_VERIFIED",
            "loop_cycle": current_loops,
            "verified_count": len([f for f in verified_findings if f.reachability_verified]),
            "unverified_count": unverified_count,
            "routing": "RETRY_EXECUTOR" if needs_retry else "PROCEED_TO_REASONING"
        })

        trace_ctx["output_data"] = {
            "verified_count": len([f for f in verified_findings if f.reachability_verified]),
            "unverified_count": unverified_count,
            "needs_retry": needs_retry
        }

        return {
            "verified_findings": [f.model_dump() for f in verified_findings],
            "needs_reverification": needs_retry,
            "verification_loops": new_loop_count,
            "max_verification_loops": MAX_VERIFICATION_LOOPS,
            "audit_trail": audit_trail,
            "trace_id": trace_id,
            "trace_url": aegis_tracer.get_trace_url(trace_id),
            "status": "VERIFICATION_LOOP_REQUESTED" if needs_retry else "VERIFICATION_COMPLETED"
        }

def route_verifier_decision(state: AgentWorkflowState) -> str:
    """
    Conditional edge router for Verifier:
    Routes back to 'planner' / 'executor' if needs_reverification is True and loops < MAX.
    Otherwise routes forward to 'reasoning'.
    """
    if state.get("needs_reverification", False) and state.get("verification_loops", 0) <= MAX_VERIFICATION_LOOPS:
        logger.info(f"Routing back to Planner/Executor for verification loop #{state.get('verification_loops')}")
        return "planner"
    return "reasoning"
