"""Pause the workflow to present patches; approval and dispatch use the authenticated API."""

from typing import Any, Dict

from langgraph.types import interrupt

from app.workflow.state import AgentWorkflowState


async def approval_gate_node(state: AgentWorkflowState) -> Dict[str, Any]:
    patches_to_review = [
        insight
        for insight in state.get("reasoned_insights", [])
        if insight.get("remediation_patch")
    ]
    audit_trail = list(state.get("audit_trail", []))

    if not patches_to_review:
        return {
            "status": "APPROVAL_SKIPPED_NO_PATCHES",
            "audit_trail": audit_trail,
        }

    review_payload = {
        "status": "WAITING_FOR_HUMAN_APPROVAL",
        "message": (
            "Review the patch. Workflow-thread decisions are not authenticated; "
            "use the authenticated remediation API to record approval and dispatch."
        ),
        "auto_merge_policy": "STRICTLY_DISABLED",
        "pending_patches": [
            {
                "finding_id": patch.get("finding_id"),
                "title": patch.get("title"),
                "patch_diff": patch.get("remediation_patch"),
                "score": patch.get("score"),
                "severity": patch.get("severity"),
            }
            for patch in patches_to_review
        ],
    }

    interrupt(review_payload)

    return {
        "dispatched_prs": [],
        "approval_status": "AUTHENTICATED_API_APPROVAL_REQUIRED",
        "audit_trail": audit_trail,
        "status": "REMEDIATION_DISPATCH_NOT_AUTHORIZED",
    }
