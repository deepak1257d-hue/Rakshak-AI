import pytest

from app.workflow.nodes import approval_gate


@pytest.mark.parametrize("action", ["APPROVE", "REJECT"])
@pytest.mark.asyncio
async def test_workflow_thread_decision_cannot_authorize_or_dispatch(action, monkeypatch):
    interrupt_payloads = []

    def untrusted_resume(payload):
        interrupt_payloads.append(payload)
        return {
            "action": action,
            "actor_id": "untrusted-workflow-user",
            "actor_email": "untrusted@example.test",
        }

    monkeypatch.setattr(approval_gate, "interrupt", untrusted_resume)
    result = await approval_gate.approval_gate_node({
        "reasoned_insights": [{
            "finding_id": "finding-1",
            "title": "Test finding",
            "severity": "HIGH",
            "score": None,
            "remediation_patch": "safe patch",
        }],
        "audit_trail": [],
    })

    assert len(interrupt_payloads) == 1
    assert interrupt_payloads[0]["status"] == "WAITING_FOR_HUMAN_APPROVAL"
    assert result["status"] == "REMEDIATION_DISPATCH_NOT_AUTHORIZED"
    assert result["approval_status"] == "AUTHENTICATED_API_APPROVAL_REQUIRED"
    assert result["dispatched_prs"] == []
    assert result["audit_trail"] == []
