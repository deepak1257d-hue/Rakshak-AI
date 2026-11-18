import pytest
import pytest_asyncio
import uuid
import asyncio
from unittest.mock import patch, AsyncMock
from app.core.database import Base, engine, AsyncSessionLocal
from app.models.domain import TargetAsset, VerificationStatus, VerificationMethod, Workspace, ScanStatus
from app.workflow.state import AgentWorkflowState, AuditPlan, ScanPhase
from app.workflow.nodes.executor import executor_node, execute_with_exponential_backoff, FALLBACK_TOOL_CHAINS
from app.workflow.nodes.reporter import reporter_node
from app.mcp.client import mcp_registry

@pytest_asyncio.fixture(scope="function", autouse=True)
async def setup_db():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield

@pytest.mark.asyncio
async def test_exponential_backoff_retries_on_transient_failure():
    """Verify that execute_with_exponential_backoff retries failed calls before giving up."""
    call_counts = {"count": 0}

    async def flaky_tool(server, tool, args):
        call_counts["count"] += 1
        if call_counts["count"] < 2:
            return {"status": "ERROR", "error": "Transient connection reset by peer"}
        return {"status": "SUCCESS", "result": "Flaky tool succeeded on retry"}

    with patch.object(mcp_registry, "call_tool", side_effect=flaky_tool):
        res = await execute_with_exponential_backoff(
            server_name="nmap",
            tool_name="nmap_port_scan",
            parameters={"target": "test.local"},
            max_retries=2,
            initial_delay=0.01,
            backoff_factor=1.5
        )
        assert res.get("status") == "SUCCESS"
        assert call_counts["count"] == 2

@pytest.mark.asyncio
async def test_fallback_routing_when_zap_fails():
    """Verify that when ZAP baseline fails, the Executor automatically falls back to Nuclei."""
    async def selective_mock(server, tool, args):
        if tool == "zap_baseline_scan":
            return {"status": "ERROR", "error": "ZAP daemon unreachable on port 8080"}
        if tool == "nuclei_scan":
            return {
                "status": "SUCCESS",
                "findings": [{"name": "Fallback Nuclei Header Finding", "severity": "medium", "matched_at": "test.local"}],
                "raw_output": "Fallback Nuclei succeeded"
            }
        return {"status": "SUCCESS", "open_ports": []}

    plan = AuditPlan(
        target="test.local",
        strategy="Test Fallback",
        phases=[
            ScanPhase(
                phase_name="Web Baseline Check",
                tool_name="zap_baseline_scan",
                server_name="zap",
                parameters={"scan_mode": "passive_baseline"},
                purpose="Test fallback from ZAP to Nuclei"
            )
        ]
    )

    state: AgentWorkflowState = {
        "target": "test.local",
        "target_id": None,
        "scan_id": None,
        "workspace_id": None,
        "plan": plan.model_dump(),
        "current_phase_index": 0,
        "raw_tool_outputs": [],
        "parsed_findings": [],
        "verified_findings": [],
        "needs_reverification": False,
        "reasoned_insights": [],
        "final_report": {},
        "verification_loops": 0,
        "max_verification_loops": 2,
        "audit_trail": [],
        "status": ""
    }

    with patch.object(mcp_registry, "call_tool", side_effect=selective_mock):
        exec_res = await executor_node(state)
        updated_plan = AuditPlan(**exec_res["plan"])
        phase = updated_plan.phases[0]

        # Verify fallback was triggered and succeeded
        assert phase.status == "FALLBACK_COMPLETED"
        assert phase.fallback_triggered is True
        assert phase.fallback_details["fallback_tool"] == "nuclei_scan"
        assert "ZAP daemon unreachable" in phase.fallback_details["primary_error"]

        # Raw output should contain the fallback result
        raw_outputs = exec_res["raw_tool_outputs"]
        assert len(raw_outputs) == 1
        assert raw_outputs[0]["is_fallback"] is True
        assert raw_outputs[0]["tool_name"] == "nuclei_scan"

@pytest.mark.asyncio
async def test_partial_results_allowed_when_one_scanner_fails():
    """Verify that partial results are preserved and the report reflects PARTIAL_COMPLETED state."""
    async def mock_mixed_tools(server, tool, args):
        if tool == "nmap_port_scan":
            return {"status": "SUCCESS", "open_ports": [{"port": "80/tcp", "service": "http", "state": "open"}]}
        if tool == "trivy_scan":
            # Unrecoverable error with no fallback
            return {"status": "ERROR", "error": "Fatal container manifest read error"}
        return {"status": "SUCCESS"}

    plan = AuditPlan(
        target="test-partial.org",
        strategy="Test Partial Execution",
        phases=[
            ScanPhase(
                phase_name="Network Recon",
                tool_name="nmap_port_scan",
                server_name="nmap",
                purpose="Network ports"
            ),
            ScanPhase(
                phase_name="Filesystem Dependency Scan",
                tool_name="trivy_scan",
                server_name="trivy",
                purpose="Dependencies"
            )
        ]
    )

    state: AgentWorkflowState = {
        "target": "test-partial.org",
        "target_id": None,
        "scan_id": None,
        "workspace_id": None,
        "plan": plan.model_dump(),
        "current_phase_index": 0,
        "raw_tool_outputs": [],
        "parsed_findings": [],
        "verified_findings": [],
        "needs_reverification": False,
        "reasoned_insights": [
            {
                "finding_id": "f-1",
                "title": "Open Port 80",
                "severity": "MEDIUM",
                "score": 60,
                "business_impact": "Impact",
                "technical_impact": "Impact",
                "reachability_proof": "Proof",
                "remediation_patch": "Patch"
            }
        ],
        "final_report": {},
        "verification_loops": 0,
        "max_verification_loops": 2,
        "audit_trail": [],
        "status": ""
    }

    with patch.object(mcp_registry, "call_tool", side_effect=mock_mixed_tools):
        exec_res = await executor_node(state)
        # Verify partial status recorded in executor
        assert exec_res["status"] == "EXECUTION_PARTIAL_COMPLETED"
        summary = exec_res["plan"]["execution_summary"]
        assert summary["completed_count"] == 1
        assert summary["failed_count"] == 1

        # Now pass to reporter_node
        state["plan"] = exec_res["plan"]
        report_res = await reporter_node(state)
        final_rep = report_res["final_report"]

        assert final_rep["status"] == "PARTIAL_COMPLETED"
        assert final_rep["is_partial"] is True
        assert final_rep["total_findings"] == 1
        assert final_rep["execution_summary"]["failed_count"] == 1
