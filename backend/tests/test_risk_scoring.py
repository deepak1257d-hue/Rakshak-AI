import pytest

from app.models.domain import SeverityLevel
from app.workflow.nodes.reasoning import reasoning_node
from app.workflow.risk_engine import (
    KNOWN_CVE_CVSS_CATALOG,
    compute_deterministic_risk_score,
)
from app.workflow.state import AgentWorkflowState, VerifiedFindingSchema


def test_known_cve_uses_curated_cvss_base_score_without_unverified_modifiers():
    breakdown = compute_deterministic_risk_score(
        severity=SeverityLevel.HIGH,
        cve_id="cve-2024-6387",
    )

    assert breakdown.base_cvss_score == KNOWN_CVE_CVSS_CATALOG["CVE-2024-6387"] == 8.1
    assert breakdown.base_score_scaled == 81
    assert breakdown.final_risk_score == 81
    assert breakdown.severity == SeverityLevel.HIGH
    assert breakdown.exposure_modifiers == {}
    assert breakdown.total_modifier_points == 0
    assert breakdown.score_source == "CURATED_CVE_CVSS_V3_1_BASE_CATALOG"
    assert "no environmental modifiers" in breakdown.calculation_formula


def test_unknown_or_missing_cve_has_no_invented_numeric_score():
    for cve_id in (None, "CVE-2099-00001"):
        breakdown = compute_deterministic_risk_score(
            severity=SeverityLevel.MEDIUM,
            cve_id=cve_id,
        )
        assert breakdown.final_risk_score is None
        assert breakdown.base_cvss_score is None
        assert breakdown.score_source is None
        assert breakdown.severity == SeverityLevel.MEDIUM
        assert "No score calculated" in breakdown.calculation_formula


@pytest.mark.asyncio
async def test_reasoning_node_reports_unavailable_score_without_cve():
    verified_finding = VerifiedFindingSchema(
        id="finding-test-unscored",
        tool_name="nmap_port_scan",
        finding_title="Exposed Service on Port 22/tcp",
        target="acme-defense.io",
        severity=SeverityLevel.HIGH,
        evidence="Port 22/tcp open",
        endpoint_or_port="22",
        reachability_verified=True,
        verification_status="VERIFIED_WITH_EVIDENCE",
        verification_notes="Scanner evidence verified.",
    )
    state: AgentWorkflowState = {
        "target": "acme-defense.io",
        "target_id": None,
        "scan_id": None,
        "workspace_id": None,
        "plan": {},
        "current_phase_index": 0,
        "raw_tool_outputs": [],
        "parsed_findings": [],
        "verified_findings": [verified_finding.model_dump()],
        "needs_reverification": False,
        "reasoned_insights": [],
        "final_report": {},
        "verification_loops": 0,
        "max_verification_loops": 2,
        "dispatched_prs": [],
        "approval_status": None,
        "audit_trail": [],
        "trace_id": None,
        "trace_url": None,
        "trace_metrics": None,
        "status": "",
    }

    result = await reasoning_node(state)
    insight = result["reasoned_insights"][0]
    assert insight["score"] is None
    assert insight["score_breakdown"]["final_risk_score"] is None
    assert "Risk score unavailable." in insight["business_impact"]
    assert "no exposure or exploitability assumptions" in insight["score_explanation"]
