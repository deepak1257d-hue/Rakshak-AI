"""Risk scoring from the curated CVSS v3.1 base-score catalog."""

from typing import Dict, Optional

from pydantic import BaseModel, Field

from app.models.domain import SeverityLevel


KNOWN_CVE_CVSS_CATALOG: Dict[str, float] = {
    "CVE-2024-6387": 8.1,
    "CVE-2023-4863": 8.8,
    "CVE-2024-21626": 8.6,
    "CVE-2024-3094": 10.0,
    "CVE-2023-38606": 7.8,
    "CVE-2021-44228": 10.0,
    "CVE-2022-22965": 9.8,
}


class RiskScoreBreakdown(BaseModel):
    cve_id: Optional[str] = None
    score_source: Optional[str] = None
    base_cvss_score: Optional[float] = Field(default=None, ge=0.0, le=10.0)
    base_score_scaled: Optional[int] = Field(default=None, ge=0, le=100)
    exposure_modifiers: Dict[str, int] = Field(default_factory=dict)
    total_modifier_points: int = 0
    final_risk_score: Optional[int] = Field(default=None, ge=0, le=100)
    severity: SeverityLevel
    calculation_formula: str
    deterministic_explanation: str


def compute_deterministic_risk_score(
    severity: SeverityLevel,
    cve_id: Optional[str] = None,
) -> RiskScoreBreakdown:
    """Return a scaled CVSS base score only when the CVE is in the curated catalog."""
    clean_cve = cve_id.strip().upper() if cve_id else None
    base_cvss = KNOWN_CVE_CVSS_CATALOG.get(clean_cve or "")
    if base_cvss is None:
        return RiskScoreBreakdown(
            cve_id=clean_cve,
            severity=severity,
            calculation_formula="No score calculated: no curated CVSS v3.1 base score is available.",
            deterministic_explanation=(
                f"No numeric score is available for {clean_cve or 'this finding'} because "
                "its CVSS v3.1 base score is not present in the curated catalog. "
                "The scanner-provided severity label is retained; no exposure or exploitability "
                "assumptions are applied."
            ),
        )

    score = int(round(base_cvss * 10))
    if base_cvss >= 9.0:
        computed_severity = SeverityLevel.CRITICAL
    elif base_cvss >= 7.0:
        computed_severity = SeverityLevel.HIGH
    elif base_cvss >= 4.0:
        computed_severity = SeverityLevel.MEDIUM
    else:
        computed_severity = SeverityLevel.LOW

    return RiskScoreBreakdown(
        cve_id=clean_cve,
        score_source="CURATED_CVE_CVSS_V3_1_BASE_CATALOG",
        base_cvss_score=base_cvss,
        base_score_scaled=score,
        exposure_modifiers={},
        total_modifier_points=0,
        final_risk_score=score,
        severity=computed_severity,
        calculation_formula=f"CVSS v3.1 base score {base_cvss} x 10 = {score}/100; no environmental modifiers.",
        deterministic_explanation=(
            f"The score is the curated CVSS v3.1 base score {base_cvss}, scaled to {score}/100. "
            "No asset exposure, authentication, exploit availability, or compensating-control "
            "modifiers were applied because those inputs are not independently measured."
        ),
    )
