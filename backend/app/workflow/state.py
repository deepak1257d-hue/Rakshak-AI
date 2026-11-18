"""
AEGIS Multi-Agent Workflow State & Typed Schemas
Defines Pydantic models for structured audit plans, sanitized findings,
verified evidence, and the LangGraph workflow state.
"""

import uuid
import hashlib
from typing import TypedDict, List, Dict, Any, Optional
from pydantic import BaseModel, Field
from app.models.domain import SeverityLevel

class ScanPhase(BaseModel):
    phase_name: str
    tool_name: str
    server_name: str
    parameters: Dict[str, Any] = Field(default_factory=dict)
    purpose: str
    status: str = "PENDING"  # PENDING, IN_PROGRESS, COMPLETED, FAILED, FALLBACK_COMPLETED, SKIPPED
    attempts: int = 0
    error_message: Optional[str] = None
    fallback_triggered: bool = False
    fallback_details: Optional[Dict[str, Any]] = None

class AuditPlan(BaseModel):
    target: str
    strategy: str
    phases: List[ScanPhase]
    revision_count: int = 0
    notes: Optional[str] = None
    execution_summary: Optional[Dict[str, Any]] = None

class SanitizedFindingSchema(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    tool_name: str
    finding_title: str
    target: str
    severity: SeverityLevel = SeverityLevel.MEDIUM
    cve_id: Optional[str] = None
    evidence: str
    endpoint_or_port: Optional[str] = None
    has_evidence: bool = True
    raw_evidence_hash: str

    @staticmethod
    def compute_hash(raw_text: str) -> str:
        return hashlib.sha256(raw_text.encode("utf-8", errors="ignore")).hexdigest()[:16]

class VerifiedFindingSchema(BaseModel):
    id: str
    tool_name: str
    finding_title: str
    target: str
    severity: SeverityLevel
    cve_id: Optional[str] = None
    evidence: str
    endpoint_or_port: Optional[str] = None
    reachability_verified: bool
    verification_status: str  # "VERIFIED_WITH_EVIDENCE", "UNVERIFIED_PENDING_PROBE", "DISCARDED"
    verification_notes: str

class ReasonedInsightSchema(BaseModel):
    finding_id: str
    title: str
    severity: SeverityLevel
    cve_id: Optional[str] = None
    score: Optional[int] = Field(default=None, ge=0, le=100)
    score_breakdown: Optional[Dict[str, Any]] = None
    score_explanation: Optional[str] = None
    business_impact: str
    technical_impact: str
    reachability_proof: str
    remediation_patch: str

class AgentWorkflowState(TypedDict):
    target: str
    target_id: Optional[str]
    scan_id: Optional[str]
    workspace_id: Optional[str]
    plan: Dict[str, Any]
    current_phase_index: int
    raw_tool_outputs: List[Dict[str, Any]]
    parsed_findings: List[Dict[str, Any]]
    verified_findings: List[Dict[str, Any]]
    needs_reverification: bool
    reasoned_insights: List[Dict[str, Any]]
    final_report: Dict[str, Any]
    verification_loops: int
    max_verification_loops: int
    dispatched_prs: List[Dict[str, Any]]
    approval_status: Optional[str]
    audit_trail: List[Dict[str, Any]]
    trace_id: Optional[str]
    trace_url: Optional[str]
    trace_metrics: Optional[Dict[str, Any]]
    status: str
