from pydantic import BaseModel, EmailStr, Field
from typing import Optional, List
from datetime import datetime
from app.models.domain import UserRole, VerificationStatus, VerificationMethod, ScanStatus, SeverityLevel

# Auth Schemas
class UserCreate(BaseModel):
    email: EmailStr
    password: str
    workspace_name: str
    role: Optional[UserRole] = UserRole.SECURITY_ANALYST

class Token(BaseModel):
    access_token: str
    token_type: str
    user_id: str
    email: str
    role: str
    workspace_id: str

class UserResponse(BaseModel):
    id: str
    email: str
    role: UserRole
    workspace_id: str
    created_at: datetime

    class Config:
        from_attributes = True

# Target Asset Schemas
class TargetCreate(BaseModel):
    domain: str
    verification_method: Optional[VerificationMethod] = VerificationMethod.DNS_TXT

class TargetResponse(BaseModel):
    id: str
    workspace_id: str
    domain: str
    verification_token: str
    verification_status: VerificationStatus
    verification_method: VerificationMethod
    lab_mode: bool = False # Backend reports True only if settings.ENV == "development" AND exact host in settings.DEV_LAB_HOSTS
    is_lab: bool = False # True if verification_method == LAB
    last_verified_at: Optional[datetime] = None
    created_at: datetime

    class Config:
        from_attributes = True

class TargetVerifyRequest(BaseModel):
    method: VerificationMethod
    simulate: Optional[bool] = None # Prohibited: any request with simulate=true is rejected by the server

# Scan Schemas
class ScanCreate(BaseModel):
    target_id: str

class ScanResponse(BaseModel):
    id: str
    workspace_id: str
    target_id: str
    status: ScanStatus
    progress_pct: int
    current_stage: str
    started_at: datetime
    completed_at: Optional[datetime] = None
    trace_id: Optional[str] = None
    trace_url: Optional[str] = None

    class Config:
        from_attributes = True

# Finding Schemas
class FindingResponse(BaseModel):
    id: str
    scan_id: str
    workspace_id: str
    title: str
    severity: SeverityLevel
    cve_id: Optional[str] = None
    score: Optional[int] = None
    score_source: Optional[str] = None
    reachability_proof: Optional[str] = None
    remediation_patch: Optional[str] = None
    sanitized_output: Optional[str] = None
    status: str
    created_at: datetime

    class Config:
        from_attributes = True

# Sanitized Parser Output Schema for Dual-LLM Guardrail
class RawToolResultSchema(BaseModel):
    tool_name: str
    raw_finding: str
    affected_host: str
    evidence: str
    potential_cve: Optional[str] = None

class RefinedSecurityInsightSchema(BaseModel):
    title: str
    severity: SeverityLevel
    score: int = Field(ge=0, le=100)
    business_impact: str
    technical_impact: str
    reachability_proof: str
    remediation_patch: str
