import uuid
from datetime import datetime
from enum import Enum
from sqlalchemy import Column, String, DateTime, ForeignKey, Integer, Text, Enum as SQLEnum
from sqlalchemy.orm import relationship
from app.core.database import Base

class UserRole(str, Enum):
    ADMIN = "ADMIN"
    SECURITY_ANALYST = "SECURITY_ANALYST"
    AUDITOR = "AUDITOR"

class VerificationStatus(str, Enum):
    PENDING = "PENDING"
    VERIFIED = "VERIFIED"
    FAILED = "FAILED"

class VerificationMethod(str, Enum):
    DNS_TXT = "DNS_TXT"
    HTML_META = "HTML_META"
    HTTP_FILE = "HTTP_FILE" # /.well-known/aegis-verification.txt
    LAB = "LAB" # Development lab override (Ownership NOT empirically proven)

class ScanStatus(str, Enum):
    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    PARTIAL = "PARTIAL"

class SeverityLevel(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"

class Workspace(Base):
    __tablename__ = "workspaces"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    name = Column(String, nullable=False)
    slug = Column(String, unique=True, index=True, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    users = relationship("User", back_populates="workspace", cascade="all, delete-orphan")
    targets = relationship("TargetAsset", back_populates="workspace", cascade="all, delete-orphan")

class User(Base):
    __tablename__ = "users"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    role = Column(SQLEnum(UserRole), default=UserRole.SECURITY_ANALYST, nullable=False)
    workspace_id = Column(String, ForeignKey("workspaces.id"), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    workspace = relationship("Workspace", back_populates="users")

class TargetAsset(Base):
    __tablename__ = "target_assets"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    workspace_id = Column(String, ForeignKey("workspaces.id"), nullable=False)
    domain = Column(String, index=True, nullable=False)
    verification_token = Column(String, nullable=False)
    verification_status = Column(SQLEnum(VerificationStatus), default=VerificationStatus.PENDING, nullable=False)
    verification_method = Column(SQLEnum(VerificationMethod), default=VerificationMethod.DNS_TXT, nullable=False)
    last_verified_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    workspace = relationship("Workspace", back_populates="targets")
    scans = relationship("ScanRun", back_populates="target", cascade="all, delete-orphan")

class ScanRun(Base):
    __tablename__ = "scan_runs"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    workspace_id = Column(String, ForeignKey("workspaces.id"), nullable=False)
    target_id = Column(String, ForeignKey("target_assets.id"), nullable=False)
    status = Column(SQLEnum(ScanStatus), default=ScanStatus.QUEUED, nullable=False)
    progress_pct = Column(Integer, default=0)
    current_stage = Column(String, default="INITIALIZING")
    started_at = Column(DateTime, default=datetime.utcnow)
    completed_at = Column(DateTime, nullable=True)
    trace_id = Column(String, nullable=True)
    trace_url = Column(String, nullable=True)

    target = relationship("TargetAsset", back_populates="scans")
    findings = relationship("Finding", back_populates="scan", cascade="all, delete-orphan")

class Finding(Base):
    __tablename__ = "findings"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id = Column(String, ForeignKey("scan_runs.id"), nullable=False)
    workspace_id = Column(String, ForeignKey("workspaces.id"), nullable=False)
    title = Column(String, nullable=False)
    severity = Column(SQLEnum(SeverityLevel), nullable=False)
    cve_id = Column(String, nullable=True)
    score = Column(Integer, nullable=True)
    score_source = Column(String, nullable=True)
    reachability_proof = Column(Text, nullable=True)
    remediation_patch = Column(Text, nullable=True)
    sanitized_output = Column(Text, nullable=True)
    status = Column(String, default="OPEN") # OPEN, VERIFIED, REMEDIATED
    created_at = Column(DateTime, default=datetime.utcnow)

    scan = relationship("ScanRun", back_populates="findings")

class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    workspace_id = Column(String, ForeignKey("workspaces.id"), nullable=False)
    actor_id = Column(String, nullable=False)
    action = Column(String, nullable=False)
    resource_type = Column(String, nullable=False)
    resource_id = Column(String, nullable=False)
    remediation_hash = Column(String, nullable=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    ip_address = Column(String, nullable=True)
