import hashlib
from fastapi import APIRouter, Depends, HTTPException
from typing import List, Dict, Any, Optional, Literal
from datetime import datetime
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update
from app.core.database import get_db
from app.api.v1.auth import get_current_user
from app.models.domain import User, UserRole, Finding, ScanRun, TargetAsset, AuditLog, VerificationMethod
from app.schemas.domain import FindingResponse
from app.mcp.client import mcp_registry

router = APIRouter(prefix="/reports", tags=["CISO Reports & Findings"])

class GitHubPRRequest(BaseModel):
    finding_id: str
    repo_name: str = "infrastructure-repo"

class ApprovalDecisionRequest(BaseModel):
    finding_id: str
    action: Literal["APPROVE", "REJECT"] = "APPROVE"
    repo_name: str = "infrastructure-repo"
    thread_id: Optional[str] = None
    notes: Optional[str] = None


def _remediation_hash(patch: str, repo_name: str) -> str:
    approval_scope = f"{repo_name}\0{patch}"
    return hashlib.sha256(approval_scope.encode("utf-8")).hexdigest()


def _require_approver(user: User) -> None:
    if user.role not in (UserRole.ADMIN, UserRole.SECURITY_ANALYST):
        raise HTTPException(status_code=403, detail="Only administrators and security analysts may approve remediation.")


async def _dispatch_approved_finding(
    finding: Finding,
    current_user: User,
    repo_name: str,
    db: AsyncSession,
) -> Dict[str, Any]:
    if not finding.remediation_patch:
        raise HTTPException(status_code=400, detail="No remediation patch available for this finding.")

    patch_hash = _remediation_hash(finding.remediation_patch, repo_name)
    approval = await db.execute(
        select(AuditLog.id).where(
            AuditLog.workspace_id == current_user.workspace_id,
            AuditLog.actor_id == current_user.id,
            AuditLog.action == "REMEDIATION_APPROVED",
            AuditLog.resource_type == "FINDING",
            AuditLog.resource_id == finding.id,
            AuditLog.remediation_hash == patch_hash,
        ).limit(1)
    )
    if approval.scalar_one_or_none() is None:
        raise HTTPException(status_code=403, detail="A matching approval by the authenticated user is required.")

    claim = await db.execute(
        update(Finding)
        .where(
            Finding.id == finding.id,
            Finding.workspace_id == current_user.workspace_id,
            Finding.status == "REMEDIATION_APPROVED",
        )
        .values(status="REMEDIATION_PR_DISPATCHING")
    )
    if claim.rowcount != 1:
        await db.rollback()
        raise HTTPException(status_code=409, detail="Finding is not awaiting dispatch or was already dispatched.")
    await db.commit()

    pr_res = await mcp_registry.call_tool("github", "create_pull_request", {
        "repo_name": repo_name,
        "finding_title": finding.title,
        "remediation_patch": finding.remediation_patch,
        "cve_id": finding.cve_id
    })
    if pr_res.get("status") == "UNAVAILABLE":
        reset = await db.execute(
            update(Finding)
            .where(
                Finding.id == finding.id,
                Finding.workspace_id == current_user.workspace_id,
                Finding.status == "REMEDIATION_PR_DISPATCHING",
            )
            .values(status="REMEDIATION_APPROVED")
        )
        if reset.rowcount != 1:
            await db.rollback()
            raise HTTPException(status_code=409, detail="Finding dispatch state changed unexpectedly.")
        await db.commit()
        raise HTTPException(
            status_code=503,
            detail=pr_res.get("error", "Pull request dispatch is unavailable; no pull request was created."),
        )

    if pr_res.get("status") != "SUCCESS" or not pr_res.get("pr_url"):
        raise HTTPException(
            status_code=502,
            detail="Pull request dispatch failed; the finding remains locked for reconciliation."
        )

    completion = await db.execute(
        update(Finding)
        .where(
            Finding.id == finding.id,
            Finding.workspace_id == current_user.workspace_id,
            Finding.status == "REMEDIATION_PR_DISPATCHING",
        )
        .values(status="REMEDIATION_PR_DISPATCHED")
    )
    if completion.rowcount != 1:
        await db.rollback()
        raise HTTPException(status_code=409, detail="Finding dispatch state changed unexpectedly.")

    db.add(AuditLog(
        workspace_id=current_user.workspace_id,
        actor_id=current_user.id,
        action="REMEDIATION_PR_APPROVED_AND_DISPATCHED",
        resource_type="FINDING",
        resource_id=finding.id,
        remediation_hash=patch_hash,
        timestamp=datetime.utcnow()
    ))
    await db.commit()

    return {
        **pr_res,
        "success": True,
        "status": "OPEN",
    }

@router.get("/findings", response_model=List[FindingResponse])
async def list_findings(current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Finding).where(Finding.workspace_id == current_user.workspace_id))
    return result.scalars().all()

@router.get("/executive-summary/{scan_id}", response_model=Dict[str, Any])
async def get_executive_summary(scan_id: str, current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    scan_res = await db.execute(select(ScanRun).where(ScanRun.id == scan_id, ScanRun.workspace_id == current_user.workspace_id))
    scan = scan_res.scalars().first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan run not found.")

    findings_res = await db.execute(select(Finding).where(Finding.scan_id == scan_id))
    findings = findings_res.scalars().all()

    target_res = await db.execute(select(TargetAsset).where(TargetAsset.id == scan.target_id))
    target = target_res.scalars().first()

    scored_findings = [
        finding.score
        for finding in findings
        if finding.score is not None
        and finding.score_source == "CURATED_CVE_CVSS_V3_1_BASE_CATALOG"
    ]
    avg_score = int(sum(scored_findings) / len(scored_findings)) if scored_findings else None
    critical_count = sum(1 for f in findings if f.severity.value == "CRITICAL")
    high_count = sum(1 for f in findings if f.severity.value == "HIGH")
    is_partial = scan.status == "PARTIAL"

    is_lab = bool(target and getattr(target, "verification_method", None) == VerificationMethod.LAB)
    verification_method = target.verification_method.value if target else "UNKNOWN"

    return {
        "scan_id": scan.id,
        "scan_status": scan.status.value,
        "is_partial": is_partial,
        "current_stage": scan.current_stage,
        "target_domain": target.domain if target else "Unknown",
        "target_verification_method": verification_method,
        "is_lab_target": is_lab,
        "ownership_badge": "LAB - not proven ownership" if is_lab else "OWNERSHIP PROVEN",
        "ownership_warning": (
            "LAB TARGET: Ownership not proven via cryptographic public DNS or HTTP records. "
            "Verified under development lab bypass."
            if is_lab else None
        ),
        "composite_risk_score": None,
        "average_risk_score": avg_score,
        "risk_score_basis": (
            "CURATED_CVE_CVSS_V3_1_BASE_CATALOG" if scored_findings else "UNAVAILABLE"
        ),
        "risk_score_scope": (
            "Arithmetic mean of scaled CVSS v3.1 base scores only; this is not a composite or "
            "environmental risk score."
        ),
        "total_findings": len(findings),
        "critical_count": critical_count,
        "high_count": high_count,
        "trace_id": scan.trace_id,
        "trace_url": scan.trace_url,
        "time_to_remediate_estimate": None,
        "time_to_remediate_status": "NOT_CALCULATED",
        "findings": [FindingResponse.model_validate(f).model_dump() for f in findings]
    }

@router.post("/remediate/decision", response_model=Dict[str, Any])
async def submit_remediation_approval_decision(
    decision_in: ApprovalDecisionRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Human-in-the-Loop decision gate:
    Analyst approves or rejects remediation patch. Auto-merge stays disabled.
    Audit log entry is recorded with approver ID and timestamp.
    """
    result = await db.execute(
        select(Finding).where(
            Finding.id == decision_in.finding_id,
            Finding.workspace_id == current_user.workspace_id
        )
    )
    finding = result.scalars().first()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found.")

    _require_approver(current_user)

    if decision_in.thread_id:
        raise HTTPException(
            status_code=400,
            detail="Workflow thread approvals are not supported by this endpoint."
        )

    if decision_in.action == "APPROVE":
        if not finding.remediation_patch:
            raise HTTPException(status_code=400, detail="No remediation patch available for this finding.")

        patch_hash = _remediation_hash(finding.remediation_patch, decision_in.repo_name)
        db.add(AuditLog(
            workspace_id=current_user.workspace_id,
            actor_id=current_user.id,
            action="REMEDIATION_APPROVED",
            resource_type="FINDING",
            resource_id=finding.id,
            remediation_hash=patch_hash,
            timestamp=datetime.utcnow()
        ))
        approval = await db.execute(
            update(Finding)
            .where(
                Finding.id == finding.id,
                Finding.workspace_id == current_user.workspace_id,
                Finding.status.in_(("OPEN", "VERIFIED")),
            )
            .values(status="REMEDIATION_APPROVED")
        )
        if approval.rowcount != 1:
            await db.rollback()
            raise HTTPException(status_code=409, detail="Finding is not eligible for approval or was already handled.")
        await db.commit()

        pr_res = await _dispatch_approved_finding(
            finding, current_user, decision_in.repo_name, db
        )
        return {
            "success": True,
            "action": "APPROVED",
            "approver": current_user.email,
            "approver_id": current_user.id,
            "auto_merge_disabled": True,
            "pr_url": pr_res.get("pr_url"),
            "branch_name": pr_res.get("branch_name"),
            "message": f"Remediation patch approved by {current_user.email}. PR created with auto-merge disabled."
        }

    else:
        rejection = await db.execute(
            update(Finding)
            .where(
                Finding.id == finding.id,
                Finding.workspace_id == current_user.workspace_id,
                Finding.status.in_(("OPEN", "VERIFIED")),
            )
            .values(status="REMEDIATION_REJECTED")
        )
        if rejection.rowcount != 1:
            await db.rollback()
            raise HTTPException(status_code=409, detail="Finding is not eligible for rejection or was already handled.")
        db.add(AuditLog(
            workspace_id=current_user.workspace_id,
            actor_id=current_user.id,
            action="REMEDIATION_PR_REJECTED",
            resource_type="FINDING",
            resource_id=finding.id,
            timestamp=datetime.utcnow()
        ))
        await db.commit()

        return {
            "success": True,
            "action": "REJECTED",
            "approver": current_user.email,
            "approver_id": current_user.id,
            "auto_merge_disabled": True,
            "message": f"Remediation patch rejected by {current_user.email}. No pull request was created."
        }

@router.post("/remediate/github-pr", response_model=Dict[str, Any])
async def create_github_pr(
    pr_req: GitHubPRRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Dispatch a PR only when this user has approved this exact remediation patch."""
    _require_approver(current_user)

    result = await db.execute(select(Finding).where(Finding.id == pr_req.finding_id, Finding.workspace_id == current_user.workspace_id))
    finding = result.scalars().first()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found.")

    return await _dispatch_approved_finding(finding, current_user, pr_req.repo_name, db)
