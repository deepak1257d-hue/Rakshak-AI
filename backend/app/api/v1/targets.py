import secrets
from datetime import datetime
from typing import List
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.core.database import get_db
from app.core.config import settings
from app.api.v1.auth import get_current_user
from app.models.domain import User, TargetAsset, VerificationStatus, VerificationMethod
from app.schemas.domain import TargetCreate, TargetResponse, TargetVerifyRequest
from app.services.verification import (
    verify_dns_txt_record,
    verify_html_meta_tag,
    verify_well_known_file
)

router = APIRouter(prefix="/targets", tags=["Target Assets"])

def is_lab_eligible(domain: str) -> bool:
    """
    Decides if a target is eligible for development lab bypass.
    Strict security rule:
    1. settings.ENV must be EXACTLY 'development'
    2. settings.LAB_MODE_ENABLED must be True
    3. Hostname must be in an EXACT allowlist (settings.DEV_LAB_HOSTS).
       No substring, wildcard, or keyword matching permitted.
    """
    if settings.ENV.lower() != "development":
        return False
    if not getattr(settings, "LAB_MODE_ENABLED", True):
        return False

    clean = domain.strip().lower()
    for prefix in ["https://", "http://"]:
        if clean.startswith(prefix):
            clean = clean[len(prefix):]
    clean = clean.split("/")[0].split(":")[0]

    exact_allowlist = {h.strip().lower() for h in settings.DEV_LAB_HOSTS}
    return clean in exact_allowlist

def to_target_response(target: TargetAsset) -> TargetResponse:
    lab_eligible = is_lab_eligible(target.domain)
    is_lab = (target.verification_method == VerificationMethod.LAB)
    return TargetResponse(
        id=target.id,
        workspace_id=target.workspace_id,
        domain=target.domain,
        verification_token=target.verification_token,
        verification_status=target.verification_status,
        verification_method=target.verification_method,
        lab_mode=lab_eligible,
        is_lab=is_lab,
        last_verified_at=target.last_verified_at,
        created_at=target.created_at
    )

@router.get("", response_model=List[TargetResponse])
async def list_targets(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    result = await db.execute(
        select(TargetAsset).where(TargetAsset.workspace_id == current_user.workspace_id)
    )
    targets = result.scalars().all()
    return [to_target_response(t) for t in targets]

@router.post("", response_model=TargetResponse)
async def create_target(
    target_in: TargetCreate,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    # Generate unique verification token
    verification_token = secrets.token_hex(16)
    clean_domain = target_in.domain.lower().strip().replace("https://", "").replace("http://", "").split("/")[0]

    target = TargetAsset(
        workspace_id=current_user.workspace_id,
        domain=clean_domain,
        verification_token=verification_token,
        verification_method=target_in.verification_method,
        verification_status=VerificationStatus.PENDING
    )
    db.add(target)
    await db.commit()
    await db.refresh(target)
    return to_target_response(target)

@router.get("/{target_id}", response_model=TargetResponse)
async def get_target(
    target_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    result = await db.execute(
        select(TargetAsset).where(
            TargetAsset.id == target_id,
            TargetAsset.workspace_id == current_user.workspace_id
        )
    )
    target = result.scalars().first()
    if not target:
        raise HTTPException(status_code=404, detail="Target asset not found.")
    return to_target_response(target)

@router.post("/{target_id}/verify", response_model=TargetResponse)
async def verify_target(
    target_id: str,
    verify_req: TargetVerifyRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    result = await db.execute(
        select(TargetAsset).where(
            TargetAsset.id == target_id,
            TargetAsset.workspace_id == current_user.workspace_id
        )
    )
    target = result.scalars().first()
    if not target:
        raise HTTPException(status_code=404, detail="Target asset not found.")

    # Rule 1 & 7: Any request containing simulate=true must be rejected
    if verify_req.simulate is True:
        target.verification_status = VerificationStatus.FAILED
        await db.commit()
        raise HTTPException(
            status_code=400,
            detail="Client-controlled 'simulate' is forbidden. Verification bypass is decided solely by server policy."
        )

    # Rule 5 & 6: Explicit LAB Verification
    if verify_req.method == VerificationMethod.LAB:
        if not is_lab_eligible(target.domain):
            target.verification_status = VerificationStatus.FAILED
            await db.commit()
            raise HTTPException(
                status_code=400,
                detail=f"Target '{target.domain}' is not eligible for LAB verification. "
                       f"Lab verification is permitted only in development environment for configured DEV_LAB_HOSTS."
            )
        target.verification_status = VerificationStatus.VERIFIED
        target.verification_method = VerificationMethod.LAB
        target.last_verified_at = datetime.utcnow()
        await db.commit()
        await db.refresh(target)
        return to_target_response(target)

    # Real verification methods
    if verify_req.method == VerificationMethod.DNS_TXT:
        is_verified, msg = await verify_dns_txt_record(target.domain, target.verification_token)
    elif verify_req.method == VerificationMethod.HTML_META:
        is_verified, msg = await verify_html_meta_tag(target.domain, target.verification_token)
    elif verify_req.method == VerificationMethod.HTTP_FILE:
        is_verified, msg = await verify_well_known_file(target.domain, target.verification_token)
    else:
        raise HTTPException(status_code=400, detail=f"Unsupported verification method: {verify_req.method}")

    if is_verified:
        target.verification_method = verify_req.method
        target.verification_status = VerificationStatus.VERIFIED
        target.last_verified_at = datetime.utcnow()
    else:
        # In development mode, check if this is an exact DEV_LAB_HOSTS host
        if is_lab_eligible(target.domain):
            # Mark lab-verified targets as verification_method=LAB (Rule 6)
            target.verification_method = VerificationMethod.LAB
            target.verification_status = VerificationStatus.VERIFIED
            target.last_verified_at = datetime.utcnow()
        else:
            target.verification_status = VerificationStatus.FAILED
            await db.commit()
            raise HTTPException(status_code=400, detail=msg)

    await db.commit()
    await db.refresh(target)
    return to_target_response(target)
