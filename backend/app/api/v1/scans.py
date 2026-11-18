import jwt
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks, WebSocket, WebSocketDisconnect
from typing import List
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.core.database import get_db
from app.api.v1.auth import get_current_user
from app.models.domain import User, TargetAsset, ScanRun, Finding, VerificationStatus, ScanStatus
from app.core.config import settings
from app.schemas.domain import ScanCreate, ScanResponse, FindingResponse
from app.services.scanner_runner import scanner_runner, ws_manager

router = APIRouter(prefix="/scans", tags=["Scan Runs"])

@router.get("", response_model=List[ScanResponse])
async def list_scans(current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(ScanRun).where(ScanRun.workspace_id == current_user.workspace_id))
    return result.scalars().all()

@router.post("", response_model=ScanResponse)
async def create_scan(
    scan_in: ScanCreate,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    # Verify Target Exists and is VERIFIED
    result = await db.execute(select(TargetAsset).where(TargetAsset.id == scan_in.target_id, TargetAsset.workspace_id == current_user.workspace_id))
    target = result.scalars().first()
    if not target:
        raise HTTPException(status_code=404, detail="Target asset not found.")

    if target.verification_status != VerificationStatus.VERIFIED:
        raise HTTPException(
            status_code=403,
            detail=f"FORBIDDEN: Target asset '{target.domain}' is not VERIFIED. Ownership verification required before active scanning."
        )

    scan = ScanRun(
        workspace_id=current_user.workspace_id,
        target_id=target.id,
        status=ScanStatus.QUEUED,
        progress_pct=0,
        current_stage="QUEUED IN BACKEND"
    )
    db.add(scan)
    await db.commit()
    await db.refresh(scan)

    # Launch runner in background task
    background_tasks.add_task(scanner_runner.execute_scan, scan.id, db)

    return scan

@router.get("/{scan_id}/findings", response_model=List[FindingResponse])
async def list_scan_findings(
    scan_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    scan_result = await db.execute(
        select(ScanRun).where(
            ScanRun.id == scan_id,
            ScanRun.workspace_id == current_user.workspace_id
        )
    )
    if not scan_result.scalars().first():
        raise HTTPException(status_code=404, detail="Scan run not found.")

    findings_result = await db.execute(
        select(Finding).where(
            Finding.scan_id == scan_id,
            Finding.workspace_id == current_user.workspace_id
        )
    )
    return findings_result.scalars().all()

@router.get("/{scan_id}", response_model=ScanResponse)
async def get_scan(scan_id: str, current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(ScanRun).where(ScanRun.id == scan_id, ScanRun.workspace_id == current_user.workspace_id))
    scan = result.scalars().first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan run not found.")
    return scan

@router.websocket("/{scan_id}/ws")
async def scan_websocket(
    websocket: WebSocket,
    scan_id: str,
    db: AsyncSession = Depends(get_db)
):
    authorization = websocket.headers.get("authorization", "")
    token = None
    if authorization.startswith("Bearer "):
        token = authorization[7:]
    else:
        for subprotocol in websocket.scope.get("subprotocols", []):
            if subprotocol.startswith("aegis.bearer."):
                token = subprotocol[len("aegis.bearer."):]
                break

    if not token:
        await websocket.close(code=1008)
        return

    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        user_id = payload.get("sub")
    except (jwt.InvalidTokenError, TypeError):
        await websocket.close(code=1008)
        return

    if not user_id:
        await websocket.close(code=1008)
        return

    user_result = await db.execute(select(User).where(User.id == user_id))
    current_user = user_result.scalars().first()
    if not current_user:
        await websocket.close(code=1008)
        return

    scan_result = await db.execute(
        select(ScanRun).where(
            ScanRun.id == scan_id,
            ScanRun.workspace_id == current_user.workspace_id
        )
    )
    if not scan_result.scalars().first():
        await websocket.close(code=1008)
        return

    accepted_protocol = "aegis" if "aegis" in websocket.scope.get("subprotocols", []) else None
    await ws_manager.connect(scan_id, websocket, subprotocol=accepted_protocol)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        ws_manager.disconnect(scan_id, websocket)
