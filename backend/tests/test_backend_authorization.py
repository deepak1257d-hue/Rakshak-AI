import uuid

import pytest
import pytest_asyncio
from fastapi.testclient import TestClient
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select
from starlette.websockets import WebSocketDisconnect

from app.core.database import AsyncSessionLocal, Base, engine
from app.core.security import create_access_token, get_password_hash
from app.main import app, startup_event
from app.mcp.client import mcp_registry
from app.models.domain import (
    AuditLog,
    Finding,
    ScanRun,
    ScanStatus,
    SeverityLevel,
    TargetAsset,
    User,
    UserRole,
    VerificationMethod,
    VerificationStatus,
    Workspace,
)


@pytest_asyncio.fixture(scope="function", autouse=True)
async def setup_db():
    await startup_event()
    yield


async def create_scan_and_users():
    suffix = uuid.uuid4().hex
    workspace = Workspace(
        id=f"workspace-{suffix}",
        name=f"Workspace {suffix}",
        slug=f"workspace-{suffix}",
    )
    other_workspace = Workspace(
        id=f"other-workspace-{suffix}",
        name=f"Other {suffix}",
        slug=f"other-{suffix}",
    )
    owner = User(
        email=f"owner-{suffix}@example.test",
        hashed_password=get_password_hash("test-password"),
        role=UserRole.SECURITY_ANALYST,
        workspace_id=workspace.id,
    )
    second_analyst = User(
        email=f"second-{suffix}@example.test",
        hashed_password=get_password_hash("test-password"),
        role=UserRole.SECURITY_ANALYST,
        workspace_id=workspace.id,
    )
    auditor = User(
        email=f"auditor-{suffix}@example.test",
        hashed_password=get_password_hash("test-password"),
        role=UserRole.AUDITOR,
        workspace_id=workspace.id,
    )
    other_user = User(
        email=f"other-{suffix}@example.test",
        hashed_password=get_password_hash("test-password"),
        role=UserRole.SECURITY_ANALYST,
        workspace_id=other_workspace.id,
    )
    target = TargetAsset(
        id=f"target-{suffix}",
        workspace_id=workspace.id,
        domain=f"target-{suffix}.example.test",
        verification_token=suffix,
        verification_status=VerificationStatus.VERIFIED,
        verification_method=VerificationMethod.DNS_TXT,
    )
    other_target = TargetAsset(
        id=f"other-target-{suffix}",
        workspace_id=other_workspace.id,
        domain=f"other-{suffix}.example.test",
        verification_token=suffix,
        verification_status=VerificationStatus.VERIFIED,
        verification_method=VerificationMethod.DNS_TXT,
    )
    scan = ScanRun(
        id=f"scan-{suffix}",
        workspace_id=workspace.id,
        target_id=target.id,
        status=ScanStatus.COMPLETED,
    )
    other_scan = ScanRun(
        id=f"other-scan-{suffix}",
        workspace_id=other_workspace.id,
        target_id=other_target.id,
        status=ScanStatus.COMPLETED,
    )
    finding = Finding(
        id=f"finding-{suffix}",
        scan_id=scan.id,
        workspace_id=workspace.id,
        title="Test finding",
        severity=SeverityLevel.HIGH,
        remediation_patch="apply safe patch",
        status="OPEN",
    )

    async with AsyncSessionLocal() as db:
        db.add_all([
            workspace, other_workspace, owner, second_analyst, auditor, other_user,
            target, other_target, scan, other_scan, finding,
        ])
        await db.commit()
        await db.refresh(owner)
        await db.refresh(second_analyst)
        await db.refresh(auditor)
        await db.refresh(other_user)
        await db.refresh(scan)
        await db.refresh(other_scan)
        await db.refresh(finding)

    return owner, second_analyst, auditor, other_user, scan, other_scan, finding


@pytest.mark.asyncio
async def test_scan_websocket_authenticates_user_and_enforces_workspace():
    owner, _, _, other_user, scan, other_scan, _ = await create_scan_and_users()
    owner_token = create_access_token(owner.id)
    other_token = create_access_token(other_user.id)

    with TestClient(app) as client:
        with client.websocket_connect(
            f"/api/v1/scans/{scan.id}/ws",
            subprotocols=["aegis", f"aegis.bearer.{owner_token}"],
        ) as websocket:
            assert websocket.accepted_subprotocol == "aegis"
            websocket.send_text("keepalive")

        with pytest.raises(WebSocketDisconnect) as unauthenticated:
            with client.websocket_connect(f"/api/v1/scans/{scan.id}/ws"):
                pass
        assert unauthenticated.value.code == 1008

        with pytest.raises(WebSocketDisconnect) as invalid_token:
            with client.websocket_connect(
                f"/api/v1/scans/{scan.id}/ws",
                subprotocols=["aegis", "aegis.bearer.invalid-token"],
            ):
                pass
        assert invalid_token.value.code == 1008

        with pytest.raises(WebSocketDisconnect) as cross_workspace:
            with client.websocket_connect(
                f"/api/v1/scans/{scan.id}/ws",
                subprotocols=["aegis", f"aegis.bearer.{other_token}"],
            ):
                pass
        assert cross_workspace.value.code == 1008

        with pytest.raises(WebSocketDisconnect) as wrong_scan:
            with client.websocket_connect(
                f"/api/v1/scans/{other_scan.id}/ws",
                subprotocols=["aegis", f"aegis.bearer.{owner_token}"],
            ):
                pass
        assert wrong_scan.value.code == 1008


@pytest.mark.asyncio
async def test_pr_dispatch_rejects_missing_wrong_user_and_stale_approvals():
    owner, second_analyst, auditor, _, _, _, finding = await create_scan_and_users()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        owner_headers = {"Authorization": f"Bearer {create_access_token(owner.id)}"}
        second_headers = {"Authorization": f"Bearer {create_access_token(second_analyst.id)}"}
        auditor_headers = {"Authorization": f"Bearer {create_access_token(auditor.id)}"}
        payload = {"finding_id": finding.id}

        missing_approval = await client.post(
            "/api/v1/reports/remediate/github-pr",
            json=payload,
            headers=owner_headers,
        )
        assert missing_approval.status_code == 403

        malformed_decision = await client.post(
            "/api/v1/reports/remediate/decision",
            json={"finding_id": finding.id, "action": "APPROVE_NOW"},
            headers=owner_headers,
        )
        assert malformed_decision.status_code == 422

        unbound_thread = await client.post(
            "/api/v1/reports/remediate/decision",
            json={
                "finding_id": finding.id,
                "action": "APPROVE",
                "thread_id": "untrusted-workflow-thread",
            },
            headers=owner_headers,
        )
        assert unbound_thread.status_code == 400

        auditor_decision = await client.post(
            "/api/v1/reports/remediate/decision",
            json={"finding_id": finding.id, "action": "APPROVE"},
            headers=auditor_headers,
        )
        assert auditor_decision.status_code == 403

        async with AsyncSessionLocal() as db:
            db.add(AuditLog(
                workspace_id=owner.workspace_id,
                actor_id=owner.id,
                action="REMEDIATION_APPROVED",
                resource_type="FINDING",
                resource_id=finding.id,
                remediation_hash="approval-for-another-patch",
            ))
            db_finding = await db.get(Finding, finding.id)
            db_finding.status = "REMEDIATION_APPROVED"
            await db.commit()

        stale_approval = await client.post(
            "/api/v1/reports/remediate/github-pr",
            json=payload,
            headers=owner_headers,
        )
        assert stale_approval.status_code == 403

        wrong_user_approval = await client.post(
            "/api/v1/reports/remediate/github-pr",
            json=payload,
            headers=second_headers,
        )
        assert wrong_user_approval.status_code == 403


@pytest.mark.asyncio
async def test_valid_approval_is_recorded_before_dispatch_and_replay_is_blocked(monkeypatch):
    owner, _, _, _, _, _, finding = await create_scan_and_users()
    dispatch_calls = []

    async def dispatch_failure(server, tool, arguments):
        dispatch_calls.append((server, tool, arguments))
        return {"status": "ERROR", "error": "GitHub unavailable"}

    monkeypatch.setattr(mcp_registry, "call_tool", dispatch_failure)
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        headers = {"Authorization": f"Bearer {create_access_token(owner.id)}"}

        invalid_lowercase_action = await client.post(
            "/api/v1/reports/remediate/decision",
            json={"finding_id": finding.id, "action": "approve"},
            headers=headers,
        )
        assert invalid_lowercase_action.status_code == 422

        decision = await client.post(
            "/api/v1/reports/remediate/decision",
            json={"finding_id": finding.id, "action": "APPROVE"},
            headers=headers,
        )
        assert decision.status_code == 502
        assert len(dispatch_calls) == 1

        async with AsyncSessionLocal() as db:
            refreshed = await db.get(Finding, finding.id)
            assert refreshed.status == "REMEDIATION_PR_DISPATCHING"
            approval = (await db.execute(
                select(AuditLog).where(
                    AuditLog.actor_id == owner.id,
                    AuditLog.action == "REMEDIATION_APPROVED",
                    AuditLog.resource_id == finding.id,
                )
            )).scalars().one()
            assert approval.remediation_hash

        replay = await client.post(
            "/api/v1/reports/remediate/github-pr",
            json={"finding_id": finding.id},
            headers=headers,
        )
        assert replay.status_code == 409
        assert len(dispatch_calls) == 1


@pytest.mark.asyncio
async def test_unavailable_github_dispatch_does_not_claim_success_or_lock_finding():
    owner, _, _, _, _, _, finding = await create_scan_and_users()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        headers = {"Authorization": f"Bearer {create_access_token(owner.id)}"}
        decision = await client.post(
            "/api/v1/reports/remediate/decision",
            json={"finding_id": finding.id, "action": "APPROVE"},
            headers=headers,
        )

        assert decision.status_code == 503
        assert "no branch, commit, or pull request was created" in decision.json()["detail"]

        async with AsyncSessionLocal() as db:
            refreshed = await db.get(Finding, finding.id)
            assert refreshed.status == "REMEDIATION_APPROVED"
            assert (await db.execute(
                select(AuditLog).where(
                    AuditLog.actor_id == owner.id,
                    AuditLog.action == "REMEDIATION_APPROVED",
                    AuditLog.resource_id == finding.id,
                )
            )).scalars().one()
            dispatched = (await db.execute(
                select(AuditLog).where(
                    AuditLog.action == "REMEDIATION_PR_APPROVED_AND_DISPATCHED",
                    AuditLog.resource_id == finding.id,
                )
            )).scalars().all()
            assert dispatched == []


@pytest.mark.asyncio
async def test_rejection_is_supported_and_cannot_be_changed_to_approval():
    owner, _, _, _, _, _, finding = await create_scan_and_users()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        headers = {"Authorization": f"Bearer {create_access_token(owner.id)}"}

        rejection = await client.post(
            "/api/v1/reports/remediate/decision",
            json={"finding_id": finding.id, "action": "REJECT"},
            headers=headers,
        )
        assert rejection.status_code == 200
        assert rejection.json()["action"] == "REJECTED"

        approval_after_rejection = await client.post(
            "/api/v1/reports/remediate/decision",
            json={"finding_id": finding.id, "action": "APPROVE"},
            headers=headers,
        )
        assert approval_after_rejection.status_code == 409
