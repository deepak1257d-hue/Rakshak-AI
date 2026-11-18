import pytest
import pytest_asyncio
import asyncio
from httpx import AsyncClient, ASGITransport
from app.main import app
from app.core.database import engine, Base

@pytest_asyncio.fixture(scope="function", autouse=True)
async def setup_db():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
    yield

@pytest.mark.asyncio
async def test_scan_flow_reports_actual_tool_availability():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # 1. Register User
        reg_res = await client.post("/api/v1/auth/register", json={
            "email": "secops@aegis-defense.io",
            "password": "SuperSecretPassword123!",
            "workspace_name": "AEGIS Corp"
        })
        assert reg_res.status_code == 200
        token_data = reg_res.json()
        token = token_data["access_token"]
        headers = {"Authorization": f"Bearer {token}"}

        # 2. Add Target Asset (using dev lab allowlisted host)
        target_res = await client.post("/api/v1/targets", json={
            "domain": "juice-shop.cyber.local",
            "verification_method": "DNS_TXT"
        }, headers=headers)
        assert target_res.status_code == 200
        target = target_res.json()
        target_id = target["id"]
        assert target["verification_status"] == "PENDING"

        # 3. Attempt scan before verification (Must fail with 403)
        scan_unverified = await client.post("/api/v1/scans", json={"target_id": target_id}, headers=headers)
        assert scan_unverified.status_code == 403

        # 4. Verify Target Ownership
        verify_res = await client.post(f"/api/v1/targets/{target_id}/verify", json={"method": "DNS_TXT"}, headers=headers)
        assert verify_res.status_code == 200
        assert verify_res.json()["verification_status"] == "VERIFIED"

        # 5. Launch Scan on Verified Target
        scan_res = await client.post("/api/v1/scans", json={"target_id": target_id}, headers=headers)
        assert scan_res.status_code == 200
        scan_id = scan_res.json()["id"]

        # Wait briefly for background execution
        await asyncio.sleep(5)

        # 6. Fetch Scan Progress
        scan_check = await client.get(f"/api/v1/scans/{scan_id}", headers=headers)
        assert scan_check.status_code == 200
        assert scan_check.json()["status"] in {"COMPLETED", "PARTIAL"}

        # 7. Check Executive Summary & Findings
        summary_res = await client.get(f"/api/v1/reports/executive-summary/{scan_id}", headers=headers)
        assert summary_res.status_code == 200
        summary = summary_res.json()
        assert summary["total_findings"] == len(summary["findings"])
        assert summary["composite_risk_score"] is None
        assert summary["time_to_remediate_estimate"] is None

        scan_findings_res = await client.get(
            f"/api/v1/scans/{scan_id}/findings",
            headers=headers
        )
        assert scan_findings_res.status_code == 200
        assert [f["id"] for f in scan_findings_res.json()] == [
            f["id"] for f in summary["findings"]
        ]
        unauthenticated_findings_res = await client.get(
            f"/api/v1/scans/{scan_id}/findings"
        )
        assert unauthenticated_findings_res.status_code == 401

