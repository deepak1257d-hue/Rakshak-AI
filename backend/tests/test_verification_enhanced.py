import pytest
import pytest_asyncio
import uuid
from unittest.mock import AsyncMock, patch
from httpx import AsyncClient, ASGITransport
from app.main import app
from app.core.database import Base, engine, AsyncSessionLocal
from app.models.domain import Workspace, TargetAsset, User, VerificationStatus, VerificationMethod
from app.core.security import create_access_token, get_password_hash
from app.services.verification import verify_dns_txt_record, verify_html_meta_tag

@pytest_asyncio.fixture(scope="function", autouse=True)
async def setup_db():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield

@pytest.mark.asyncio
async def test_client_simulation_flag_is_rejected():
    """Client-controlled simulation must not bypass ownership verification."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        uid = uuid.uuid4().hex[:6]
        reg_res = await client.post("/api/v1/auth/register", json={
            "email": f"sim_analyst_{uid}@aegis.io",
            "password": "Password123!",
            "workspace_name": f"Sim Workspace {uid}"
        })
        assert reg_res.status_code == 200
        token = reg_res.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}

        # Create target with arbitrary domain (e.g. non-resolvable corporate domain)
        target_res = await client.post("/api/v1/targets", json={
            "domain": f"arbitrary-corp-asset-{uid}.internal.private",
            "verification_method": "DNS_TXT"
        }, headers=headers)
        assert target_res.status_code == 200
        target = target_res.json()
        assert target["verification_status"] == "PENDING"

        # A client cannot request a simulated verification.
        verify_res = await client.post(
            f"/api/v1/targets/{target['id']}/verify",
            json={"method": "DNS_TXT", "simulate": True},
            headers=headers
        )
        assert verify_res.status_code == 400
        assert "simulate" in verify_res.json()["detail"].lower()
        assert "forbidden" in verify_res.json()["detail"].lower()

@pytest.mark.asyncio
async def test_non_allowlisted_development_hosts_are_not_auto_verified():
    """Development-like names outside the exact allowlist must not bypass verification."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        uid = uuid.uuid4().hex[:6]
        reg_res = await client.post("/api/v1/auth/register", json={
            "email": f"dev_analyst_{uid}@aegis.io",
            "password": "Password123!",
            "workspace_name": f"Dev Workspace {uid}"
        })
        token = reg_res.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}

        test_domains = [
            f"juice-shop-{uid}.cyber.local",
            f"resume-labs-{uid}.vercel.app",
            f"staging-app-{uid}.test"
        ]

        with patch(
            "app.api.v1.targets.verify_dns_txt_record",
            new=AsyncMock(return_value=(False, "DNS TXT record not found")),
        ):
            for domain in test_domains:
                target_res = await client.post("/api/v1/targets", json={
                    "domain": domain,
                    "verification_method": "DNS_TXT"
                }, headers=headers)
                target = target_res.json()

                verify_res = await client.post(
                    f"/api/v1/targets/{target['id']}/verify",
                    json={"method": "DNS_TXT", "simulate": False},
                    headers=headers
                )
                assert verify_res.status_code == 400
                assert "not found" in verify_res.json()["detail"].lower()

@pytest.mark.asyncio
async def test_verification_unverified_hostile_rejected():
    """Verify that unknown public domain without TXT record is strictly rejected without simulation."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        uid = uuid.uuid4().hex[:6]
        reg_res = await client.post("/api/v1/auth/register", json={
            "email": f"strict_{uid}@aegis.io",
            "password": "Password123!",
            "workspace_name": f"Strict Workspace {uid}"
        })
        token = reg_res.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}

        target_res = await client.post("/api/v1/targets", json={
            "domain": f"unregistered-hostile-{uid}.org",
            "verification_method": "DNS_TXT"
        }, headers=headers)
        target = target_res.json()

        verify_res = await client.post(
            f"/api/v1/targets/{target['id']}/verify",
            json={"method": "DNS_TXT", "simulate": False},
            headers=headers
        )
        assert verify_res.status_code == 400
        assert "not found" in verify_res.json()["detail"].lower() or "error" in verify_res.json()["detail"].lower()

