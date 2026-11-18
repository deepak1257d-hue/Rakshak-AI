import pytest
import pytest_asyncio
import uuid
import logging
from unittest.mock import patch, MagicMock
from httpx import AsyncClient, ASGITransport, Response

from app.main import app
from app.core.database import engine, Base
from app.core.config import Settings, settings
from app.models.domain import VerificationMethod
from app.services.verification import (
    verify_dns_txt_record,
    verify_html_meta_tag,
    verify_well_known_file,
)

@pytest_asyncio.fixture(scope="function", autouse=True)
async def setup_db():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
    yield

async def get_auth_headers(client: AsyncClient, suffix: str = "sec") -> dict:
    reg_res = await client.post("/api/v1/auth/register", json={
        "email": f"security-{suffix}-{uuid.uuid4().hex[:6]}@aegis-defense.io",
        "password": "SuperSecretPassword123!",
        "workspace_name": f"Security Workspace {suffix}"
    })
    assert reg_res.status_code == 200
    token = reg_res.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}

@pytest.mark.asyncio
async def test_must_fail_unauthorized_domains():
    """Requirement 7: test.victim.com, cyber-bank.com, random.vercel.app, google.com MUST fail verification."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        headers = await get_auth_headers(client, "fail-tests")

        unauthorized_domains = [
            "test.victim.com",
            "cyber-bank.com",
            "random.vercel.app",
            "google.com",
        ]

        for domain in unauthorized_domains:
            # Create target
            create_res = await client.post("/api/v1/targets", json={
                "domain": domain,
                "verification_method": "DNS_TXT"
            }, headers=headers)
            assert create_res.status_code == 200, f"Failed to create target for {domain}"
            target_id = create_res.json()["id"]

            # Attempt verification via DNS_TXT (without real records) -> MUST FAIL (400)
            verify_res = await client.post(
                f"/api/v1/targets/{target_id}/verify",
                json={"method": "DNS_TXT"},
                headers=headers
            )
            assert verify_res.status_code == 400, f"Expected verification failure for {domain}, got {verify_res.status_code}"
            assert "failed" in verify_res.json()["detail"].lower()

            # Attempt verification via LAB method on non-allowlisted domain -> MUST FAIL (400)
            lab_verify_res = await client.post(
                f"/api/v1/targets/{target_id}/verify",
                json={"method": "LAB"},
                headers=headers
            )
            assert lab_verify_res.status_code == 400, f"LAB verify should fail for {domain}"
            assert "dev_lab_hosts" in lab_verify_res.json()["detail"].lower()

@pytest.mark.asyncio
async def test_must_fail_simulate_parameter():
    """Requirement 1 & 7: Any verification request containing simulate=true MUST fail immediately."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        headers = await get_auth_headers(client, "simulate-fail")

        # Test on both an external domain and an allowlisted dev domain
        for domain in ["localhost", "test.victim.com"]:
            create_res = await client.post("/api/v1/targets", json={
                "domain": domain,
                "verification_method": "DNS_TXT"
            }, headers=headers)
            assert create_res.status_code == 200
            target_id = create_res.json()["id"]

            # Sending simulate=True must be rejected with 400
            sim_res = await client.post(
                f"/api/v1/targets/{target_id}/verify",
                json={"method": "DNS_TXT", "simulate": True},
                headers=headers
            )
            assert sim_res.status_code == 400
            assert "simulate" in sim_res.json()["detail"].lower()
            assert "forbidden" in sim_res.json()["detail"].lower()

@pytest.mark.asyncio
async def test_must_pass_allowlisted_hosts_in_development():
    """Requirement 1, 6 & 7: localhost and juice-shop.cyber.local MUST pass in development and be marked LAB."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        headers = await get_auth_headers(client, "dev-pass")

        dev_hosts = ["localhost", "juice-shop.cyber.local"]

        for host in dev_hosts:
            create_res = await client.post("/api/v1/targets", json={
                "domain": host,
                "verification_method": "DNS_TXT"
            }, headers=headers)
            assert create_res.status_code == 200
            target_data = create_res.json()
            target_id = target_data["id"]
            assert target_data["lab_mode"] is True
            assert target_data["verification_status"] == "PENDING"

            # Verify using LAB method
            verify_res = await client.post(
                f"/api/v1/targets/{target_id}/verify",
                json={"method": "LAB"},
                headers=headers
            )
            assert verify_res.status_code == 200
            verified_target = verify_res.json()
            assert verified_target["verification_status"] == "VERIFIED"
            assert verified_target["verification_method"] == "LAB"
            assert verified_target["is_lab"] is True

@pytest.mark.asyncio
async def test_must_fail_lab_verification_in_production():
    """Requirement 1 & 7: In production, lab verification must be disabled even for localhost."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        headers = await get_auth_headers(client, "prod-env")

        create_res = await client.post("/api/v1/targets", json={
            "domain": "localhost",
            "verification_method": "DNS_TXT"
        }, headers=headers)
        assert create_res.status_code == 200
        target_id = create_res.json()["id"]

        with patch.object(settings, "ENV", "production"):
            # GET target must report lab_mode = False in production
            get_res = await client.get(f"/api/v1/targets/{target_id}", headers=headers)
            assert get_res.status_code == 200
            assert get_res.json()["lab_mode"] is False

            # Verify with LAB method MUST fail in production
            verify_lab = await client.post(
                f"/api/v1/targets/{target_id}/verify",
                json={"method": "LAB"},
                headers=headers
            )
            assert verify_lab.status_code == 400

            # Verify with DNS_TXT without DNS MUST fail in production (no lab fallback)
            verify_dns = await client.post(
                f"/api/v1/targets/{target_id}/verify",
                json={"method": "DNS_TXT"},
                headers=headers
            )
            assert verify_dns.status_code == 400

def test_startup_refusal_when_lab_on_in_production():
    """Requirement 1: App must refuse to start if lab mode is on when ENV != 'development'."""
    with pytest.raises(ValueError, match="CRITICAL SECURITY CONFIGURATION ERROR"):
        Settings(
            ENV="production",
            DEV_LAB_HOSTS=["localhost"],
            LAB_MODE_ENABLED=True
        )

@pytest.mark.asyncio
async def test_well_known_file_verification():
    """Requirement 3 & 4: Support /.well-known/aegis-verification.txt with exact format aegis-verification=<token>."""
    token = "aegis_test_token_1234567890abcdef"

    with patch("app.services.verification._resolve_public_addresses", return_value=["93.184.216.34"]):
        # 1. Exact match with current aegis-verification= format
        mock_resp_valid = Response(200, text=f"aegis-verification={token}")
        with patch("httpx.AsyncClient.get", return_value=mock_resp_valid):
            success, msg = await verify_well_known_file("example.com", token)
            assert success is True

        # 2. Legacy antigravity-verification= format with deprecation warning
        mock_resp_legacy = Response(200, text=f"antigravity-verification={token}")
        with patch("httpx.AsyncClient.get", return_value=mock_resp_legacy):
            with patch.object(logging.getLogger("app.services.verification"), "warning") as mock_warn:
                success, msg = await verify_well_known_file("example.com", token)
                assert success is True
                mock_warn.assert_called()
                assert "deprecation" in mock_warn.call_args[0][0].lower()

        # 3. Raw token without prefix MUST FAIL
        mock_resp_raw = Response(200, text=token)
        with patch("httpx.AsyncClient.get", return_value=mock_resp_raw):
            success, msg = await verify_well_known_file("example.com", token)
            assert success is False

        # 4. Wrong prefix MUST FAIL
        mock_resp_wrong_prefix = Response(200, text=f"other-verification={token}")
        with patch("httpx.AsyncClient.get", return_value=mock_resp_wrong_prefix):
            success, msg = await verify_well_known_file("example.com", token)
            assert success is False

        # 5. Wrong token MUST FAIL
        mock_resp_wrong_token = Response(200, text=f"aegis-verification=wrong_token_here")
        with patch("httpx.AsyncClient.get", return_value=mock_resp_wrong_token):
            success, msg = await verify_well_known_file("example.com", token)
            assert success is False

@pytest.mark.asyncio
async def test_dns_txt_strict_format_and_rejection():
    """Requirement 4: Strict token format matching, rejecting raw tokens and unauthorized prefixes."""
    token = "aegis_dns_token_9876543210fedcba"

    # Mock DNS returning exact format
    with patch("dns.resolver.Resolver.resolve") as mock_resolve:
        mock_rr = MagicMock()
        mock_rr.strings = [f"aegis-verification={token}".encode()]
        mock_resolve.return_value = [mock_rr]

        success, msg = await verify_dns_txt_record("example.com", token)
        assert success is True

    # Mock DNS returning raw token (MUST FAIL)
    with patch("dns.resolver.Resolver.resolve") as mock_resolve:
        mock_rr = MagicMock()
        mock_rr.strings = [token.encode()]
        mock_resolve.return_value = [mock_rr]

        success, msg = await verify_dns_txt_record("example.com", token)
        assert success is False

    # Mock DNS returning substring / forged prefix (MUST FAIL)
    with patch("dns.resolver.Resolver.resolve") as mock_resolve:
        mock_rr = MagicMock()
        mock_rr.strings = [f"cyber-verification={token}".encode()]
        mock_resolve.return_value = [mock_rr]

        success, msg = await verify_dns_txt_record("example.com", token)
        assert success is False
