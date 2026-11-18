import pytest
import pytest_asyncio
import uuid
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from app.core.database import Base, engine
from app.models.domain import TargetAsset, VerificationStatus, VerificationMethod, Workspace
from app.mcp.client import mcp_registry
from app.mcp.guardrails import check_target_ownership, validate_scope_limits, GuardrailViolation, extract_domain
from app.mcp.servers import nmap_server, nuclei_server, zap_server, trivy_server

@pytest_asyncio.fixture(scope="function", autouse=True)
async def setup_db():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield

@pytest.mark.asyncio
async def test_mcp_registry_lists_all_tools():
    """Verify all 5 MCP servers are registered and expose tools with schemas."""
    inventory = await mcp_registry.list_tools()
    assert "nmap" in inventory
    assert "zap" in inventory
    assert "nuclei" in inventory
    assert "trivy" in inventory
    assert "github" in inventory

    nmap_tools = [t["name"] for t in inventory["nmap"]]
    assert "nmap_port_scan" in nmap_tools

    zap_tools = [t["name"] for t in inventory["zap"]]
    assert "zap_baseline_scan" in zap_tools

    nuclei_tools = [t["name"] for t in inventory["nuclei"]]
    assert "nuclei_scan" in nuclei_tools

    trivy_tools = [t["name"] for t in inventory["trivy"]]
    assert "trivy_scan" in trivy_tools

    github_tools = [t["name"] for t in inventory["github"]]
    assert "create_pull_request" in github_tools

@pytest.mark.asyncio
async def test_unverified_target_refused_across_all_active_tools():
    """Verify that every active scanning tool refuses unverified targets."""
    unauthorized_target = "unauthorized-malicious-target.com"

    # 1. Nmap
    nmap_res = await mcp_registry.call_tool("nmap", "nmap_port_scan", {"target": unauthorized_target})
    assert nmap_res.get("status") == "REFUSED"
    assert "UNVERIFIED_TARGET_REFUSAL" in nmap_res.get("error_type", "")

    # 2. ZAP
    zap_res = await mcp_registry.call_tool("zap", "zap_baseline_scan", {"target_url": f"https://{unauthorized_target}"})
    assert zap_res.get("status") == "REFUSED"
    assert "UNVERIFIED_TARGET_REFUSAL" in zap_res.get("error_type", "")

    # 3. Nuclei
    nuclei_res = await mcp_registry.call_tool("nuclei", "nuclei_scan", {"target": unauthorized_target})
    assert nuclei_res.get("status") == "REFUSED"
    assert "UNVERIFIED_TARGET_REFUSAL" in nuclei_res.get("error_type", "")

    # 4. Trivy (against remote repo/domain)
    trivy_res = await mcp_registry.call_tool("trivy", "trivy_scan", {"target_path": f"https://{unauthorized_target}/repo.git"})
    assert trivy_res.get("status") == "REFUSED"
    assert "UNVERIFIED_TARGET_REFUSAL" in trivy_res.get("error_type", "")

@pytest.mark.asyncio
async def test_verified_target_without_scanner_binaries_is_unavailable(monkeypatch):
    """Verified ownership must not turn a missing scanner into synthetic findings."""
    from app.core.database import AsyncSessionLocal

    test_uid = str(uuid.uuid4())[:8]
    test_domain = f"verified-{test_uid}.org"

    # Insert verified target asset in DB for testing
    async with AsyncSessionLocal() as session:
        ws = Workspace(id=f"ws-{test_uid}", name=f"Test Workspace {test_uid}", slug=f"test-slug-{test_uid}")
        session.add(ws)
        target = TargetAsset(
            id=f"target-{test_uid}",
            workspace_id=f"ws-{test_uid}",
            domain=test_domain,
            verification_token=f"token-{test_uid}",
            verification_status=VerificationStatus.VERIFIED,
            verification_method=VerificationMethod.DNS_TXT
        )
        session.add(target)
        await session.commit()

    monkeypatch.setattr(nmap_server, "check_cli_available", lambda: None)
    monkeypatch.setattr(nuclei_server, "check_cli_available", lambda: None)
    monkeypatch.setattr(zap_server, "check_cli_available", lambda: None)

    nmap_res = await mcp_registry.call_tool("nmap", "nmap_port_scan", {"target": test_domain})
    assert nmap_res.get("status") == "UNAVAILABLE"
    assert test_domain in nmap_res.get("target", "")
    assert "open_ports" not in nmap_res

    nuclei_res = await mcp_registry.call_tool("nuclei", "nuclei_scan", {"target": test_domain})
    assert nuclei_res.get("status") == "UNAVAILABLE"
    assert "findings" not in nuclei_res

    zap_res = await mcp_registry.call_tool("zap", "zap_baseline_scan", {"target_url": f"https://{test_domain}"})
    assert zap_res.get("status") == "UNAVAILABLE"
    assert "alerts_found" not in zap_res

    monkeypatch.setattr(trivy_server, "check_cli_available", lambda: None)
    trivy_res = await mcp_registry.call_tool(
        "trivy", "trivy_scan", {"target_path": "."}
    )
    assert trivy_res.get("status") == "UNAVAILABLE"
    assert "vulnerabilities" not in trivy_res

@pytest.mark.asyncio
async def test_scope_limits_reject_destructive_modes():
    """Test that destructive patterns and rate limit / duration violations are blocked."""
    # Destructive pattern in tags
    with pytest.raises(GuardrailViolation) as excinfo:
        validate_scope_limits("verified-client.org", parameters={"tags": "cve,exploit,dos"})
    assert "Disallowed destructive pattern" in str(excinfo.value)

    # Excessive duration
    with pytest.raises(GuardrailViolation) as excinfo_dur:
        validate_scope_limits("verified-client.org", requested_duration=500)
    assert "exceeds maximum permitted scan window" in str(excinfo_dur.value)

    # Excessive rate limit
    with pytest.raises(GuardrailViolation) as excinfo_rate:
        validate_scope_limits("verified-client.org", requested_rate_limit=500, max_rate_allowed=100)
    assert "exceeds platform threshold" in str(excinfo_rate.value)

@pytest.mark.asyncio
async def test_github_mcp_does_not_claim_unimplemented_dispatch_succeeded():
    pr_res = await mcp_registry.call_tool("github", "create_pull_request", {
        "repo_name": "aegis-corp/production-infra",
        "finding_title": "Remediate Missing HSTS and OpenSSH RegreSSHion",
        "remediation_patch": "--- nginx.conf\n+++ nginx.conf\n+ add_header Strict-Transport-Security max-age=31536000;",
        "cve_id": "CVE-2024-6387"
    })
    assert pr_res.get("status") == "UNAVAILABLE"
    assert "no branch, commit, or pull request was created" in pr_res["error"]
    assert "pr_url" not in pr_res
