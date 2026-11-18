import pytest
from httpx import ASGITransport, AsyncClient
from unittest.mock import patch
from app.main import app
from app.services.scanner_health import check_all_scanners, find_scanner_binary

@pytest.mark.asyncio
async def test_scanner_health_endpoint_reports_status():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/health/scanners")
        assert resp.status_code == 200
        data = resp.json()
        assert "total_scanners" in data
        assert data["total_scanners"] == 4
        assert "scanners" in data
        for tool in ["nmap", "zap", "nuclei", "trivy"]:
            assert tool in data["scanners"]
            assert "installed" in data["scanners"][tool]
            assert "install_guide" in data["scanners"][tool]
            assert "status" in data["scanners"][tool]

@pytest.mark.asyncio
async def test_scanner_detection_with_mock_paths():
    with patch("app.services.scanner_health.find_scanner_binary", return_value="/usr/local/bin/mock-tool"), \
         patch("app.services.scanner_health.get_scanner_version", return_value="2.9.1"):
        results = await check_all_scanners()
        assert results["installed_count"] == 4
        assert results["all_ready"] is True
        for tool in ["nmap", "zap", "nuclei", "trivy"]:
            assert results["scanners"][tool]["installed"] is True
            assert results["scanners"][tool]["version"] == "2.9.1"
            assert results["scanners"][tool]["status"] == "READY"
