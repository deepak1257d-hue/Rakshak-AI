import pytest
from httpx import ASGITransport, AsyncClient
from fastapi.middleware.cors import CORSMiddleware
from app.core.config import Settings
from app.main import app

def test_cors_accepts_comma_separated_origins():
    s = Settings(
        SECRET_KEY="test-secret",
        CORS_ORIGINS="https://app.aegis-security.io, https://aegis-portal.vercel.app, http://localhost:3000",
        _env_file=None
    )
    assert "https://app.aegis-security.io" in s.CORS_ORIGINS
    assert "https://aegis-portal.vercel.app" in s.CORS_ORIGINS
    assert "http://localhost:3000" in s.CORS_ORIGINS
    assert len(s.CORS_ORIGINS) == 3

def test_cors_accepts_json_array_string():
    s = Settings(
        SECRET_KEY="test-secret",
        CORS_ORIGINS='["https://app.example.com", "https://staging.example.com"]',
        _env_file=None
    )
    assert s.CORS_ORIGINS == ["https://app.example.com", "https://staging.example.com"]

def test_cors_rejects_wildcard_in_production():
    with pytest.raises(ValueError, match="CORS SECURITY ERROR: Wildcard '\*' origin is strictly forbidden in production"):
        Settings(
            SECRET_KEY="test-secret",
            ENV="production",
            CORS_ORIGINS=["*"],
            _env_file=None
        )

def test_cors_rejects_origins_with_path():
    with pytest.raises(ValueError, match="cannot contain a URL path"):
        Settings(
            SECRET_KEY="test-secret",
            CORS_ORIGINS=["https://example.com/api"],
            _env_file=None
        )

def test_cors_rejects_origins_with_query_or_fragment():
    with pytest.raises(ValueError, match="cannot contain query parameters"):
        Settings(
            SECRET_KEY="test-secret",
            CORS_ORIGINS=["https://example.com?auth=1"],
            _env_file=None
        )

@pytest.mark.asyncio
async def test_cors_multiple_allowed_origins_preflight():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Origin 1: localhost:3000
        res1 = await client.options(
            "/api/v1/auth/token",
            headers={
                "Origin": "http://localhost:3000",
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": "content-type",
            },
        )
        assert res1.status_code == 200
        assert res1.headers["access-control-allow-origin"] == "http://localhost:3000"
        assert res1.headers["access-control-allow-credentials"] == "true"

        # Disallowed origin
        res_bad = await client.options(
            "/api/v1/auth/token",
            headers={
                "Origin": "https://malicious-site.com",
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": "content-type",
            },
        )
        assert res_bad.status_code == 400
        assert "access-control-allow-origin" not in res_bad.headers
