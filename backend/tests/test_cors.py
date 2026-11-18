import pytest
from httpx import ASGITransport, AsyncClient
from fastapi.middleware.cors import CORSMiddleware

from app.core.config import Settings, settings
from app.main import app


def test_cors_uses_explicit_configured_origins():
    defaults = Settings(SECRET_KEY="test-secret", _env_file=None)
    cors_middleware = next(
        middleware
        for middleware in app.user_middleware
        if middleware.cls is CORSMiddleware
    )

    assert defaults.CORS_ORIGINS == ["http://localhost:3000"]
    assert cors_middleware.kwargs["allow_origins"] == settings.CORS_ORIGINS
    assert settings.CORS_ORIGINS
    assert "*" not in settings.CORS_ORIGINS


@pytest.mark.asyncio
async def test_cors_preflight_rejects_unlisted_origins():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        allowed = await client.options(
            "/api/v1/auth/token",
            headers={
                "Origin": "http://localhost:3000",
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": "content-type",
            },
        )
        rejected = await client.options(
            "/api/v1/auth/token",
            headers={
                "Origin": "https://not-allowed.example",
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": "content-type",
            },
        )

    assert allowed.status_code == 200
    assert allowed.headers["access-control-allow-origin"] == "http://localhost:3000"
    assert rejected.status_code == 400
    assert "access-control-allow-origin" not in rejected.headers
