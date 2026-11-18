from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import HTTPException
from sqlalchemy.exc import SQLAlchemyError

from app.main import health_check


@pytest.mark.asyncio
async def test_health_check_reports_database_connection():
    connection = AsyncMock()
    context = AsyncMock()
    context.__aenter__.return_value = connection
    test_engine = MagicMock()
    test_engine.connect.return_value = context

    with patch("app.main.engine", test_engine):
        assert await health_check() == {"status": "ok", "database": "connected"}

    test_engine.connect.assert_called_once_with()
    connection.execute.assert_awaited_once()


@pytest.mark.asyncio
async def test_health_check_returns_service_unavailable_when_database_fails():
    context = AsyncMock()
    context.__aenter__.side_effect = SQLAlchemyError("database unavailable")
    test_engine = MagicMock()
    test_engine.connect.return_value = context

    with patch("app.main.engine", test_engine):
        with pytest.raises(HTTPException) as exc_info:
            await health_check()

    assert exc_info.value.status_code == 503
    assert exc_info.value.detail == "Database is unavailable"
