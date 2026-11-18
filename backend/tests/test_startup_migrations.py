import pytest
from sqlalchemy import inspect, text
from sqlalchemy.ext.asyncio import create_async_engine

from app import main


@pytest.mark.asyncio
async def test_startup_adds_missing_scan_trace_columns_idempotently(tmp_path, monkeypatch):
    database_path = tmp_path / "legacy.db"
    test_engine = create_async_engine(f"sqlite+aiosqlite:///{database_path}")
    monkeypatch.setattr(main, "engine", test_engine)

    async with test_engine.begin() as connection:
        await connection.execute(
            text("CREATE TABLE scan_runs (id VARCHAR PRIMARY KEY)")
        )

    try:
        await main.startup_event()
        await main.startup_event()

        async with test_engine.connect() as connection:
            columns = await connection.run_sync(
                lambda sync_connection: inspect(sync_connection).get_columns("scan_runs")
            )
        column_names = {column["name"] for column in columns}
        assert {"trace_id", "trace_url"} <= column_names
    finally:
        await test_engine.dispose()
