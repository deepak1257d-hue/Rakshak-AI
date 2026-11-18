from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.exc import SQLAlchemyError
from app.core.config import settings
from app.core.database import engine, Base
from app.api.v1 import auth, targets, scans, reports
from app.workflow.checkpointer import close_workflow_checkpointer

app = FastAPI(
    title=settings.PROJECT_NAME,
    openapi_url=f"{settings.API_V1_STR}/openapi.json"
)

# Enable CORS for frontend integration
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

from sqlalchemy import text, inspect

@app.on_event("startup")
async def startup_event():
    # Security Guardrail: Refuse to start if lab mode is on when ENV != "development"
    if settings.ENV.lower() != "development" and getattr(settings, "LAB_MODE_ENABLED", False) and len(getattr(settings, "DEV_LAB_HOSTS", [])) > 0:
        raise RuntimeError(
            f"REFUSING TO START: Lab verification mode cannot be enabled when ENV is '{settings.ENV}'. "
            f"DEV_LAB_HOSTS must be empty outside development."
        )

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        audit_columns = await conn.run_sync(
            lambda sync_conn: inspect(sync_conn).get_columns("audit_logs")
        )
        if not any(column["name"] == "remediation_hash" for column in audit_columns):
            await conn.execute(text("ALTER TABLE audit_logs ADD COLUMN remediation_hash VARCHAR"))
        finding_columns = await conn.run_sync(
            lambda sync_conn: inspect(sync_conn).get_columns("findings")
        )
        if not any(column["name"] == "score_source" for column in finding_columns):
            await conn.execute(text("ALTER TABLE findings ADD COLUMN score_source VARCHAR"))
            await conn.execute(
                text(
                    "UPDATE findings SET score = NULL, score_source = 'LEGACY_UNVERIFIED' "
                    "WHERE score_source IS NULL"
                )
            )
        scan_columns = await conn.run_sync(
            lambda sync_conn: inspect(sync_conn).get_columns("scan_runs")
        )
        for column_name in ("trace_id", "trace_url"):
            if not any(column["name"] == column_name for column in scan_columns):
                await conn.execute(
                    text(f"ALTER TABLE scan_runs ADD COLUMN {column_name} VARCHAR")
                )

@app.on_event("shutdown")
async def shutdown_event():
    close_workflow_checkpointer()
    await engine.dispose()

app.include_router(auth.router, prefix=settings.API_V1_STR)
app.include_router(targets.router, prefix=settings.API_V1_STR)
app.include_router(scans.router, prefix=settings.API_V1_STR)
app.include_router(reports.router, prefix=settings.API_V1_STR)

from app.services.scanner_health import check_all_scanners

@app.get("/health")
async def health_check():
    try:
        async with engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
    except SQLAlchemyError as exc:
        raise HTTPException(status_code=503, detail="Database is unavailable") from exc
    return {"status": "ok", "database": "connected"}

@app.get("/health/scanners")
async def scanner_health_check():
    """Returns the operational status, version, and presence of all CTEM security scanner binaries."""
    return await check_all_scanners()

@app.get("/")
async def root():
    return {
        "status": "online",
        "platform": "AEGIS AI - Enterprise CTEM Platform",
        "docs_url": "/docs"
    }
