"""
AEGIS Unit Tests for Task 6: Tracing & Observability Layer
Verifies:
1. Langfuse AegisTracer initialization, trace ID generation, and trace URL formatting.
2. Step telemetry: latency (ms), token counting, and estimated USD cost tracking.
3. MCP tool execution span recording with status, input, output, and duration.
4. LangGraph workflow propagation of trace_id and export of trace_url in final report output.
5. Executive summary API export of trace_id and trace_url.
"""

import pytest
import uuid
import asyncio
from httpx import AsyncClient, ASGITransport
from app.main import app
from app.core.config import settings
from app.core.tracing import AegisTracer, aegis_tracer
from app.workflow.graph import run_aegis_workflow
from app.core.database import AsyncSessionLocal
from app.models.domain import User, Workspace, TargetAsset, ScanRun, ScanStatus, VerificationStatus
from app.core.security import get_password_hash, create_access_token

@pytest.mark.asyncio
async def test_tracer_trace_id_generation_and_url_formatting():
    """Verify trace ID generation produces 32-char hex and trace URL is formatted."""
    tracer = AegisTracer()
    scan_id = str(uuid.uuid4())
    trace_id = tracer.get_or_create_trace_id(scan_id)

    assert len(trace_id) == 32
    assert int(trace_id, 16) >= 0  # valid hex string

    url = tracer.get_trace_url(trace_id)
    assert url.startswith(settings.LANGFUSE_HOST.rstrip("/"))
    assert f"/traces/{trace_id}" in url

@pytest.mark.asyncio
async def test_tracer_tokens_cost_and_step_duration():
    """Verify token counting, cost calculation, and latency tracking in trace_agent_step."""
    tracer = AegisTracer()
    trace_id = tracer.get_or_create_trace_id("test-scan-metrics")

    # Test token/cost calculation directly
    prompt = "A" * 400   # ~100 tokens
    completion = "B" * 800  # ~200 tokens
    in_tok, out_tok, tot_tok, cost = tracer.calculate_tokens_and_cost(prompt, completion, model="gpt-4o")

    assert in_tok == 100
    assert out_tok == 200
    assert tot_tok == 300
    assert cost > 0.0

    # Test context manager step tracking
    async with tracer.trace_agent_step(
        trace_id=trace_id,
        step_name="test_step",
        agent_name="TestAgent",
        scan_id="test-scan-metrics",
        target="demo.test",
        workspace_id="ws-1",
        input_data={"test": "val"},
        model="gpt-4o"
    ) as ctx:
        await asyncio.sleep(0.02)  # simulate 20ms work
        ctx["output_data"] = {"status": "success"}
        ctx["completion_text"] = "Sample response text"

    metrics = tracer.finalize_trace(trace_id)
    assert metrics["trace_id"] == trace_id
    assert metrics["scan_id"] == "test-scan-metrics"
    assert metrics["target"] == "demo.test"
    assert metrics["total_duration_ms"] >= 15.0
    assert metrics["step_count"] == 1
    assert metrics["total_tokens"] > 0
    assert metrics["total_cost_usd"] > 0.0

@pytest.mark.asyncio
async def test_tracer_mcp_tool_span_recording():
    """Verify MCP tool calls record span details including input, output, duration, and status."""
    tracer = AegisTracer()
    trace_id = tracer.get_or_create_trace_id("test-scan-mcp")

    tracer.record_mcp_tool_call(
        trace_id=trace_id,
        server_name="nmap",
        tool_name="nmap_port_scan",
        scan_id="test-scan-mcp",
        target="192.168.1.100",
        workspace_id="ws-test",
        input_args={"ports": "top-100"},
        output_res={"status": "SUCCESS", "open_ports": [22, 80]},
        duration_ms=88.5,
        status="SUCCESS"
    )

    metrics = tracer.get_trace_metrics(trace_id)
    assert len(metrics["tool_calls"]) == 1
    tool_call = metrics["tool_calls"][0]
    assert tool_call["server_name"] == "nmap"
    assert tool_call["tool_name"] == "nmap_port_scan"
    assert tool_call["duration_ms"] == 88.5
    assert tool_call["status"] == "SUCCESS"
    assert tool_call["output_res"]["open_ports"] == [22, 80]

@pytest.mark.asyncio
async def test_workflow_exports_trace_url_in_report():
    """Verify full LangGraph multi-agent workflow exports trace_url in final report output."""
    uid = uuid.uuid4().hex[:8]
    scan_id = f"scan-trace-{uid}"

    result = await run_aegis_workflow(
        target=f"test-trace-domain-{uid}.org",
        target_id=f"target-{uid}",
        scan_id=scan_id,
        workspace_id=f"ws-{uid}"
    )

    final_report = result.get("final_report", {})
    assert "trace_url" in final_report
    assert "trace_id" in final_report
    assert final_report["trace_url"].startswith(settings.LANGFUSE_HOST.rstrip("/"))
    assert f"/traces/{final_report['trace_id']}" in final_report["trace_url"]

    # Verify telemetry metrics in report
    assert "trace_metrics" in final_report
    metrics = final_report["trace_metrics"]
    assert metrics["step_count"] >= 3  # planner, executor, parser, etc.
    assert metrics["total_duration_ms"] > 0
    assert metrics["total_tokens"] > 0

@pytest.mark.asyncio
async def test_api_executive_summary_exports_trace_url():
    """Verify /executive-summary/{scan_id} API returns trace_id and trace_url."""
    uid = uuid.uuid4().hex[:8]
    async with AsyncSessionLocal() as session:
        ws = Workspace(name=f"Trace WS {uid}", slug=f"trace-slug-{uid}")
        session.add(ws)
        await session.commit()
        await session.refresh(ws)

        user = User(
            email=f"ciso-trace-{uid}@aegis.io",
            hashed_password=get_password_hash("testpass"),
            workspace_id=ws.id
        )
        session.add(user)

        target = TargetAsset(
            workspace_id=ws.id,
            domain=f"api-trace-{uid}.test",
            verification_token=f"aegis-verify-{uid}",
            verification_status=VerificationStatus.VERIFIED
        )
        session.add(target)
        await session.commit()
        await session.refresh(target)

        trace_id = aegis_tracer.get_or_create_trace_id(f"scan-{uid}")
        trace_url = aegis_tracer.get_trace_url(trace_id)

        scan = ScanRun(
            workspace_id=ws.id,
            target_id=target.id,
            status=ScanStatus.COMPLETED,
            progress_pct=100,
            current_stage="COMPLETED",
            trace_id=trace_id,
            trace_url=trace_url
        )
        session.add(scan)
        await session.commit()
        await session.refresh(user)
        await session.refresh(scan)

        token = create_access_token(user.id)

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        res = await ac.get(
            f"/api/v1/reports/executive-summary/{scan.id}",
            headers={"Authorization": f"Bearer {token}"}
        )
        assert res.status_code == 200
        data = res.json()
        assert data["trace_id"] == trace_id
        assert data["trace_url"] == trace_url
        assert "/traces/" in data["trace_url"]
