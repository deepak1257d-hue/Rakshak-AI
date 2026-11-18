import asyncio
import logging
from typing import Dict, Any, List, Optional
from fastapi import WebSocket
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.models.domain import ScanRun, Finding, TargetAsset, ScanStatus, VerificationStatus

logger = logging.getLogger(__name__)

class ConnectionManager:
    """
    Manages active WebSocket connections for live scan streaming.
    """
    def __init__(self):
        self.active_connections: Dict[str, List[WebSocket]] = {}

    async def connect(self, scan_id: str, websocket: WebSocket, subprotocol: Optional[str] = None):
        await websocket.accept(subprotocol=subprotocol)
        if scan_id not in self.active_connections:
            self.active_connections[scan_id] = []
        self.active_connections[scan_id].append(websocket)

    def disconnect(self, scan_id: str, websocket: WebSocket):
        if scan_id in self.active_connections:
            if websocket in self.active_connections[scan_id]:
                self.active_connections[scan_id].remove(websocket)

    async def broadcast(self, scan_id: str, message: Dict[str, Any]):
        if scan_id in self.active_connections:
            for connection in self.active_connections[scan_id]:
                try:
                    await connection.send_json(message)
                except Exception as e:
                    logger.error(f"Error broadcasting WebSocket message: {e}")

ws_manager = ConnectionManager()

class SandboxedScannerRunner:
    """
    Executes security auditing steps deterministically inside isolated runners,
    streams events via WebSockets, and routes outputs through the Dual-LLM Pipeline.
    """
    @staticmethod
    async def execute_scan(scan_id: str, db: AsyncSession):
        result = await db.execute(select(ScanRun).where(ScanRun.id == scan_id))
        scan = result.scalars().first()
        if not scan:
            return

        # Fetch Target
        target_res = await db.execute(select(TargetAsset).where(TargetAsset.id == scan.target_id))
        target = target_res.scalars().first()
        if not target or target.verification_status != VerificationStatus.VERIFIED:
            scan.status = ScanStatus.FAILED
            scan.current_stage = "ABORTED: TARGET UNVERIFIED"
            await db.commit()
            await ws_manager.broadcast(scan_id, {
                "status": "FAILED",
                "progress_pct": 0,
                "current_stage": "ABORTED: TARGET UNVERIFIED"
            })
            return

        # Stage 1: Multi-Agent Planner Formulating Plan
        scan.status = ScanStatus.RUNNING
        scan.progress_pct = 20
        scan.current_stage = "STAGE 1/4: LangGraph Multi-Agent Planner Formulating Audit Strategy"
        await db.commit()
        await ws_manager.broadcast(scan_id, {
            "status": "RUNNING",
            "progress_pct": 20,
            "current_stage": scan.current_stage
        })

        # Stage 2: Executor Dispatching MCP Tools
        scan.progress_pct = 45
        scan.current_stage = "STAGE 2/4: Executor Dispatching Scoped Tools via MCP Servers (Nmap, Nuclei, ZAP)"
        await db.commit()
        await ws_manager.broadcast(scan_id, {
            "status": "RUNNING",
            "progress_pct": 45,
            "current_stage": scan.current_stage
        })

        # Run the full compiled LangGraph workflow
        from app.workflow.graph import run_aegis_workflow
        workflow_result = await run_aegis_workflow(
            target=target.domain,
            target_id=target.id,
            scan_id=scan.id,
            workspace_id=scan.workspace_id
        )

        # Stage 3: Untrusted Parser Sanitization & Verifier Proof Check
        scan.progress_pct = 75
        scan.current_stage = "STAGE 3/4: Untrusted Parser Sanitizing Inputs & Verifier Validating Reachability"
        await db.commit()
        await ws_manager.broadcast(scan_id, {
            "status": "RUNNING",
            "progress_pct": 75,
            "current_stage": scan.current_stage
        })

        # Stage 4: Persist System Reasoning Insights & Auto-Patches
        scan.progress_pct = 90
        scan.current_stage = "STAGE 4/4: System Reasoning Synthesizing Auto-Patches & Reporter Compiling Report"
        await db.commit()
        await ws_manager.broadcast(scan_id, {
            "status": "RUNNING",
            "progress_pct": 90,
            "current_stage": scan.current_stage
        })

        reasoned_insights = workflow_result.get("reasoned_insights", [])
        for insight in reasoned_insights:
            finding = Finding(
                scan_id=scan.id,
                workspace_id=scan.workspace_id,
                title=insight["title"],
                severity=insight["severity"],
                cve_id=insight.get("cve_id"),
                score=insight["score"],
                score_source=(insight.get("score_breakdown") or {}).get("score_source") or "UNAVAILABLE",
                reachability_proof=insight.get("reachability_proof"),
                remediation_patch=insight.get("remediation_patch"),
                sanitized_output=f"Sanitized Evidence:\n{insight.get('reachability_proof', '')}"
            )
            db.add(finding)

        # Completion & Status Assessment (Handle Partial vs Complete)
        final_rep = workflow_result.get("final_report", {})
        is_partial = final_rep.get("is_partial", False)
        trace_id = workflow_result.get("trace_id") or final_rep.get("trace_id")
        trace_url = workflow_result.get("trace_url") or final_rep.get("trace_url")

        scan.progress_pct = 100
        scan.status = ScanStatus.PARTIAL if is_partial else ScanStatus.COMPLETED
        scan.trace_id = trace_id
        scan.trace_url = trace_url
        scan.current_stage = (
            "COMPLETED (PARTIAL RESULTS): Assessment completed with scanner fallback diagnostics"
            if is_partial else
            "COMPLETED: LangGraph Multi-Agent CTEM Assessment Finished"
        )
        await db.commit()
        await ws_manager.broadcast(scan_id, {
            "status": scan.status.value,
            "progress_pct": 100,
            "current_stage": scan.current_stage,
            "is_partial": is_partial,
            "trace_id": trace_id,
            "trace_url": trace_url
        })

scanner_runner = SandboxedScannerRunner()
