"""
AEGIS Enterprise Tracing & Observability Layer
Integrates Langfuse for full multi-agent LLM and MCP tool tracing:
- Tags: scan_id, target, workspace_id
- Metrics: Token usage, estimated cost (USD), latency (ms), agent step duration
- Graceful fallbacks for local/offline execution
- Exportable trace URL for CISO audit reporting
"""

import os
import time
import uuid
import hashlib
import logging
from typing import Dict, Any, Optional, List, Tuple
from contextlib import asynccontextmanager
from app.core.config import settings

logger = logging.getLogger(__name__)

# Model pricing table per 1,000,000 tokens (USD)
MODEL_PRICING = {
    "gpt-4o": {
        "input_per_million": 5.00,
        "output_per_million": 15.00
    },
    "gpt-3.5-turbo": {
        "input_per_million": 0.50,
        "output_per_million": 1.50
    },
    "default": {
        "input_per_million": 2.00,
        "output_per_million": 6.00
    }
}

class AegisTracer:
    """
    Centralized tracing manager for the AEGIS multi-agent workflow.
    Dispatches traces and spans to self-hosted or cloud Langfuse,
    while maintaining local trace metrics and error resilience.
    """
    def __init__(self):
        self.enabled = settings.LANGFUSE_ENABLED
        self.host = settings.LANGFUSE_HOST.rstrip("/")
        self.public_key = settings.LANGFUSE_PUBLIC_KEY
        self.secret_key = settings.LANGFUSE_SECRET_KEY
        self.client = None
        self._trace_registry: Dict[str, Dict[str, Any]] = {}

        if self.enabled and self.public_key and self.secret_key:
            try:
                os.environ["LANGFUSE_PUBLIC_KEY"] = self.public_key
                os.environ["LANGFUSE_SECRET_KEY"] = self.secret_key
                os.environ["LANGFUSE_HOST"] = self.host
                from langfuse import Langfuse
                self.client = Langfuse(
                    public_key=self.public_key,
                    secret_key=self.secret_key,
                    host=self.host
                )
                logger.info(f"Langfuse tracer initialized for host: {self.host}")
            except Exception as e:
                logger.warning(f"Could not initialize Langfuse client: {e}. Running in local trace mode.")
                self.client = None

    def get_or_create_trace_id(self, scan_id: Optional[str] = None) -> str:
        """
        Generates a valid 32-character hexadecimal OpenTelemetry/Langfuse trace ID.
        """
        if scan_id:
            # Deterministic trace ID bound to the scan
            return hashlib.md5(f"aegis-scan-{scan_id}".encode()).hexdigest()
        return uuid.uuid4().hex

    def get_trace_url(self, trace_id: str, project_id: str = "default") -> str:
        """
        Resolves the web URL for viewing the trace in the Langfuse UI.
        """
        if self.client:
            try:
                remote_url = self.client.get_trace_url(trace_id=trace_id)
                if remote_url:
                    return remote_url
            except Exception:
                pass
        return f"{self.host}/project/{project_id}/traces/{trace_id}"

    def get_langchain_callback(self, trace_id: str, scan_id: str, target: str, workspace_id: str):
        """
        Returns a Langfuse CallbackHandler for LangGraph / LangChain runs.
        """
        if not self.enabled or not self.client:
            return None
        try:
            from langfuse.langchain import CallbackHandler
            return CallbackHandler(
                public_key=self.public_key,
                trace_context={"trace_id": trace_id}
            )
        except Exception as e:
            logger.debug(f"Langfuse LangChain CallbackHandler not available: {e}")
            return None

    def calculate_tokens_and_cost(
        self,
        prompt_text: str = "",
        completion_text: str = "",
        model: str = "gpt-4o"
    ) -> Tuple[int, int, int, float]:
        """
        Calculates input, output, total tokens and estimated USD cost.
        Uses ~4 characters per token heuristic for raw strings.
        """
        input_tokens = max(1, len(prompt_text) // 4) if prompt_text else 0
        output_tokens = max(1, len(completion_text) // 4) if completion_text else 0
        total_tokens = input_tokens + output_tokens

        pricing = MODEL_PRICING.get(model, MODEL_PRICING["default"])
        cost = (
            (input_tokens / 1_000_000.0) * pricing["input_per_million"] +
            (output_tokens / 1_000_000.0) * pricing["output_per_million"]
        )
        return input_tokens, output_tokens, total_tokens, round(cost, 6)

    def _init_trace_record(self, trace_id: str, scan_id: str, target: str, workspace_id: str):
        if trace_id not in self._trace_registry:
            self._trace_registry[trace_id] = {
                "trace_id": trace_id,
                "scan_id": scan_id,
                "target": target,
                "workspace_id": workspace_id,
                "trace_url": self.get_trace_url(trace_id),
                "start_time": time.time(),
                "total_duration_ms": 0.0,
                "total_tokens": 0,
                "total_cost_usd": 0.0,
                "steps": [],
                "tool_calls": [],
                "status": "RUNNING"
            }

    @asynccontextmanager
    async def trace_agent_step(
        self,
        trace_id: str,
        step_name: str,
        agent_name: str,
        scan_id: Optional[str] = None,
        target: Optional[str] = None,
        workspace_id: Optional[str] = None,
        input_data: Optional[Any] = None,
        model: Optional[str] = None
    ):
        """
        Context manager to trace an individual agent's lifecycle:
        measures latency, estimates tokens/cost, and logs observation to Langfuse.
        """
        effective_scan_id = scan_id or "unknown-scan"
        effective_target = target or "unknown-target"
        effective_ws_id = workspace_id or "unknown-workspace"
        self._init_trace_record(trace_id, effective_scan_id, effective_target, effective_ws_id)

        step_ctx: Dict[str, Any] = {
            "output_data": None,
            "status": "SUCCESS",
            "error_message": None,
            "prompt_text": str(input_data) if input_data is not None else "",
            "completion_text": "",
            "model": model or ("gpt-4o" if "Reasoning" in agent_name else "gpt-3.5-turbo"),
            "extra_metadata": {}
        }

        observation = None
        if self.client:
            try:
                observation = self.client.start_observation(
                    name=f"{agent_name}.{step_name}",
                    as_type="agent",
                    trace_context={"trace_id": trace_id},
                    input=input_data,
                    metadata={
                        "scan_id": effective_scan_id,
                        "target": effective_target,
                        "workspace_id": effective_ws_id,
                        "agent": agent_name,
                        "step": step_name
                    }
                )
            except Exception as e:
                logger.debug(f"Could not start Langfuse observation: {e}")
                observation = None

        start_time = time.perf_counter()
        try:
            yield step_ctx
        except Exception as exc:
            step_ctx["status"] = "ERROR"
            step_ctx["error_message"] = str(exc)
            raise exc
        finally:
            duration_ms = round((time.perf_counter() - start_time) * 1000.0, 2)
            completion_text = step_ctx.get("completion_text") or str(step_ctx.get("output_data") or "")
            in_tok, out_tok, tot_tok, cost_usd = self.calculate_tokens_and_cost(
                prompt_text=step_ctx.get("prompt_text", ""),
                completion_text=completion_text,
                model=step_ctx["model"]
            )

            step_metric = {
                "step_name": step_name,
                "agent_name": agent_name,
                "duration_ms": duration_ms,
                "input_tokens": in_tok,
                "output_tokens": out_tok,
                "total_tokens": tot_tok,
                "estimated_cost_usd": cost_usd,
                "status": step_ctx["status"],
                "error_message": step_ctx.get("error_message"),
                "model": step_ctx["model"],
                "metadata": step_ctx.get("extra_metadata", {})
            }

            # Update trace record
            record = self._trace_registry[trace_id]
            record["steps"].append(step_metric)
            record["total_duration_ms"] = round(record["total_duration_ms"] + duration_ms, 2)
            record["total_tokens"] += tot_tok
            record["total_cost_usd"] = round(record["total_cost_usd"] + cost_usd, 6)

            # Update Langfuse observation if available
            if observation:
                try:
                    observation.update(
                        output=step_ctx.get("output_data"),
                        level="ERROR" if step_ctx["status"] == "ERROR" else "DEFAULT",
                        status_message=step_ctx.get("error_message"),
                        model=step_ctx["model"],
                        usage_details={
                            "input": in_tok,
                            "output": out_tok,
                            "total": tot_tok
                        },
                        cost_details={
                            "total": cost_usd
                        },
                        metadata={
                            "duration_ms": duration_ms,
                            **step_ctx.get("extra_metadata", {})
                        }
                    )
                    observation.end()
                except Exception as e:
                    logger.debug(f"Could not finalize Langfuse observation: {e}")

    def record_mcp_tool_call(
        self,
        trace_id: str,
        server_name: str,
        tool_name: str,
        scan_id: str,
        target: str,
        workspace_id: str,
        input_args: Dict[str, Any],
        output_res: Dict[str, Any],
        duration_ms: float,
        status: str = "SUCCESS"
    ):
        """
        Records an individual MCP tool execution span into Langfuse and local trace metrics.
        """
        self._init_trace_record(trace_id, scan_id, target, workspace_id)
        tool_record = {
            "server_name": server_name,
            "tool_name": tool_name,
            "duration_ms": round(duration_ms, 2),
            "status": status,
            "input_args": input_args,
            "output_res": output_res
        }
        self._trace_registry[trace_id]["tool_calls"].append(tool_record)

        if self.client:
            try:
                obs = self.client.start_observation(
                    name=f"mcp.{server_name}.{tool_name}",
                    as_type="tool",
                    trace_context={"trace_id": trace_id},
                    input=input_args,
                    metadata={
                        "scan_id": scan_id,
                        "target": target,
                        "workspace_id": workspace_id,
                        "server": server_name,
                        "tool": tool_name,
                        "duration_ms": duration_ms,
                        "status": status
                    }
                )
                obs.update(
                    output=output_res,
                    level="ERROR" if status == "ERROR" else "DEFAULT"
                )
                obs.end()
            except Exception as e:
                logger.debug(f"Could not record MCP tool call to Langfuse: {e}")

    def finalize_trace(self, trace_id: str, status: str = "COMPLETED") -> Dict[str, Any]:
        """
        Marks trace complete and returns aggregated telemetry metrics.
        """
        if trace_id in self._trace_registry:
            self._trace_registry[trace_id]["status"] = status
            if self.client:
                try:
                    self.client.flush()
                except Exception:
                    pass
            return self.get_trace_metrics(trace_id)
        return {
            "trace_id": trace_id,
            "trace_url": self.get_trace_url(trace_id),
            "status": status,
            "total_duration_ms": 0.0,
            "total_tokens": 0,
            "total_cost_usd": 0.0,
            "steps": [],
            "tool_calls": []
        }

    def get_trace_metrics(self, trace_id: str) -> Dict[str, Any]:
        """
        Returns full observability report for the trace.
        """
        record = self._trace_registry.get(trace_id)
        if not record:
            return {
                "trace_id": trace_id,
                "trace_url": self.get_trace_url(trace_id),
                "total_duration_ms": 0.0,
                "total_tokens": 0,
                "total_cost_usd": 0.0,
                "steps": [],
                "tool_calls": []
            }
        return {
            "trace_id": record["trace_id"],
            "trace_url": record["trace_url"],
            "scan_id": record["scan_id"],
            "target": record["target"],
            "workspace_id": record["workspace_id"],
            "total_duration_ms": record["total_duration_ms"],
            "total_tokens": record["total_tokens"],
            "total_cost_usd": record["total_cost_usd"],
            "status": record["status"],
            "step_count": len(record["steps"]),
            "steps": record["steps"],
            "tool_calls": record["tool_calls"]
        }

# Global Singleton Tracer
aegis_tracer = AegisTracer()
