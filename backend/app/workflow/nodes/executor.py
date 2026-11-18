"""
AEGIS Executor Agent Node with Retries, Exponential Backoff, and Fallback Routing
Dispatches tools through the MCP layer with:
- Configurable timeouts
- Exponential backoff retry logic (e.g., on network drops or temporary failures)
- Automated fallback tool switching (e.g., ZAP fails -> Nuclei)
- Partial results preservation (failed tools do not abort the entire assessment)
"""

import asyncio
import time
import logging
from typing import Dict, Any, List, Optional
from app.workflow.state import AgentWorkflowState, AuditPlan, ScanPhase
from app.workflow.allowlists import enforce_agent_tool_permission
from app.mcp.client import mcp_registry
from app.core.tracing import aegis_tracer

logger = logging.getLogger(__name__)

# Fallback tool definitions when primary scanner fails
FALLBACK_TOOL_CHAINS: Dict[str, Dict[str, Any]] = {
    # If OWASP ZAP baseline fails/times out, fallback to Nuclei web auditing
    "zap_baseline_scan": {
        "fallback_server": "nuclei",
        "fallback_tool": "nuclei_scan",
        "reason": "ZAP scanner failed or timed out; falling back to Nuclei vulnerability audit.",
        "adapter": lambda p: {
            "target": p.get("target_url", p.get("target", "")),
            "severity": "low,medium,high,critical",
            "tags": "cve,misconfig,exposure"
        }
    },
    # If Nmap comprehensive port scan fails, fallback to targeted Nmap service probe
    "nmap_port_scan": {
        "fallback_server": "nmap",
        "fallback_tool": "nmap_service_probe",
        "reason": "Nmap port scan failed; falling back to targeted web port service probe.",
        "adapter": lambda p: {
            "target": p.get("target", ""),
            "port": 80
        }
    }
}

async def execute_with_exponential_backoff(
    server_name: str,
    tool_name: str,
    parameters: Dict[str, Any],
    max_retries: int = 2,
    initial_delay: float = 0.25,
    backoff_factor: float = 2.0,
    timeout_seconds: float = 30.0
) -> Dict[str, Any]:
    """
    Executes an MCP tool call with timeout and exponential backoff retry handling.
    """
    last_res: Dict[str, Any] = {}
    last_error = ""

    for attempt in range(max_retries + 1):
        try:
            # Enforce execution timeout
            res = await asyncio.wait_for(
                mcp_registry.call_tool(server_name, tool_name, parameters),
                timeout=timeout_seconds
            )
            status = res.get("status", "")

            # Missing optional binaries and guardrail refusals are not retryable.
            if status in ["SUCCESS", "REFUSED", "UNAVAILABLE"]:
                return res

            last_res = res
            last_error = res.get("error", f"Tool status: {status}")

        except asyncio.TimeoutError:
            last_error = f"Tool '{tool_name}' timed out after {timeout_seconds}s (Attempt {attempt + 1}/{max_retries + 1})"
            last_res = {"status": "TIMEOUT", "error": last_error}
        except Exception as e:
            last_error = f"Exception in '{tool_name}': {str(e)} (Attempt {attempt + 1}/{max_retries + 1})"
            last_res = {"status": "ERROR", "error": last_error}

        if attempt < max_retries:
            delay = initial_delay * (backoff_factor ** attempt)
            logger.warning(f"Retryable failure on {server_name}.{tool_name}: {last_error}. Backing off for {delay:.2f}s...")
            await asyncio.sleep(delay)

    return last_res

async def executor_node(state: AgentWorkflowState) -> Dict[str, Any]:
    """
    Executor Node:
    - Iterates over PENDING phases in the AuditPlan.
    - Validates tool against Executor allowlist.
    - Executes tool with exponential backoff retries.
    - If primary tool fails, attempts configured fallback tool (e.g. ZAP -> Nuclei).
    - Preserves partial results and surfaces phase statuses to state.
    - Traces execution latency, token consumption, and individual MCP tool calls via Langfuse.
    """
    plan_data = state.get("plan", {})
    if not plan_data:
        return {"status": "EXECUTOR_ERROR_NO_PLAN"}

    plan = AuditPlan(**plan_data)
    raw_outputs: List[Dict[str, Any]] = list(state.get("raw_tool_outputs", []))
    audit_trail = list(state.get("audit_trail", []))
    target = state.get("target", "")
    scan_id = state.get("scan_id")
    workspace_id = state.get("workspace_id")
    trace_id = state.get("trace_id") or aegis_tracer.get_or_create_trace_id(scan_id)

    async with aegis_tracer.trace_agent_step(
        trace_id=trace_id,
        step_name="tool_execution_cycle",
        agent_name="ExecutorAgent",
        scan_id=scan_id,
        target=target,
        workspace_id=workspace_id,
        input_data={"target": target, "total_phases": len(plan.phases)}
    ) as trace_ctx:
        completed_count = 0
        fallback_count = 0
        failed_count = 0

        for phase in plan.phases:
            if phase.status == "PENDING":
                tool_name = phase.tool_name
                server_name = phase.server_name
                params = dict(phase.parameters)

                               # Target normalization
                if "target" not in params and "target_url" not in params and "target_path" not in params:
                    if server_name == "zap":
                        if target.startswith(("localhost", "127.0.0.1")):
                            local_target = target
                            if target in ("localhost", "127.0.0.1"):
                                local_target = f"{target}:3000"
                            params["target_url"] = f"http://{local_target}"
                        else:
                            params["target_url"] = (
                                target if target.startswith(("http://", "https://"))
                                else f"https://{target}"
                            )
                    elif server_name == "trivy":
                        params["target_path"] = target
                    else:
                        params["target"] = target

                # 1. Enforce strict tool allowlist
                enforce_agent_tool_permission("executor", tool_name)

                phase.status = "IN_PROGRESS"
                phase.attempts += 1
                logger.info(f"Executor running {server_name}.{tool_name} (Attempt 1)")

                # 2. Execute with retry & exponential backoff
                t_tool_start = time.perf_counter()
                tool_res = await execute_with_exponential_backoff(
                    server_name=server_name,
                    tool_name=tool_name,
                    parameters=params,
                    max_retries=2,
                    initial_delay=0.25,
                    backoff_factor=2.0
                )
                tool_dur_ms = (time.perf_counter() - t_tool_start) * 1000.0

                # Record MCP tool span in Langfuse
                aegis_tracer.record_mcp_tool_call(
                    trace_id=trace_id,
                    server_name=server_name,
                    tool_name=tool_name,
                    scan_id=scan_id or "unknown-scan",
                    target=target,
                    workspace_id=workspace_id or "unknown-workspace",
                    input_args=params,
                    output_res=tool_res,
                    duration_ms=tool_dur_ms,
                    status=tool_res.get("status", "UNKNOWN")
                )

                is_success = tool_res.get("status") == "SUCCESS"

                # 3. Fallback Handling if primary tool failed
                if not is_success and tool_name in FALLBACK_TOOL_CHAINS:
                    fallback_info = FALLBACK_TOOL_CHAINS[tool_name]
                    fb_server = fallback_info["fallback_server"]
                    fb_tool = fallback_info["fallback_tool"]
                    fb_params = fallback_info["adapter"](params)

                    logger.warning(f"Primary scanner {tool_name} failed. Triggering fallback -> {fb_server}.{fb_tool}")

                    audit_trail.append({
                        "agent": "Executor",
                        "action": "FALLBACK_TRIGGERED",
                        "original_tool": tool_name,
                        "fallback_tool": fb_tool,
                        "reason": fallback_info["reason"]
                    })

                    # Validate fallback tool in allowlist
                    enforce_agent_tool_permission("executor", fb_tool)

                    t_fb_start = time.perf_counter()
                    fb_res = await execute_with_exponential_backoff(
                        server_name=fb_server,
                        tool_name=fb_tool,
                        parameters=fb_params,
                        max_retries=1,
                        initial_delay=0.25
                    )
                    fb_dur_ms = (time.perf_counter() - t_fb_start) * 1000.0

                    # Record Fallback MCP tool span in Langfuse
                    aegis_tracer.record_mcp_tool_call(
                        trace_id=trace_id,
                        server_name=fb_server,
                        tool_name=fb_tool,
                        scan_id=scan_id or "unknown-scan",
                        target=target,
                        workspace_id=workspace_id or "unknown-workspace",
                        input_args=fb_params,
                        output_res=fb_res,
                        duration_ms=fb_dur_ms,
                        status=fb_res.get("status", "UNKNOWN")
                    )

                    if fb_res.get("status") == "SUCCESS":
                        phase.status = "FALLBACK_COMPLETED"
                        phase.fallback_triggered = True
                        phase.fallback_details = {
                            "original_tool": tool_name,
                            "fallback_tool": fb_tool,
                            "primary_error": tool_res.get("error", "Unknown primary error")
                        }
                        raw_outputs.append({
                            "phase_name": f"{phase.phase_name} [Fallback via {fb_tool}]",
                            "tool_name": fb_tool,
                            "server_name": fb_server,
                            "parameters": fb_params,
                            "output": fb_res,
                            "is_fallback": True
                        })
                        fallback_count += 1
                        audit_trail.append({
                            "agent": "Executor",
                            "action": "FALLBACK_SUCCEEDED",
                            "tool": fb_tool,
                            "status": "SUCCESS"
                        })
                    else:
                        phase.status = "FAILED"
                        phase.error_message = f"Both primary '{tool_name}' and fallback '{fb_tool}' failed."
                        failed_count += 1
                        audit_trail.append({
                            "agent": "Executor",
                            "action": "TOOL_AND_FALLBACK_FAILED",
                            "original_tool": tool_name,
                            "fallback_tool": fb_tool
                        })

                elif is_success:
                    phase.status = "COMPLETED"
                    raw_outputs.append({
                        "phase_name": phase.phase_name,
                        "tool_name": tool_name,
                        "server_name": server_name,
                        "parameters": params,
                        "output": tool_res
                    })
                    completed_count += 1
                    audit_trail.append({
                        "agent": "Executor",
                        "action": "TOOL_EXECUTED",
                        "tool": tool_name,
                        "status": "SUCCESS"
                    })

                else:
                    # Primary failed and no fallback available
                    phase.status = "FAILED"
                    phase.error_message = tool_res.get("error", "Tool execution failed")
                    failed_count += 1
                    audit_trail.append({
                        "agent": "Executor",
                        "action": "TOOL_FAILED_NO_FALLBACK",
                        "tool": tool_name,
                        "error": phase.error_message
                    })

        # Summary of phase execution
        total_phases = len(plan.phases)
        if failed_count == 0:
            overall_status = "EXECUTION_COMPLETED"
        elif completed_count + fallback_count > 0:
            overall_status = "EXECUTION_PARTIAL_COMPLETED"
        else:
            overall_status = "EXECUTION_ALL_FAILED"

        plan.execution_summary = {
            "status": overall_status,
            "total_phases": total_phases,
            "completed_count": completed_count,
            "fallback_count": fallback_count,
            "failed_count": failed_count,
            "partial_results_allowed": True
        }

        audit_trail.append({
            "agent": "Executor",
            "action": "EXECUTION_CYCLE_SUMMARY",
            "overall_status": overall_status,
            "completed": completed_count,
            "fallback": fallback_count,
            "failed": failed_count
        })

        result = {
            "plan": plan.model_dump(),
            "raw_tool_outputs": raw_outputs,
            "audit_trail": audit_trail,
            "needs_reverification": False,
            "trace_id": trace_id,
            "trace_url": aegis_tracer.get_trace_url(trace_id),
            "status": overall_status
        }
        trace_ctx["output_data"] = {
            "completed": completed_count,
            "fallback": fallback_count,
            "failed": failed_count,
            "raw_outputs_count": len(raw_outputs)
        }
        return result
