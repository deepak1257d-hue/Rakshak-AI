"""
AEGIS LangGraph Multi-Agent Workflow Graph with Human-in-the-Loop Checkpointing
Orchestrates:
START -> Planner -> Executor -> Parser (untrusted) -> Verifier -> (Loop < 2: Planner -> Executor)
      -> Reasoning -> Reporter -> ApprovalGate (review interrupt) -> END
"""

import uuid
import logging
from typing import Dict, Any, Optional
from langgraph.graph import StateGraph, START, END
from langgraph.types import Command
from app.workflow.state import AgentWorkflowState
from app.workflow.checkpointer import get_workflow_checkpointer
from app.workflow.nodes.planner import planner_node
from app.workflow.nodes.executor import executor_node
from app.workflow.nodes.parser import parser_node
from app.workflow.nodes.verifier import verifier_node, route_verifier_decision
from app.workflow.nodes.reasoning import reasoning_node
from app.workflow.nodes.reporter import reporter_node
from app.workflow.nodes.approval_gate import approval_gate_node
from app.core.tracing import aegis_tracer

logger = logging.getLogger(__name__)

def build_aegis_workflow_graph() -> StateGraph:
    """
    Constructs the AEGIS StateGraph connecting all workflow nodes, including
    the review interrupt. Dispatch authorization is handled by the authenticated API.
    """
    graph = StateGraph(AgentWorkflowState)

    # 1. Register Nodes
    graph.add_node("planner", planner_node)
    graph.add_node("executor", executor_node)
    graph.add_node("parser", parser_node)
    graph.add_node("verifier", verifier_node)
    graph.add_node("reasoning", reasoning_node)
    graph.add_node("reporter", reporter_node)
    graph.add_node("approval_gate", approval_gate_node)

    # 2. Add Fixed Edges
    graph.add_edge(START, "planner")
    graph.add_edge("planner", "executor")
    graph.add_edge("executor", "parser")
    graph.add_edge("parser", "verifier")

    # 3. Add Conditional Verification Edge (Evidence check & loop bounding)
    graph.add_conditional_edges(
        "verifier",
        route_verifier_decision,
        {
            "planner": "planner",
            "reasoning": "reasoning"
        }
    )

    # 4. Add Reasoning -> Reporter -> Approval Gate (review interrupt) -> END
    graph.add_edge("reasoning", "reporter")
    graph.add_edge("reporter", "approval_gate")
    graph.add_edge("approval_gate", END)

    return graph

# Compile the workflow graph with persistent checkpointer
checkpointer = get_workflow_checkpointer()
aegis_workflow_app = build_aegis_workflow_graph().compile(checkpointer=checkpointer)

async def run_aegis_workflow(
    target: str,
    target_id: Optional[str] = None,
    scan_id: Optional[str] = None,
    workspace_id: Optional[str] = None,
    thread_id: Optional[str] = None
) -> Dict[str, Any]:
    """
    Executes the workflow for a target and pauses for review when patches exist.
    Workflow-thread decisions cannot authorize pull-request dispatch.
    """
    effective_thread = thread_id or scan_id or f"scan-thread-{uuid.uuid4()}"
    trace_id = aegis_tracer.get_or_create_trace_id(scan_id)
    trace_url = aegis_tracer.get_trace_url(trace_id)

    # Initialize Langfuse callbacks and telemetry tags
    lf_callback = aegis_tracer.get_langchain_callback(
        trace_id=trace_id,
        scan_id=scan_id or "unknown",
        target=target,
        workspace_id=workspace_id or "unknown"
    )
    callbacks = [lf_callback] if lf_callback else []

    config = {
        "configurable": {"thread_id": effective_thread},
        "callbacks": callbacks,
        "tags": [scan_id or "scan", target, workspace_id or "workspace"],
        "metadata": {
            "scan_id": scan_id,
            "target": target,
            "workspace_id": workspace_id,
            "trace_id": trace_id
        }
    }

    initial_state: AgentWorkflowState = {
        "target": target,
        "target_id": target_id,
        "scan_id": scan_id,
        "workspace_id": workspace_id,
        "plan": {},
        "current_phase_index": 0,
        "raw_tool_outputs": [],
        "parsed_findings": [],
        "verified_findings": [],
        "needs_reverification": False,
        "reasoned_insights": [],
        "final_report": {},
        "verification_loops": 0,
        "max_verification_loops": 2,
        "dispatched_prs": [],
        "approval_status": None,
        "audit_trail": [],
        "trace_id": trace_id,
        "trace_url": trace_url,
        "trace_metrics": None,
        "status": "INITIALIZING"
    }

    result = await aegis_workflow_app.ainvoke(initial_state, config=config)

    # If paused at approval gate, extract the full accumulated state values
    if "__interrupt__" in result:
        state_snapshot = get_workflow_state(effective_thread)
        merged = dict(state_snapshot.values) if state_snapshot and state_snapshot.values else {}
        merged["__interrupt__"] = result["__interrupt__"]
        merged["thread_id"] = effective_thread

        return merged

    return result

async def resume_workflow_approval(
    thread_id: str,
    decision: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Resumes the review workflow only; this cannot authorize or dispatch a pull request.
    """
    config = {"configurable": {"thread_id": thread_id}}
    result = await aegis_workflow_app.ainvoke(Command(resume=decision), config=config)
    return result

def get_workflow_state(thread_id: str):
    """
    Retrieves the current checkpoint state for a thread.
    """
    config = {"configurable": {"thread_id": thread_id}}
    return aegis_workflow_app.get_state(config)
