"""
AEGIS LangGraph Checkpointer Engine
Provides persistence and state saving for workflow interrupts.
Uses a configured synchronous PostgreSQL saver or an in-memory saver for local/test environments.
"""

import logging
from contextlib import ExitStack
from typing import Optional
from langgraph.checkpoint.base import BaseCheckpointSaver
from langgraph.checkpoint.memory import MemorySaver
from app.core.config import settings

logger = logging.getLogger(__name__)

# Global checkpointer instance for stateful execution
_global_checkpointer: Optional[BaseCheckpointSaver] = None
_postgres_resources: Optional[ExitStack] = None

def get_workflow_checkpointer() -> BaseCheckpointSaver:
    """
    Returns the configured checkpointer.
    Uses PostgreSQL PostgresSaver when POSTGRES_CHECKPOINT_URL is set; initialization
    errors are raised instead of silently falling back to in-memory state.
    """
    global _global_checkpointer
    if _global_checkpointer is not None:
        return _global_checkpointer

    global _postgres_resources
    pg_url = settings.POSTGRES_CHECKPOINT_URL
    if pg_url:
        resources = ExitStack()
        try:
            from langgraph.checkpoint.postgres import PostgresSaver
            checkpointer = resources.enter_context(
                PostgresSaver.from_conn_string(pg_url)
            )
            checkpointer.setup()
        except Exception as exc:
            resources.close()
            raise RuntimeError(
                "POSTGRES_CHECKPOINT_URL was set, but the PostgreSQL workflow checkpointer "
                "could not be initialized."
            ) from exc

        logger.info("Initialized PostgreSQL checkpointer for LangGraph HITL workflows.")
        _postgres_resources = resources
        _global_checkpointer = checkpointer
        return _global_checkpointer

    _global_checkpointer = MemorySaver()
    return _global_checkpointer

def close_workflow_checkpointer() -> None:
    """Release the PostgreSQL connection pool when the application shuts down."""
    global _global_checkpointer, _postgres_resources
    if _postgres_resources is not None:
        _postgres_resources.close()
        _postgres_resources = None
    _global_checkpointer = None

def reset_checkpointer_for_testing():
    """Resets checkpointer for isolated unit tests."""
    close_workflow_checkpointer()
    global _global_checkpointer
    _global_checkpointer = MemorySaver()
