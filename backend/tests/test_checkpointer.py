import sys
from types import SimpleNamespace

import pytest

from app.workflow import checkpointer


@pytest.fixture(autouse=True)
def reset_checkpointer():
    checkpointer.close_workflow_checkpointer()
    yield
    checkpointer.close_workflow_checkpointer()


def test_postgres_initialization_failure_is_explicit(monkeypatch):
    class BrokenSaver:
        @classmethod
        def from_conn_string(cls, connection_string):
            raise OSError("database unavailable")

    monkeypatch.setattr(
        checkpointer.settings,
        "POSTGRES_CHECKPOINT_URL",
        "postgresql://invalid",
    )
    monkeypatch.setitem(
        sys.modules,
        "langgraph.checkpoint.postgres",
        SimpleNamespace(PostgresSaver=BrokenSaver),
    )

    with pytest.raises(RuntimeError, match="could not be initialized"):
        checkpointer.get_workflow_checkpointer()


def test_postgres_connection_resources_close_with_checkpointer(monkeypatch):
    class FakeSaver:
        closed = False

        @classmethod
        def from_conn_string(cls, connection_string):
            return cls()

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, traceback):
            self.closed = True

        def setup(self):
            pass

    monkeypatch.setattr(
        checkpointer.settings,
        "POSTGRES_CHECKPOINT_URL",
        "postgresql://configured",
    )
    monkeypatch.setitem(
        sys.modules,
        "langgraph.checkpoint.postgres",
        SimpleNamespace(PostgresSaver=FakeSaver),
    )

    saver = checkpointer.get_workflow_checkpointer()
    checkpointer.close_workflow_checkpointer()

    assert saver.closed
