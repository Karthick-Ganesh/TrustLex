import pytest


@pytest.fixture(autouse=True)
def _no_ir_key(monkeypatch):
    """Keep tests independent of a TRUSTLEX_IR_KEY set in the developer's shell."""
    monkeypatch.delenv("TRUSTLEX_IR_KEY", raising=False)
