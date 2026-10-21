import pytest


@pytest.fixture(autouse=True)
def _clean_environment(monkeypatch):
    """Keep tests independent of TrustLex variables set in the developer's shell."""
    monkeypatch.delenv("TRUSTLEX_IR_KEY", raising=False)
    monkeypatch.delenv("TRUSTLEX_DEFAULT_MODEL", raising=False)
