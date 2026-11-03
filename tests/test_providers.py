"""Provider behaviour that the other evaluation tests do not cover."""
import json
import sys
from pathlib import Path

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "eval"))

from providers import OpenAICompatProvider  # noqa: E402


def test_ollama_repetition_abort_returns_the_text_written_so_far():
    """Ollama answers a reply that loops on one token with HTTP 500 'token repeat limit';
    the provider then reads the text up to the abort from a streamed request."""
    def handler(request):
        body = json.loads(request.content)
        if not body.get("stream"):
            return httpx.Response(500, json={"error": {"message": "prediction aborted, token repeat limit reached"}})
        chunks = ['data: {"choices":[{"delta":{"content":"Summary: "}}]}',
                  'data: {"choices":[{"delta":{"content":"two e-mails"}}]}',
                  'data: {"error":{"message":"prediction aborted, token repeat limit reached"}}']
        return httpx.Response(200, text="\n\n".join(chunks) + "\n\n")
    p = OpenAICompatProvider("m", base_url="http://local/v1", transport=httpx.MockTransport(handler))
    assert p.complete("s", [{"role": "user", "content": "u"}], 0.0, 16) == "Summary: two e-mails"


def test_other_server_errors_are_still_retried():
    p = OpenAICompatProvider("m", base_url="http://local/v1",
                             transport=httpx.MockTransport(lambda r: httpx.Response(503, text="busy")))
    try:
        p.complete("s", [{"role": "user", "content": "u"}], 0.0, 16)
    except Exception as exc:  # noqa: BLE001
        assert type(exc).__name__ == "RetryableError"
    else:
        raise AssertionError("expected a retryable error")
