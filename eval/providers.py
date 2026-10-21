"""
LLM providers for the live attack-success experiment (eval/llm_asr.py).

    Provider.complete(system, messages, temperature, max_tokens) -> str

* GeminiProvider        Google Gemini REST API (generateContent); key from
                        $GEMINI_API_KEY (or another variable).
* OpenAICompatProvider  any OpenAI-style /chat/completions endpoint: Groq
                        (https://api.groq.com/openai/v1, $GROQ_API_KEY),
                        OpenRouter, or a local Ollama (http://localhost:11434/v1,
                        no key).
* FakeProvider          offline stand-in for tests: obeys an attack (repeats
                        its canary) with a configurable probability.

ReliableClient wraps any provider with a requests-per-minute limit, retries
with exponential backoff on 429/5xx (at most 5), a timeout, and a JSONL
response cache keyed by SHA-256 of (provider, model, system, messages,
temperature), so re-runs do not spend quota again.

API keys are read from the environment only (llm_asr.py loads a .env file
into it). They are sent in request headers, never in URLs, and are never
printed, logged or written to disk.
"""

from __future__ import annotations

import hashlib
import json
import os
import random
import re
import threading
import time
from abc import ABC, abstractmethod
from pathlib import Path

import httpx

RETRY_STATUS = {429, 500, 502, 503, 504}
MAX_RETRIES = 5
DEFAULT_TIMEOUT = 60.0


class ProviderError(Exception):
    """A request failed for good (after retries, or with a non-retryable status)."""


class MissingKeyError(ProviderError):
    pass


def _key(env_var: str | None) -> str | None:
    if not env_var:
        return None
    value = os.environ.get(env_var)
    if not value:
        raise MissingKeyError(f"environment variable {env_var} is not set (add it to .env or your shell)")
    return value


class Provider(ABC):
    name = "provider"

    def __init__(self, model: str):
        if not model:
            raise ValueError("a model ID is required")
        self.model = model

    @abstractmethod
    def complete(self, system: str, messages: list[dict], temperature: float, max_tokens: int) -> str:
        """Return the model's reply text."""


class _HTTPProvider(Provider):
    def __init__(self, model: str, timeout: float = DEFAULT_TIMEOUT, transport: httpx.BaseTransport | None = None):
        super().__init__(model)
        self._client = httpx.Client(timeout=timeout, transport=transport)

    def _post(self, url: str, headers: dict, body: dict) -> dict:
        response = self._client.post(url, headers=headers, json=body)
        if response.status_code in RETRY_STATUS:
            raise RetryableError(response.status_code, _retry_after(response))
        if response.status_code >= 400:
            # The body is the provider's error message; headers (with the key) are never shown.
            raise ProviderError(f"{self.name} returned HTTP {response.status_code}: {response.text[:300]}")
        return response.json()


class GeminiProvider(_HTTPProvider):
    name = "gemini"
    BASE_URL = "https://generativelanguage.googleapis.com/v1beta"

    def __init__(self, model: str, key_env: str = "GEMINI_API_KEY", **kwargs):
        super().__init__(model, **kwargs)
        self.key_env = key_env

    def request(self, system: str, messages: list[dict], temperature: float, max_tokens: int) -> dict:
        body = {
            "contents": [{"role": "model" if m["role"] == "assistant" else "user", "parts": [{"text": m["content"]}]}
                         for m in messages],
            "generationConfig": {"temperature": temperature, "maxOutputTokens": max_tokens},
        }
        if system:
            body["systemInstruction"] = {"parts": [{"text": system}]}
        return body

    def complete(self, system, messages, temperature, max_tokens) -> str:
        headers = {"x-goog-api-key": _key(self.key_env), "Content-Type": "application/json"}
        url = f"{self.BASE_URL}/models/{self.model}:generateContent"
        data = self._post(url, headers, self.request(system, messages, temperature, max_tokens))
        candidates = data.get("candidates") or []
        if not candidates:
            return ""  # blocked by the provider's safety filter: no reply
        parts = (candidates[0].get("content") or {}).get("parts") or []
        return "".join(p.get("text", "") for p in parts)


class OpenAICompatProvider(_HTTPProvider):
    name = "openai_compat"

    def __init__(self, model: str, base_url: str, key_env: str | None = None, **kwargs):
        super().__init__(model, **kwargs)
        if not base_url:
            raise ValueError("--base-url is required for openai_compat (e.g. https://api.groq.com/openai/v1)")
        self.base_url = base_url.rstrip("/")
        self.key_env = key_env

    def request(self, system: str, messages: list[dict], temperature: float, max_tokens: int) -> dict:
        chat = ([{"role": "system", "content": system}] if system else []) + list(messages)
        return {"model": self.model, "messages": chat, "temperature": temperature, "max_tokens": max_tokens}

    def complete(self, system, messages, temperature, max_tokens) -> str:
        headers = {"Content-Type": "application/json"}
        key = _key(self.key_env)
        if key:
            headers["Authorization"] = f"Bearer {key}"
        data = self._post(f"{self.base_url}/chat/completions", headers,
                          self.request(system, messages, temperature, max_tokens))
        choices = data.get("choices") or []
        if not choices:
            return ""
        return (choices[0].get("message") or {}).get("content") or ""


_CANARY = re.compile(r"TLX-[0-9A-F]{6}")


class FakeProvider(Provider):
    """Offline model. If the prompt contains a canary it repeats it with
    probability `obey`; otherwise it gives a polite answer echoing the request
    (with any canary removed). Deterministic for a given prompt and seed."""

    name = "fake"

    def __init__(self, model: str = "fake", obey: float = 0.5, seed: int = 0):
        super().__init__(model)
        self.obey = obey
        self.seed = seed
        self.calls = 0

    def complete(self, system, messages, temperature, max_tokens) -> str:
        self.calls += 1
        text = "\n".join([system, *(m["content"] for m in messages)])
        rng = random.Random(hashlib.sha256(f"{self.seed}\x1f{text}".encode("utf-8")).digest())
        found = _CANARY.findall(text)
        if found and rng.random() < self.obey:
            return f"Sure! {found[0]}"
        return "Thanks for contacting Acme support. About your request: " + _CANARY.sub("", text)[-400:]


# ---- reliability: rate limit, retries, cache ---------------------------------

class RetryableError(Exception):
    def __init__(self, status: int, retry_after: float | None = None):
        super().__init__(f"HTTP {status}")
        self.status = status
        self.retry_after = retry_after


def _retry_after(response: httpx.Response) -> float | None:
    try:
        return float(response.headers.get("retry-after", ""))
    except ValueError:
        return None


def cache_key(provider: str, model: str, system: str, messages: list[dict], temperature: float) -> str:
    blob = json.dumps([provider, model, system, messages, temperature], sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


class ReliableClient:
    """Rate-limited, retrying, caching front for a Provider."""

    def __init__(self, provider: Provider, cache_path: Path | None = None, rpm: float = 20,
                 sleep=time.sleep, clock=time.monotonic, max_retries: int = MAX_RETRIES):
        self.provider = provider
        self.cache_path = cache_path
        self.interval = 60.0 / rpm if rpm > 0 else 0.0
        self.sleep, self.clock = sleep, clock
        self.max_retries = max_retries
        self._last = None
        self._lock = threading.Lock()
        self.cache: dict[str, str] = {}
        self.requests = 0  # sent to the provider, including retries
        if cache_path is not None and cache_path.exists():
            with cache_path.open(encoding="utf-8") as f:
                for line in f:
                    if line.strip():
                        entry = json.loads(line)
                        self.cache[entry["key"]] = entry["response"]

    def key(self, system: str, messages: list[dict], temperature: float) -> str:
        return cache_key(self.provider.name, self.provider.model, system, messages, temperature)

    def is_cached(self, system: str, messages: list[dict], temperature: float) -> bool:
        return self.key(system, messages, temperature) in self.cache

    def _wait_for_slot(self):
        if self._last is not None and self.interval:
            remaining = self.interval - (self.clock() - self._last)
            if remaining > 0:
                self.sleep(remaining)
        self._last = self.clock()

    def complete(self, system: str, messages: list[dict], temperature: float, max_tokens: int) -> tuple[str, bool]:
        """Return (reply, from_cache)."""
        key = self.key(system, messages, temperature)
        if key in self.cache:
            return self.cache[key], True
        for attempt in range(self.max_retries + 1):
            self._wait_for_slot()
            self.requests += 1
            try:
                reply = self.provider.complete(system, messages, temperature, max_tokens)
                break
            except (RetryableError, httpx.TimeoutException, httpx.TransportError) as exc:
                if attempt == self.max_retries:
                    raise ProviderError(f"giving up after {attempt + 1} attempts: {exc}") from exc
                delay = getattr(exc, "retry_after", None) or 2.0 ** attempt
                self.sleep(min(delay, 60.0))
        self.cache[key] = reply
        if self.cache_path is not None:
            with self.cache_path.open("a", encoding="utf-8") as f:
                f.write(json.dumps({"key": key, "provider": self.provider.name, "model": self.provider.model,
                                    "response": reply}, ensure_ascii=False) + "\n")
        return reply, False


def make_provider(name: str, model: str, base_url: str | None = None, key_env: str | None = None,
                  obey: float = 0.5, **kwargs) -> Provider:
    if name == "gemini":
        return GeminiProvider(model, key_env=key_env or "GEMINI_API_KEY", **kwargs)
    if name == "openai_compat":
        return OpenAICompatProvider(model, base_url=base_url, key_env=key_env, **kwargs)
    if name == "fake":
        return FakeProvider(model, obey=obey)
    raise ValueError(f"unknown provider {name!r}")
