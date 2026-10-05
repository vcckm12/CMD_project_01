"""Shared Ollama client (DES-005 §5, D-14·D-15).

One process-wide slot: the CPU model server slows every request down when two run at once, so chat
generations and safety-judge calls queue for the same slot. Waiting longer than `queue_wait_s` raises
InferenceBusy (429). `think` is always false and `num_ctx` is the same for every call, because a
different context size makes Ollama reload the model.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from typing import Any

import httpx


class InferenceBusy(Exception):
    """The inference slot stayed taken past the queue wait limit (429 RATE_LIMITED)."""


class InferenceUnavailable(Exception):
    """Connection failure, non-200 status or malformed response (502 INFERENCE_UNAVAILABLE)."""


class InferenceTimeout(Exception):
    """The model did not answer within the per-call timeout (504 INFERENCE_TIMEOUT)."""


@dataclass(frozen=True)
class ChatResult:
    message: dict[str, Any]
    prompt_tokens: int
    completion_tokens: int
    duration_ms: float


class OllamaClient:
    def __init__(
        self,
        base_url: str,
        model: str,
        *,
        num_ctx: int = 8192,
        keep_alive: str = "30m",
        queue_wait_s: float = 30.0,
        connect_timeout_s: float = 3.0,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.model = model
        self.num_ctx = num_ctx
        self.keep_alive = keep_alive
        self.queue_wait_s = queue_wait_s
        self._slot = asyncio.Semaphore(1)
        self._http = httpx.AsyncClient(
            base_url=base_url.rstrip("/"),
            timeout=httpx.Timeout(connect=connect_timeout_s, read=None, write=10.0, pool=5.0),
            transport=transport,
            follow_redirects=False,
            trust_env=False,  # never route model traffic through an environment proxy
        )

    async def close(self) -> None:
        await self._http.aclose()

    async def chat(
        self,
        messages: list[dict[str, Any]],
        *,
        timeout_s: float,
        num_predict: int,
        temperature: float | None = None,
        response_format: str | None = None,
        tools: list[dict[str, Any]] | None = None,
    ) -> ChatResult:
        options: dict[str, Any] = {"num_ctx": self.num_ctx, "num_predict": num_predict}
        if temperature is not None:
            options["temperature"] = temperature
        body: dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "stream": False,
            "think": False,
            "keep_alive": self.keep_alive,
            "options": options,
        }
        if response_format:
            body["format"] = response_format
        if tools:
            body["tools"] = tools

        try:
            await asyncio.wait_for(self._slot.acquire(), timeout=self.queue_wait_s)
        except TimeoutError as exc:
            raise InferenceBusy from exc
        started = time.perf_counter()
        try:
            response = await asyncio.wait_for(self._http.post("/api/chat", json=body), timeout=timeout_s)
        except TimeoutError as exc:
            raise InferenceTimeout from exc
        except httpx.HTTPError as exc:
            raise InferenceUnavailable from exc
        finally:
            self._slot.release()
        if response.status_code != 200:
            raise InferenceUnavailable
        try:
            data = response.json()
            message = data["message"]
            if not isinstance(message, dict):
                raise TypeError
        except (ValueError, KeyError, TypeError) as exc:
            raise InferenceUnavailable from exc
        message.pop("thinking", None)  # never used, stored or forwarded
        return ChatResult(
            message=message,
            prompt_tokens=int(data.get("prompt_eval_count") or 0),
            completion_tokens=int(data.get("eval_count") or 0),
            duration_ms=round((time.perf_counter() - started) * 1000, 3),
        )

    async def model_digest(self) -> str | None:
        """Digest of the configured model from /api/tags, for readiness (None when unreachable)."""
        try:
            response = await self._http.get("/api/tags", timeout=5.0)
            models = response.json().get("models", [])
        except (httpx.HTTPError, ValueError, AttributeError):
            return None
        for m in models:
            if m.get("name") == self.model or m.get("model") == self.model:
                return m.get("digest")
        return None
