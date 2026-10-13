"""Shared setup for the measurement scripts: paths, datasets, model client and the guardrail pipeline.

Run the scripts from backend/ in the test image so `app` is importable, e.g.
    docker run --rm -v "<repo>:/repo" -w /repo/backend ag_prod-db-test python /repo/scripts/eval_pipeline.py
"""

from __future__ import annotations

import json
import os
import statistics
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DATASETS = ROOT / "datasets"
sys.path.insert(0, str(ROOT / "backend"))

# The scripts import app names from here only, so `backend/` is on sys.path before `app` loads.
from app.config import Settings  # noqa: E402, F401
from app.guardrails.alerts import AlertMonitor  # noqa: E402
from app.guardrails.input_guardrail import InputGuardrailEngine, InputMessage  # noqa: E402, F401
from app.guardrails.judge import SafetyJudge  # noqa: E402
from app.guardrails.output_guardrail import OutputGuardrailEngine  # noqa: E402
from app.guardrails.pipeline import GuardrailPipeline, GuardrailUnavailable  # noqa: E402, F401
from app.guardrails.ruleset import default_snapshot  # noqa: E402, F401
from app.guardrails.types import GuardrailTimeout  # noqa: E402, F401
from app.services.ollama import InferenceBusy, OllamaClient  # noqa: E402, F401

MODEL = os.environ.get("OLLAMA_MODEL", "qwen3:8b")


def read_jsonl(path: str | Path) -> list[dict]:
    """Rows of a JSONL file: absolute, repo-relative (datasets/…, backend/…) or a bare name in datasets/."""
    path = Path(path)
    if not path.is_absolute():
        path = ROOT / path if path.parts[0] in ("datasets", "backend") else DATASETS / path
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def model_client() -> OllamaClient:
    return OllamaClient(
        os.environ.get("OLLAMA_BASE_URL", "http://10.10.70.65:11434"),
        MODEL,
        queue_wait_s=300,
    )


def pipeline(client: OllamaClient | None, judge_timeout_s: float = 60) -> GuardrailPipeline:
    """Rules + judge (both always run and are recorded in timing.layers); rules only when client is None."""
    judge = SafetyJudge(client, timeout_s=judge_timeout_s) if client else None
    return GuardrailPipeline(
        InputGuardrailEngine(),
        OutputGuardrailEngine(),
        judge,
        AlertMonitor(None, b"k" * 32),
    )


def percentiles(values: list[float]) -> str:
    if not values:
        return "no data"
    q = statistics.quantiles(values, n=100) if len(values) > 1 else [values[0]] * 99
    return f"p50 {statistics.median(values):.0f}ms · p95 {q[94]:.0f}ms · max {max(values):.0f}ms"


def rate(hits: int, total: int) -> str:
    return f"{hits}/{total} ({hits / total:.1%})" if total else "-"
