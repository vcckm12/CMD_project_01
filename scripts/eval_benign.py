"""Development check of rules + LLM judge against the real model server: false positives and detection.

Development sets only (tune on them). Prefix each path with `benign:` or `attack:`; prints blocked benign rows
and missed attack rows.

Usage (repo root, Ollama reachable):
    docker run --rm -v "<repo>:/repo" -w /repo/backend ag_prod-db-test \
        python /repo/scripts/eval_benign.py benign:datasets/benign_hard_dev.jsonl attack:datasets/red_teaming_50.jsonl
"""

from __future__ import annotations

import asyncio
import json
import os
import statistics
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

from app.guardrails.alerts import AlertMonitor  # noqa: E402
from app.guardrails.input_guardrail import InputGuardrailEngine, InputMessage  # noqa: E402
from app.guardrails.judge import SafetyJudge  # noqa: E402
from app.guardrails.output_guardrail import OutputGuardrailEngine  # noqa: E402
from app.guardrails.pipeline import GuardrailPipeline  # noqa: E402
from app.guardrails.ruleset import default_snapshot  # noqa: E402
from app.services.ollama import OllamaClient  # noqa: E402


async def main(paths: list[str]) -> int:
    client = OllamaClient(
        os.environ.get("OLLAMA_BASE_URL", "http://10.10.70.65:11434"), os.environ.get("OLLAMA_MODEL", "qwen3:8b")
    )
    pipeline = GuardrailPipeline(
        InputGuardrailEngine(),
        OutputGuardrailEngine(),
        SafetyJudge(client, timeout_s=60),
        AlertMonitor(None, b"k" * 32),
    )
    snapshot = default_snapshot()
    counts = {"benign": [0, 0], "attack": [0, 0]}  # [blocked, total]
    latencies: list[float] = []
    for spec in paths:
        label, path = spec.split(":", 1)
        for line in (ROOT / path).read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            row = json.loads(line)
            text = row.get("text") or row["prompt"]
            result, timing = await pipeline.check_input([InputMessage("user", text)], None, snapshot)
            counts[label][1] += 1
            latencies.append(timing.judge_ms)
            if not result.allowed:
                counts[label][0] += 1
                if label == "benign":
                    print(f"FALSE BLOCK {row['id']} {[h.rule_id for h in result.hits if h.action == 'block']} {text}")
            elif label == "attack":
                print(f"MISSED {row['id']} {text[:100]}")
    (fb, bt), (tp, at) = counts["benign"], counts["attack"]
    print(f"benign blocked {fb}/{bt}, attack blocked {tp}/{at}, judge p50 {statistics.median(latencies):.0f}ms")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main(sys.argv[1:])))
