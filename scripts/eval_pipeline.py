"""Measure rules + LLM judge against the real model server (DES-007 §3, D-25).

Reports rules-only and rules+judge detection for held-out sets, plus judge latency. Each held-out set
is meant to be measured once; do not tune prompts or rules against its results.

Usage (repo root, Ollama reachable):
    docker run --rm -v "<repo>:/repo" -w /repo/backend ag_prod-db-test python /repo/scripts/eval_pipeline.py
"""

from __future__ import annotations

import asyncio
import json
import os
import statistics
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

from app.guardrails.alerts import AlertMonitor  # noqa: E402
from app.guardrails.input_guardrail import InputGuardrailEngine, InputMessage  # noqa: E402
from app.guardrails.judge import SafetyJudge  # noqa: E402
from app.guardrails.output_guardrail import OutputGuardrailEngine  # noqa: E402
from app.guardrails.pipeline import GuardrailPipeline, GuardrailUnavailable  # noqa: E402
from app.guardrails.ruleset import default_snapshot  # noqa: E402
from app.services.ollama import OllamaClient  # noqa: E402

DATASETS = Path(__file__).resolve().parents[1] / "datasets"


def rows_v1():
    for name, label in (("heldout_attacks_v1.jsonl", "attack"), ("heldout_benign_v1.jsonl", "benign")):
        for line in (DATASETS / name).read_text(encoding="utf-8").splitlines():
            if line.strip():
                row = json.loads(line)
                yield {"set": "v1", "target": "input", "label": label, "category": row.get("category", "benign"),
                       "text": row["text"]}  # fmt: skip


def rows_v2():
    for line in (DATASETS / "heldout_v2.jsonl").read_text(encoding="utf-8").splitlines():
        if line.strip():
            yield {"set": "v2", **json.loads(line)}


async def main() -> int:
    client = OllamaClient(os.environ.get("OLLAMA_BASE_URL", "http://10.10.70.65:11434"), "qwen3:8b", queue_wait_s=300)
    snapshot = default_snapshot()
    rules_only = GuardrailPipeline(InputGuardrailEngine(), OutputGuardrailEngine(), None, AlertMonitor(None, b"k" * 32))
    full = GuardrailPipeline(
        InputGuardrailEngine(), OutputGuardrailEngine(), SafetyJudge(client, timeout_s=60), AlertMonitor(None, b"k" * 32)
    )
    await client.chat([{"role": "user", "content": "hi"}], timeout_s=120, num_predict=1)  # warm-up / model load

    results = []
    for row in [*rows_v1(), *rows_v2()]:
        record = dict(row)
        for name, p in (("rules", rules_only), ("full", full)):
            try:
                if row["target"] == "input":
                    res, timing = await p.check_input([InputMessage("user", row["text"])], None, snapshot)
                    blocked = not res.allowed
                else:
                    res, timing = await p.check_output(row["text"], snapshot)
                    blocked = res.blocked
                record[name] = blocked
                if name == "full":
                    record["judge_ms"] = timing.judge_ms if timing.judge_calls else None
            except GuardrailUnavailable:
                record[name] = None
        results.append(record)
    await client.close()

    def rate(rows, key, label):
        sel = [r for r in rows if r["label"] == label]
        hits = sum(1 for r in sel if r[key])
        return f"{hits}/{len(sel)} ({hits / len(sel):.1%})" if sel else "-"

    for set_name in ("v1", "v2"):
        for target in ("input", "output"):
            sel = [r for r in results if r["set"] == set_name and r["target"] == target]
            if not sel:
                continue
            print(f"[{set_name} {target}] attacks blocked: rules {rate(sel, 'rules', 'attack')} | "
                  f"rules+judge {rate(sel, 'full', 'attack')}")  # fmt: skip
            print(f"[{set_name} {target}] benign blocked (FP): rules {rate(sel, 'rules', 'benign')} | "
                  f"rules+judge {rate(sel, 'full', 'benign')}")  # fmt: skip
    manip = [r for r in results if r.get("category") == "judge_manipulation"]
    print(f"judge-manipulation attempts blocked: {sum(1 for r in manip if r['full'])}/{len(manip)}")
    lat = [r["judge_ms"] for r in results if r.get("judge_ms")]
    q = statistics.quantiles(lat, n=100)
    print(f"judge latency ms: p50 {statistics.median(lat):.0f}  p95 {q[94]:.0f}  max {max(lat):.0f}  calls {len(lat)}")
    print(f"judge unavailable: {sum(1 for r in results if r['full'] is None)}")
    if "--show" in sys.argv:
        for r in results:
            if (r["label"] == "attack" and not r["full"]) or (r["label"] == "benign" and r["full"]):
                kind = "MISS" if r["label"] == "attack" else "FP"
                print(f"{kind} [{r['set']} {r['target']} {r['category']}] {r['text'][:110]}")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
