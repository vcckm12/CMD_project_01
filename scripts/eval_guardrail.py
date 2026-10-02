"""Measure the input guardrail on labelled JSONL sets (DES-007 §3).

These legacy sets were visible while writing the rules, so results are a DEVELOPMENT measurement,
not the independent T-24 result required by REQ-N02.

Usage (from the repo root):
    docker run --rm -v "<repo>:/repo" -w /repo/backend ag_prod-db-test python /repo/scripts/eval_guardrail.py
"""

from __future__ import annotations

import json
import statistics
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

from app.guardrails.input_guardrail import InputGuardrailEngine, InputMessage  # noqa: E402
from app.guardrails.ruleset import default_snapshot  # noqa: E402

DATASETS = Path(__file__).resolve().parents[1] / "datasets"


def load(name: str, text_key: str, label_key: str | None) -> list[tuple[str, str]]:
    rows = []
    for line in (DATASETS / name).read_text(encoding="utf-8").splitlines():
        if line.strip():
            row = json.loads(line)
            rows.append((row.get(label_key, "BENIGN") if label_key else "BENIGN", row[text_key]))
    return rows


def main() -> int:
    engine = InputGuardrailEngine()
    snapshot = default_snapshot()
    for _ in range(100):  # warm-up (DES-007 §3)
        engine.inspect([InputMessage("user", "무선 마우스 추천해줘")], None, snapshot)

    if "--heldout" in sys.argv:
        # Held-out v1: written after the rules were tuned and never used for tuning.
        attacks = load("heldout_attacks_v1.jsonl", "text", "category")
        benign_sets = {"heldout(benign)": load("heldout_benign_v1.jsonl", "text", None)}
    else:
        attacks = load("attack_payloads_100.jsonl", "text", "category") + load(
            "red_teaming_50.jsonl", "prompt", "category"
        )
        benign_sets = {
            "benign(simple)": load("benign_testset_100.jsonl", "text", None),
            "benign(hard)": load("benign_hard_dev.jsonl", "text", None),
        }
    per_category: dict[str, list[int]] = defaultdict(lambda: [0, 0])
    misses: dict[str, list[str]] = defaultdict(list)
    latencies = []
    tp = fn = 0
    for category, text in attacks:
        result = engine.inspect([InputMessage("user", text)], None, snapshot)
        latencies.append(result.input_ms)
        per_category[category][1] += 1
        if not result.allowed:
            tp += 1
            per_category[category][0] += 1
        else:
            fn += 1
            misses[category].append(text)
    false_positives = []
    benign_counts = {}
    for name, rows in benign_sets.items():
        fp = 0
        for _, text in rows:
            result = engine.inspect([InputMessage("user", text)], None, snapshot)
            latencies.append(result.input_ms)
            if not result.allowed:
                fp += 1
                false_positives.append((name, text, [h.rule_id for h in result.hits]))
        benign_counts[name] = (fp, len(rows))

    q = statistics.quantiles(latencies, n=100)
    print(f"attacks {tp + fn}  detected {tp}  TPR {tp / (tp + fn):.1%}")
    for name, (fp, total) in benign_counts.items():
        print(f"{name:<15} {total}  blocked {fp}  FPR {fp / total:.1%}")
    print(f"input_ms p50 {statistics.median(latencies):.2f}  p95 {q[94]:.2f}  max {max(latencies):.2f}")
    print("\nper category (detected/total):")
    for category, (hit, total) in sorted(per_category.items()):
        print(f"  {category:<22} {hit:>3}/{total:<3}")
    if "--show-misses" in sys.argv:
        for category, texts in sorted(misses.items()):
            print(f"\nMISSED {category}:")
            for t in texts:
                print("   ", t[:140])
        for name, text, rules in false_positives:
            print(f"\nFALSE POSITIVE [{name}]:", text[:140], rules)
    return 0


if __name__ == "__main__":
    sys.exit(main())
