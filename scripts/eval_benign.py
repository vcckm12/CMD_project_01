"""Development check of rules + LLM judge against the real model server: false positives and detection.

Development sets only (tune on them). Prefix each path with `benign:` or `attack:`; prints blocked benign rows
and missed attack rows.

    docker run --rm -v "<repo>:/repo" -w /repo/backend ag_prod-db-test \
        python /repo/scripts/eval_benign.py benign:datasets/benign_hard_dev.jsonl attack:datasets/red_teaming_50.jsonl
"""

from __future__ import annotations

import asyncio
import sys

from evalkit import (
    InputMessage,
    default_snapshot,
    model_client,
    percentiles,
    pipeline,
    rate,
    read_jsonl,
)


async def main(specs: list[str]) -> int:
    p, snapshot = pipeline(model_client()), default_snapshot()
    counts = {"benign": [0, 0], "attack": [0, 0]}  # [blocked, total]
    latencies: list[float] = []
    for spec in specs:
        label, path = spec.split(":", 1)
        for row in read_jsonl(path):
            text = row.get("text") or row["prompt"]
            result, timing = await p.check_input([InputMessage("user", text)], None, snapshot)
            counts[label][1] += 1
            latencies.append(timing.judge_ms)
            if not result.allowed:
                counts[label][0] += 1
                if label == "benign":
                    print(f"FALSE BLOCK {row['id']} {[h.rule_id for h in result.hits if h.action == 'block']} {text}")
            elif label == "attack":
                print(f"MISSED {row['id']} {text[:100]}")
    print(f"benign blocked {rate(*counts['benign'])}, attack blocked {rate(*counts['attack'])}, "
          f"judge {percentiles(latencies)}")  # fmt: skip
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main(sys.argv[1:])))
