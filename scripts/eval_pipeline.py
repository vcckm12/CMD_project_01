"""Measure rules + LLM judge on the held-out sets against the real model server (DES-007 §3, D-25).

One pass per row: both layers always run (D-36), so the rules-only and rules+judge results come from the
same check. Each held-out set is meant to be measured once; do not tune prompts or rules against it.

    docker run --rm -v "<repo>:/repo" -w /repo/backend ag_prod-db-test python /repo/scripts/eval_pipeline.py [--show]
"""

from __future__ import annotations

import asyncio
import sys

from evalkit import (
    GuardrailUnavailable,
    InputMessage,
    default_snapshot,
    model_client,
    percentiles,
    pipeline,
    rate,
    read_jsonl,
)


def rows() -> list[dict]:
    v1 = [{"set": "v1", "target": "input", "label": label, "category": r.get("category", "benign"), "text": r["text"]}
          for name, label in (("heldout_attacks_v1.jsonl", "attack"), ("heldout_benign_v1.jsonl", "benign"))
          for r in read_jsonl(name)]  # fmt: skip
    return v1 + [{"set": "v2", **r} for r in read_jsonl("heldout_v2.jsonl")]


async def main() -> int:
    client = model_client()
    p, snapshot = pipeline(client), default_snapshot()
    await client.chat([{"role": "user", "content": "hi"}], timeout_s=120, num_predict=1)  # warm-up / model load
    results = []
    for row in rows():
        try:
            if row["target"] == "input":
                res, timing = await p.check_input([InputMessage("user", row["text"])], None, snapshot)
                full = not res.allowed
            else:
                res, timing = await p.check_output(row["text"], snapshot)
                full = res.blocked
            stage = row["target"]
            rules = timing.layers.get(f"{stage}_rules", ("pass", 0))[0] == "block"
            results.append(
                {
                    **row,
                    "rules": rules,
                    "full": full,
                    "judge_ms": timing.judge_ms or None,
                }
            )
        except GuardrailUnavailable:
            results.append({**row, "rules": None, "full": None, "judge_ms": None})
    await client.close()

    def blocked(sel: list[dict], key: str, label: str) -> str:
        chosen = [r for r in sel if r["label"] == label]
        return rate(sum(bool(r[key]) for r in chosen), len(chosen))

    for set_name in ("v1", "v2"):
        for target in ("input", "output"):
            sel = [r for r in results if r["set"] == set_name and r["target"] == target]
            if sel:
                print(f"[{set_name} {target}] attacks blocked: rules {blocked(sel, 'rules', 'attack')} | "
                      f"rules+judge {blocked(sel, 'full', 'attack')}")  # fmt: skip
                print(f"[{set_name} {target}] benign blocked (FP): rules {blocked(sel, 'rules', 'benign')} | "
                      f"rules+judge {blocked(sel, 'full', 'benign')}")  # fmt: skip
    manip = [r for r in results if r.get("category") == "judge_manipulation"]
    print(f"judge-manipulation attempts blocked: {sum(bool(r['full']) for r in manip)}/{len(manip)}")
    print("judge latency:", percentiles([r["judge_ms"] for r in results if r["judge_ms"]]))
    print(f"judge unavailable: {sum(r['full'] is None for r in results)}")
    if "--show" in sys.argv:
        for r in results:
            if (r["label"] == "attack") != bool(r["full"]):
                kind = "MISS" if r["label"] == "attack" else "FP"
                print(f"{kind} [{r['set']} {r['target']} {r['category']}] {r['text'][:110]}")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
