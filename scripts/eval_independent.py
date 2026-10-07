"""One-shot measurement of the independent test set (datasets/independent/README.md) on the real model.

Runs every row through the input guardrail exactly as the chat service does (client context as a system
message, then the user text) with both layers recorded (D-36), so one pass gives rules-only, judge-only and
combined detection. Refuses to measure a set that fails validation or was already measured (same SHA-256),
because tuning against it would end its independence.

Usage (repo root, Ollama reachable):
    docker run --rm -v "<repo>:/repo" -w /repo/backend ag_prod-db-test \
        python /repo/scripts/eval_independent.py datasets/independent
"""

from __future__ import annotations

import argparse
import asyncio
import csv
import os
import statistics
import sys
import time
from collections import defaultdict
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))
sys.path.insert(0, str(ROOT / "scripts"))

from app.config import Settings  # noqa: E402
from app.guardrails.alerts import AlertMonitor  # noqa: E402
from app.guardrails.input_guardrail import InputGuardrailEngine, InputMessage  # noqa: E402
from app.guardrails.judge import SafetyJudge  # noqa: E402
from app.guardrails.output_guardrail import OutputGuardrailEngine  # noqa: E402
from app.guardrails.pipeline import GuardrailPipeline, GuardrailUnavailable  # noqa: E402
from app.guardrails.ruleset import default_snapshot  # noqa: E402
from app.guardrails.types import GuardrailTimeout  # noqa: E402
from app.services.ollama import InferenceBusy, OllamaClient  # noqa: E402
from validate_testset import QUOTAS, validate  # noqa: E402


def pct(n: int, d: int) -> str:
    return f"{n / d * 100:.1f}% ({n}/{d})" if d else "—"


async def measure(rows: list[dict]) -> list[dict]:
    client = OllamaClient(os.environ.get("OLLAMA_BASE_URL", "http://10.10.70.65:11434"),
                          os.environ.get("OLLAMA_MODEL", "qwen3:8b"), queue_wait_s=300)  # fmt: skip
    judge = SafetyJudge(
        client, timeout_s=Settings.model_fields["judge_timeout_seconds"].default
    )
    pipeline = GuardrailPipeline(
        InputGuardrailEngine(),
        OutputGuardrailEngine(),
        judge,
        AlertMonitor(None, b"k" * 32),
    )
    snapshot = default_snapshot()
    out = []
    for i, r in enumerate(rows, 1):
        messages = (
            [InputMessage("system", r["context"])] if r.get("context") else []
        ) + [InputMessage("user", r["text"])]
        started = time.perf_counter()
        result = {"id": r["id"], "label": r["label"], "category": r["category"],
                  "technique": r.get("technique", ""), "lang": r["lang"]}  # fmt: skip
        for attempt in range(2):
            try:
                inspection, timing = await pipeline.check_input(
                    messages, None, snapshot
                )
                layers = timing.layers
                result |= {
                    "rules": layers.get("input_rules", ("pass", 0))[0],
                    "judge": layers.get("input_judge", ("skip", 0))[0],
                    "final": "block" if not inspection.allowed else "pass",
                    "judge_ms": round(timing.judge_ms),
                    "rule_ids": " ".join(
                        sorted(
                            {h.rule_id for h in inspection.hits if h.action == "block"}
                        )
                    ),
                }
                break
            except (GuardrailUnavailable, GuardrailTimeout, InferenceBusy) as exc:
                result |= {
                    "rules": "?",
                    "judge": "error",
                    "final": "error",
                    "judge_ms": 0,
                    "rule_ids": type(exc).__name__,
                }
        result["total_ms"] = round((time.perf_counter() - started) * 1000)
        out.append(result)
        if i % 25 == 0:
            print(f"  {i}/{len(rows)}", flush=True)
    return out


def git_commit() -> str:
    """HEAD commit read from .git (the measurement container has no git binary)."""
    git = ROOT / ".git"
    try:
        head = (git / "HEAD").read_text().strip()
        if not head.startswith("ref: "):
            return head[:7]
        ref = head[5:]
        if (git / ref).exists():
            return (git / ref).read_text().strip()[:7]
        for line in (git / "packed-refs").read_text().splitlines():
            if line.endswith(" " + ref):
                return line[:7]
    except OSError:
        pass
    return "?"


def report(results: list[dict], digest: str, started: datetime) -> str:
    attacks = [r for r in results if r["label"] == "attack"]
    benign = [r for r in results if r["label"] == "benign"]
    errors = [r for r in results if r["final"] == "error"]

    def rate(rows: list[dict], key: str) -> str:
        return pct(sum(r[key] == "block" for r in rows), len(rows))

    lines = [
        "# 독립 시험셋 측정 결과",
        "",
        f"- 측정 시각(UTC): {started:%Y-%m-%d %H:%M} · 코드 {git_commit()} · 시험셋 sha256 `{digest}`",
        f"- 모델 {os.environ.get('OLLAMA_MODEL', 'qwen3:8b')} · AI 판별 제한 시간 "
        f"{Settings.model_fields['judge_timeout_seconds'].default}초 · 규칙 출하 기본 룰셋 · 입력 단계만 측정",
        f"- 판별 실패(재시도 후): {len(errors)}건 — 아래 비율에서는 차단되지 않은 것으로 셈",
        "",
        "## 요약",
        "",
        "| | 규칙만 | AI 판별만 | 규칙 + AI (실제 서비스) |",
        "|---|---|---|---|",
        f"| 공격 탐지율 | {rate(attacks, 'rules')} | {rate(attacks, 'judge')} | **{rate(attacks, 'final')}** |",
        f"| 정상 오탐률 | {rate(benign, 'rules')} | {rate(benign, 'judge')} | **{rate(benign, 'final')}** |",
        "",
        "## 공격 분류별 (규칙 + AI)",
        "",
        "| category | 규칙만 | AI만 | 규칙 + AI |",
        "|---|---|---|---|",
    ]
    for category in QUOTAS["attack"]:
        rows = [r for r in attacks if r["category"] == category]
        lines.append(
            f"| {category} | {rate(rows, 'rules')} | {rate(rows, 'judge')} | {rate(rows, 'final')} |"
        )
    lines += [
        "",
        "## 공격 기법별 (규칙 + AI)",
        "",
        "| technique | 규칙 + AI |",
        "|---|---|",
    ]
    by_tech = defaultdict(list)
    for r in attacks:
        by_tech[r["technique"]].append(r)
    for tech, rows in sorted(by_tech.items()):
        lines.append(f"| {tech} | {rate(rows, 'final')} |")
    lines += [
        "",
        "## 정상 분류별 오탐 (규칙 + AI)",
        "",
        "| category | 오탐률 |",
        "|---|---|",
    ]
    for category in QUOTAS["benign"]:
        rows = [r for r in benign if r["category"] == category]
        lines.append(f"| {category} | {rate(rows, 'final')} |")
    judged = [r["judge_ms"] for r in results if r["judge_ms"]]
    if judged:
        q = statistics.quantiles(judged, n=20)
        lines += [
            "",
            f"AI 판별 시간: p50 {statistics.median(judged):.0f}ms · p95 {q[18]:.0f}ms (CPU 추론)",
        ]
    missed = [r for r in attacks if r["final"] != "block"]
    false_blocks = [r for r in benign if r["final"] == "block"]
    lines += ["", f"놓친 공격 id: {', '.join(r['id'] for r in missed) or '없음'}",
              f"오탐 정상 id: {', '.join(r['id'] for r in false_blocks) or '없음'}"]  # fmt: skip
    lines += [
        "",
        "이 시험셋으로 규칙·판별 기준을 고치면 다음 측정에는 새 독립 시험셋이 필요하다.",
    ]
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("folder")
    parser.add_argument(
        "--allow-partial",
        action="store_true",
        help="dry run of this script on an incomplete set",
    )
    parser.add_argument(
        "--force", action="store_true", help="measure a set that was already measured"
    )
    args = parser.parse_args()
    folder = ROOT / args.folder
    errors, _, counts, digest, rows = validate(folder)
    complete = not errors and all(
        counts[(lbl, c)] >= n for lbl, q in QUOTAS.items() for c, n in q.items()
    )
    if not complete and not args.allow_partial:
        print(
            "시험셋이 검사를 통과하지 않았습니다: python scripts/validate_testset.py "
            + args.folder
        )
        return 1
    results_dir = folder / "results"
    results_dir.mkdir(exist_ok=True)
    if any(digest[:16] in p.name for p in results_dir.iterdir()) and not args.force:
        print(
            f"이미 측정한 시험셋입니다(sha256 {digest[:16]}). 독립 시험셋은 한 번만 측정합니다."
        )
        return 1
    started = datetime.now(UTC)
    print(f"측정 시작: {len(rows)}건 (실모델, 수십 분 걸릴 수 있음)", flush=True)
    results = asyncio.run(measure(rows))
    stem = f"{started:%Y%m%d-%H%M}_{digest[:16]}" + ("_partial" if not complete else "")
    (results_dir / f"{stem}.md").write_text(
        report(results, digest, started), encoding="utf-8"
    )
    with (results_dir / f"{stem}.csv").open("w", encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(results[0]))
        writer.writeheader()
        writer.writerows(results)
    print(f"저장: {results_dir / stem}.md / .csv")
    return 0


if __name__ == "__main__":
    sys.exit(main())
