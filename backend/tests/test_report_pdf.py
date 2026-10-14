"""AUDIT-04 PDF layout: renders with full, empty and markup-laden data (no DB needed)."""

import re
import uuid
from datetime import UTC, datetime

from app.audit.report import build_report_pdf

NOW = datetime(2026, 10, 14, 3, 0, tzinfo=UTC)
STATUSES = ("success", "blocked", "masked", "confirmation_required", "error")


def summary(counts=None, **extra):
    counts = counts or dict.fromkeys(STATUSES, 0)
    return {
        "from": "2026-10-13T00:00:00+00:00", "to": NOW.isoformat(), "total": sum(counts.values()),
        "status_counts": counts, "category_counts": {}, "latency_p95_ms": None,
        "layer_overlap": {s: {"both": 0, "rules_only": 0, "judge_only": 0, "rules_judge_error": 0}
                          for s in ("input", "tool", "output")},
        "ruleset_versions": [], "as_of": NOW.isoformat(), "ingestion_lag_seconds": 0.0, **extra,
    }  # fmt: skip


def row(status="blocked", text="차단(input): RULE_IGNORE_INSTRUCTIONS"):
    return {"occurred_at": NOW, "source": "web", "status": status, "stage": "input", "total_ms": 12.3,
            "summary_redacted": text}  # fmt: skip


def build(s, rows, total):
    return build_report_pdf(s, rows, session_id=None, author_id=uuid.uuid4(), total_events=total)


def test_full_report_is_a_pdf():
    counts = {"success": 10, "blocked": 3, "masked": 1, "confirmation_required": 2, "error": 1}
    s = summary(counts, category_counts={"LLM01:2025": 4, "LLM02:2025": 1}, latency_p95_ms=1234.5,
                ruleset_versions=[{"id": str(uuid.uuid4()), "label": "lab-v1"}])  # fmt: skip
    s["layer_overlap"]["tool"]["judge_only"] = 1
    assert build(s, [row(st) for st in STATUSES], 17).startswith(b"%PDF-")


def test_empty_period_renders_without_division_errors():
    assert build(summary(), [], 0).startswith(b"%PDF-")


def test_markup_in_data_is_text_not_layout():
    s = summary(ruleset_versions=[{"id": "<para>", "label": "<b>x</b><font color=red>y"}])
    rows = [row(text="<b>x</b><font color=red>y</font><para>")]
    assert build(s, rows, 1).startswith(b"%PDF-")


def test_long_event_list_spans_pages():
    pdf = build(summary({**dict.fromkeys(STATUSES, 0), "success": 500}), [row("success")] * 500, 500)
    assert len(re.findall(rb"/Type\s*/Page(?!s)", pdf)) >= 2
