"""AUDIT-04 PDF (DES-004 SCR-O05): fixed layout, masked summaries only, KST display, units stated.

The Korean font is embedded so the file renders the same everywhere. No user message text exists in
the audit data, so none can reach the report.
"""

from __future__ import annotations

import io
import uuid
from datetime import UTC, datetime
from pathlib import Path
from xml.sax.saxutils import escape
from zoneinfo import ZoneInfo

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

KST = ZoneInfo("Asia/Seoul")
FONT = "NanumGothic"
FONT_PATHS = (Path("/usr/share/fonts/truetype/nanum/NanumGothic.ttf"),)


def _font() -> str:
    if FONT not in pdfmetrics.getRegisteredFontNames():
        for path in FONT_PATHS:
            if path.exists():
                pdfmetrics.registerFont(TTFont(FONT, str(path)))
                return FONT
        return "Helvetica"  # tests without the font package still produce a valid PDF
    return FONT


def _kst(value: str | datetime) -> str:
    dt = datetime.fromisoformat(value) if isinstance(value, str) else value
    return dt.astimezone(KST).strftime("%Y-%m-%d %H:%M:%S")


def build_report_pdf(
    summary: dict, rows: list[dict], *, session_id: uuid.UUID | None, author_id: uuid.UUID, total_events: int
) -> bytes:
    font = _font()
    body = ParagraphStyle("body", fontName=font, fontSize=9, leading=12)
    title = ParagraphStyle("title", fontName=font, fontSize=16, leading=20, spaceAfter=6)
    head = ParagraphStyle("head", fontName=font, fontSize=11, leading=14, spaceBefore=10, spaceAfter=4)

    def table(data, widths):
        t = Table(data, colWidths=widths, repeatRows=1)
        t.setStyle(TableStyle([
            ("FONTNAME", (0, 0), (-1, -1), font), ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e2e8f0")),
            ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#94a3b8")), ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ]))  # fmt: skip
        return t

    def p(text) -> Paragraph:
        return Paragraph(escape(str(text)), body)  # Paragraph parses markup: always escape

    story = [
        Paragraph("AI 보안 가드레일 세션 보고서", title),
        p(f"기간: {_kst(summary['from'])} ~ {_kst(summary['to'])} (Asia/Seoul)"),
        p(f"세션: {session_id or '전체'} · 대상 이벤트 {total_events}건 · 생성자 내부 ID {author_id}"),
        p(
            f"기준 시각(as_of): {_kst(summary['as_of'])} · 적재 지연 {summary['ingestion_lag_seconds']}초 "
            "(아직 적재되지 않은 이벤트는 포함되지 않음)"
        ),
        p(f"생성: {_kst(datetime.now(UTC))}"),
        Paragraph("처리 결과 (단위: 이벤트 수)", head),
        table([["상태", "건수"]] + [[k, str(v)] for k, v in summary["status_counts"].items()], [60 * mm, 30 * mm]),
        Paragraph("OWASP LLM Top 10 2025 분류 (단위: 룰 적중 수, 이벤트 수와 다름)", head),
        table(
            [["분류", "적중 수"]] + [[k, str(v)] for k, v in summary["category_counts"].items()]
            or [["분류", "적중 수"], ["-", "0"]],
            [60 * mm, 30 * mm],
        ),  # fmt: skip
        Paragraph("지연·룰 버전", head),
        p(
            f"서버 처리 시간 P95: {summary['latency_p95_ms'] if summary['latency_p95_ms'] is not None else '-'} ms "
            "(모델 생성 시간 포함, 가드레일 검사 시간만이 아님)"
        ),
        p(
            "사용된 룰셋: "
            + (", ".join(f"{v['label'] or '?'} ({v['id'][:8]})" for v in summary["ruleset_versions"]) or "-")
        ),
        Paragraph("이벤트 요약 (최근 500건, 마스킹된 요약만 표시)", head),
        table(
            [["시각(KST)", "출처", "상태", "단계", "ms", "요약"]]
            + [
                [
                    _kst(r["occurred_at"]),
                    r["source"],
                    r["status"],
                    r["stage"] or "",
                    f"{float(r['total_ms']):.0f}",
                    p(r["summary_redacted"]),
                ]
                for r in rows
            ],
            [32 * mm, 18 * mm, 24 * mm, 16 * mm, 14 * mm, 76 * mm],
        ),  # fmt: skip
        Spacer(1, 6 * mm),
        p("이 보고서의 차단 비율은 운영 이벤트 기준이며, 정답 라벨이 있는 시험셋의 탐지율과 다릅니다."),
    ]
    buffer = io.BytesIO()
    SimpleDocTemplate(buffer, pagesize=A4, leftMargin=12 * mm, rightMargin=12 * mm, title="Security report").build(
        story
    )
    return buffer.getvalue()
