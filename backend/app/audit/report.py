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

from reportlab.graphics.charts.piecharts import Pie
from reportlab.graphics.shapes import Circle, Drawing, Rect, String
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import HRFlowable, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

KST = ZoneInfo("Asia/Seoul")
FONT = "NanumGothic"
FONT_BOLD = "NanumGothicBold"
FONT_PATHS = (
    Path("/usr/share/fonts/truetype/nanum/NanumGothic.ttf"),
    Path("/usr/share/fonts/truetype/nanum/NanumGothicBold.ttf"),
)

STATUS_MAP = {
    "success": ("정상 (Success)", "#047857"),
    "blocked": ("차단 (Blocked)", "#b91c1c"),
    "masked": ("정화 (Masked)", "#b45309"),
    "confirmation_required": ("승인 대기 (Pending)", "#1d4ed8"),
    "error": ("오류 (Error)", "#64748b"),
}

OWASP_NAMES = {
    "LLM01:2025": "LLM01 프롬프트 인젝션 (Prompt Injection)",
    "LLM02:2025": "LLM02 민감정보 노출 (Sensitive Info Disclosure)",
    "LLM05:2025": "LLM05 부적절한 출력 (Improper Output Handling)",
    "LLM06:2025": "LLM06 과도한 권한 (Excessive Agency)",
    "LLM07:2025": "LLM07 시스템 프롬프트 유출 (System Prompt Leakage)",
    "LLM10:2025": "LLM10 무제한 자원 소비 (Unbounded Consumption)",
}

STAGE_NAMES = {
    "input": "입력 (Input)",
    "tool": "도구 결과 (Tool)",
    "output": "출력 (Output)",
}


def _fonts() -> tuple[str, str]:
    reg_ok = FONT in pdfmetrics.getRegisteredFontNames()
    bold_ok = FONT_BOLD in pdfmetrics.getRegisteredFontNames()
    if not reg_ok and FONT_PATHS[0].exists():
        pdfmetrics.registerFont(TTFont(FONT, str(FONT_PATHS[0])))
        reg_ok = True
    if not bold_ok and FONT_PATHS[1].exists():
        pdfmetrics.registerFont(TTFont(FONT_BOLD, str(FONT_PATHS[1])))
        bold_ok = True
    font_reg = FONT if reg_ok else "Helvetica"
    font_bold = FONT_BOLD if bold_ok else (FONT if reg_ok else "Helvetica-Bold")
    return font_reg, font_bold


def _kst(value: str | datetime) -> str:
    dt = datetime.fromisoformat(value) if isinstance(value, str) else value
    return dt.astimezone(KST).strftime("%Y-%m-%d %H:%M:%S")


def _status_donut(
    counts: dict[str, int], total: int, font: str, font_bold: str, width: float = 54 * mm, height: float = 44 * mm
) -> Drawing:
    d = Drawing(width, height)
    cx, cy = width / 2.0, height / 2.0
    r = 18.0 * mm
    inner_r = 10.5 * mm

    palette = [
        ("success", colors.HexColor("#047857")),
        ("blocked", colors.HexColor("#b91c1c")),
        ("masked", colors.HexColor("#b45309")),
        ("confirmation_required", colors.HexColor("#1d4ed8")),
        ("error", colors.HexColor("#64748b")),
    ]
    active_items = []
    for k, col in palette:
        cnt = counts.get(k, 0)
        if cnt > 0:
            active_items.append((cnt, col))

    if not active_items or total <= 0:
        d.add(
            Circle(
                cx,
                cy,
                r,
                fillColor=colors.HexColor("#f1f5f9"),
                strokeColor=colors.HexColor("#cbd5e1"),
                strokeWidth=0.8,
            )
        )
        d.add(
            Circle(
                cx,
                cy,
                inner_r,
                fillColor=colors.white,
                strokeColor=colors.HexColor("#f1f5f9"),
                strokeWidth=0.5,
            )
        )
        d.add(
            String(
                cx,
                cy + 2,
                "0건",
                textAnchor="middle",
                fontName=font_bold,
                fontSize=10,
                fillColor=colors.HexColor("#64748b"),
            )
        )
        d.add(
            String(
                cx,
                cy - 8,
                "데이터 없음",
                textAnchor="middle",
                fontName=font,
                fontSize=6.5,
                fillColor=colors.HexColor("#94a3b8"),
            )
        )
        return d

    p = Pie()
    p.x = cx - r
    p.y = cy - r
    p.width = r * 2
    p.height = r * 2
    p.data = [item[0] for item in active_items]
    p.sideLabels = 0
    p.labels = None
    p.slices.strokeColor = colors.white
    p.slices.strokeWidth = 1.2
    for idx, (_, col) in enumerate(active_items):
        p.slices[idx].fillColor = col
    d.add(p)

    d.add(
        Circle(
            cx,
            cy,
            inner_r,
            fillColor=colors.white,
            strokeColor=colors.HexColor("#f8fafc"),
            strokeWidth=0.5,
        )
    )
    d.add(
        String(
            cx,
            cy + 2,
            f"{total:,}건",
            textAnchor="middle",
            fontName=font_bold,
            fontSize=10,
            fillColor=colors.HexColor("#0f172a"),
        )
    )
    d.add(
        String(
            cx,
            cy - 8,
            "총 이벤트",
            textAnchor="middle",
            fontName=font,
            fontSize=6.5,
            fillColor=colors.HexColor("#64748b"),
        )
    )
    return d


def _status_bar(counts: dict[str, int], total: int, width: float = 516, height: float = 14) -> Drawing:
    d = Drawing(width, height + 4)
    d.add(
        Rect(
            0,
            2,
            width,
            height,
            rx=3,
            ry=3,
            fillColor=colors.HexColor("#f1f5f9"),
            strokeColor=colors.HexColor("#e2e8f0"),
            strokeWidth=0.5,
        )
    )
    if total <= 0:
        return d
    palette = {
        "success": colors.HexColor("#047857"),
        "blocked": colors.HexColor("#b91c1c"),
        "masked": colors.HexColor("#b45309"),
        "confirmation_required": colors.HexColor("#1d4ed8"),
        "error": colors.HexColor("#64748b"),
    }
    x = 0.0
    for k in ("success", "blocked", "masked", "confirmation_required", "error"):
        cnt = counts.get(k, 0)
        if cnt > 0:
            w = (cnt / total) * width
            d.add(
                Rect(
                    x,
                    2,
                    w,
                    height,
                    rx=1,
                    ry=1,
                    fillColor=palette.get(k, colors.HexColor("#64748b")),
                    strokeColor=None,
                )
            )
            x += w
    return d


def build_report_pdf(
    summary: dict, rows: list[dict], *, session_id: uuid.UUID | None, author_id: uuid.UUID, total_events: int
) -> bytes:
    font, font_bold = _fonts()

    tag_style = ParagraphStyle(
        "tag", fontName=font_bold, fontSize=8, leading=10, textColor=colors.HexColor("#c5a880")
    )
    title_style = ParagraphStyle(
        "title",
        fontName=font_bold,
        fontSize=16,
        leading=20,
        textColor=colors.HexColor("#0f172a"),
        spaceAfter=4,
    )
    head_style = ParagraphStyle(
        "head",
        fontName=font_bold,
        fontSize=10,
        leading=13,
        textColor=colors.HexColor("#0f172a"),
        spaceBefore=10,
        spaceAfter=4,
    )
    body = ParagraphStyle("body", fontName=font, fontSize=7.5, leading=10.5, textColor=colors.HexColor("#1e293b"))
    body_bold = ParagraphStyle(
        "body_bold", fontName=font_bold, fontSize=7.5, leading=10.5, textColor=colors.HexColor("#0f172a")
    )
    body_right = ParagraphStyle(
        "body_right", fontName=font, fontSize=7.5, leading=10.5, textColor=colors.HexColor("#1e293b"), alignment=2
    )
    body_center = ParagraphStyle(
        "body_center", fontName=font, fontSize=7.5, leading=10.5, textColor=colors.HexColor("#1e293b"), alignment=1
    )
    th_style = ParagraphStyle(
        "th", fontName=font_bold, fontSize=7.5, leading=10.5, textColor=colors.HexColor("#ffffff"), alignment=1
    )
    kpi_num_style = ParagraphStyle("kpi_num", fontName=font_bold, fontSize=13, leading=15, alignment=1)
    kpi_lbl_style = ParagraphStyle(
        "kpi_lbl", fontName=font, fontSize=7.5, leading=9.5, textColor=colors.HexColor("#64748b"), alignment=1
    )

    story = [
        Paragraph("GUARDRAIL FASHION · AI SECURITY OPERATIONS", tag_style),
        Paragraph("AI 보안 가드레일 감사 및 세션 보고서", title_style),
        HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#0f172a"), spaceAfter=8, spaceBefore=0),
    ]

    # 1. KPI Summary Cards (4 columns)
    kpi_data = [
        [
            Paragraph(
                f"{total_events:,}건",
                ParagraphStyle("k1", parent=kpi_num_style, textColor=colors.HexColor("#0f172a")),
            ),
            Paragraph(
                f"{summary['status_counts'].get('success', 0):,}건",
                ParagraphStyle("k2", parent=kpi_num_style, textColor=colors.HexColor("#047857")),
            ),
            Paragraph(
                f"{summary['status_counts'].get('blocked', 0):,}건",
                ParagraphStyle("k3", parent=kpi_num_style, textColor=colors.HexColor("#b91c1c")),
            ),
            Paragraph(
                f"{summary['latency_p95_ms']:.0f} ms" if summary.get("latency_p95_ms") is not None else "-",
                ParagraphStyle("k4", parent=kpi_num_style, textColor=colors.HexColor("#0f172a")),
            ),
        ],
        [
            Paragraph("총 요청 이벤트", kpi_lbl_style),
            Paragraph("정상 처리 (Success)", kpi_lbl_style),
            Paragraph("보안 차단 (Blocked)", kpi_lbl_style),
            Paragraph("서버 지연 (P95 Latency)", kpi_lbl_style),
        ],
    ]
    kpi_table = Table(kpi_data, colWidths=[45.5 * mm] * 4)
    kpi_table.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
            ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ])
    )
    story.append(kpi_table)
    story.append(Spacer(1, 4 * mm))

    # 2. Metadata Table (2-column layout)
    meta_rows = [
        [
            Paragraph("<b>기간 (KST)</b>", body),
            Paragraph(f"{_kst(summary['from'])} ~ {_kst(summary['to'])}", body),
            Paragraph("<b>세션 식별자</b>", body),
            Paragraph(str(session_id or "전체 세션"), body),
        ],
        [
            Paragraph("<b>기준 시각 (as_of)</b>", body),
            Paragraph(f"{_kst(summary['as_of'])} (적재 지연 {summary['ingestion_lag_seconds']}s)", body),
            Paragraph("<b>생성자 내부 ID</b>", body),
            Paragraph(str(author_id), body),
        ],
        [
            Paragraph("<b>보고서 생성일시</b>", body),
            Paragraph(_kst(datetime.now(UTC)), body),
            Paragraph("<b>대상 이벤트</b>", body),
            Paragraph(f"총 {total_events:,}건 (지연분 제외)", body),
        ],
    ]
    meta_table = Table(meta_rows, colWidths=[28 * mm, 63 * mm, 28 * mm, 63 * mm])
    meta_table.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#ffffff")),
            ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
            ("INNERGRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#f1f5f9")),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ])
    )
    story.append(meta_table)
    story.append(Spacer(1, 4 * mm))

    # 3. Section: 처리 결과 통계 (단위: 이벤트 수) - 도넛 그래프 + 상세 표
    story.append(Paragraph("1. 처리 결과 통계 (단위: 이벤트 수)", head_style))

    tot_s = sum(summary["status_counts"].values()) or 1
    donut_chart = _status_donut(summary["status_counts"], total_events, font, font_bold, width=54 * mm, height=44 * mm)

    status_table_data = [
        [Paragraph("상태 구분", th_style), Paragraph("건수", th_style), Paragraph("비율", th_style)]
    ]
    for k in ("success", "blocked", "masked", "confirmation_required", "error"):
        cnt = summary["status_counts"].get(k, 0)
        label, color_code = STATUS_MAP.get(k, (k, "#334155"))
        status_table_data.append([
            Paragraph(f"<font color='{color_code}'>●</font> {label}", body),
            Paragraph(f"{cnt:,}건", body_right),
            Paragraph(f"{cnt / tot_s * 100:.1f}%", body_right),
        ])
    t_status = Table(status_table_data, colWidths=[58 * mm, 35 * mm, 35 * mm])
    t_status.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
            ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#cbd5e1")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#ffffff"), colors.HexColor("#f8fafc")]),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ])
    )

    layout_status = Table([[donut_chart, t_status]], colWidths=[54 * mm, 128 * mm])
    layout_status.setStyle(
        TableStyle([
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("ALIGN", (0, 0), (0, 0), "CENTER"),
            ("LEFTPADDING", (0, 0), (-1, -1), 0),
            ("RIGHTPADDING", (0, 0), (-1, -1), 0),
            ("TOPPADDING", (0, 0), (-1, -1), 0),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
        ])
    )
    story.append(layout_status)
    story.append(Spacer(1, 4 * mm))

    # 4. Section: [신규 항목] 차단을 만든 계층 분석 (규칙 · AI 판별기 적중 분포)
    story.append(Paragraph("2. 차단을 만든 계층 분석 (규칙 · AI 판별기 적중 분포)", head_style))
    overlap = summary.get("layer_overlap", {})
    overlap_rows = [
        [
            Paragraph("단계", th_style),
            Paragraph("규칙만", th_style),
            Paragraph("AI 판별만", th_style),
            Paragraph("둘 다", th_style),
            Paragraph("규칙만(AI 실패)", th_style),
            Paragraph("계층 차단 합계", th_style),
        ]
    ]
    sum_ro, sum_jo, sum_b, sum_err = 0, 0, 0, 0
    for stage_key in ("input", "tool", "output"):
        stage_name = STAGE_NAMES.get(stage_key, stage_key)
        st_data = overlap.get(stage_key, {})
        ro = int(st_data.get("rules_only", 0))
        jo = int(st_data.get("judge_only", 0))
        b = int(st_data.get("both", 0))
        err = int(st_data.get("rules_judge_error", 0))
        st_tot = ro + jo + b + err
        sum_ro += ro
        sum_jo += jo
        sum_b += b
        sum_err += err
        overlap_rows.append([
            Paragraph(stage_name, body),
            Paragraph(f"{ro:,}", body_right),
            Paragraph(f"{jo:,}", body_right),
            Paragraph(f"{b:,}", body_right),
            Paragraph(f"{err:,}", body_right),
            Paragraph(f"<b>{st_tot:,}</b>", body_right),
        ])
    overlap_rows.append([
        Paragraph("<b>전체 합계</b>", body_bold),
        Paragraph(f"<b>{sum_ro:,}</b>", body_right),
        Paragraph(f"<b>{sum_jo:,}</b>", body_right),
        Paragraph(f"<b>{sum_b:,}</b>", body_right),
        Paragraph(f"<b>{sum_err:,}</b>", body_right),
        Paragraph(f"<b>{(sum_ro + sum_jo + sum_b + sum_err):,}</b>", body_right),
    ])
    t_overlap = Table(overlap_rows, colWidths=[37 * mm, 29 * mm, 29 * mm, 29 * mm, 31 * mm, 27 * mm])
    t_overlap.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
            ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#cbd5e1")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -2), [colors.HexColor("#ffffff"), colors.HexColor("#f8fafc")]),
            ("BACKGROUND", (0, -1), (-1, -1), colors.HexColor("#f1f5f9")),
            ("TOPPADDING", (0, 0), (-1, -1), 3.5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3.5),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ])
    )
    story.append(t_overlap)
    story.append(Spacer(1, 4 * mm))

    # 5. Section: OWASP LLM Top 10 2025 분류
    story.append(Paragraph("3. OWASP LLM Top 10 2025 분류 (단위: 룰 적중 수)", head_style))
    cat_counts = summary.get("category_counts", {})
    tot_hits = sum(cat_counts.values()) or 1
    owasp_rows = [
        [Paragraph("OWASP 2025 분류 항목", th_style), Paragraph("적중 수", th_style), Paragraph("비율", th_style)]
    ]
    if cat_counts:
        for k, v in cat_counts.items():
            name = OWASP_NAMES.get(k, k)
            owasp_rows.append([
                Paragraph(escape(name), body),
                Paragraph(f"{v:,}회", body_right),
                Paragraph(f"{v / tot_hits * 100:.1f}%", body_right),
            ])
    else:
        owasp_rows.append([
            Paragraph("적중한 보안 규칙이 없습니다.", body),
            Paragraph("0회", body_right),
            Paragraph("0.0%", body_right),
        ])
    t_owasp = Table(owasp_rows, colWidths=[112 * mm, 35 * mm, 35 * mm])
    t_owasp.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
            ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#cbd5e1")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#ffffff"), colors.HexColor("#f8fafc")]),
            ("TOPPADDING", (0, 0), (-1, -1), 3.5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3.5),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ])
    )
    story.append(t_owasp)
    story.append(Spacer(1, 4 * mm))

    # 6. Section: 인프라 지연 및 룰셋 버전 정보
    story.append(Paragraph("4. 인프라 지연 및 보안 룰셋 버전", head_style))
    rules_str = (
        ", ".join(f"<b>{escape(v['label'] or '미지정')}</b> ({escape(v['id'][:8])})"
                  for v in summary.get("ruleset_versions", []))
        or "기본 내장 룰셋"
    )
    p95_str = f"{summary['latency_p95_ms']:.1f} ms" if summary.get("latency_p95_ms") is not None else "데이터 없음"
    infra_rows = [
        [
            Paragraph("<b>서버 처리 시간 (P95)</b>", body),
            Paragraph(
                f"{p95_str} <font color='#64748b'>(LLM 모델 생성 시간 포함, 순수 가드레일 판별 시간이 아님)</font>",
                body,
            ),
        ],
        [
            Paragraph("<b>적용된 룰셋 버전</b>", body),
            Paragraph(rules_str, body),
        ],
    ]
    t_infra = Table(infra_rows, colWidths=[42 * mm, 140 * mm])
    t_infra.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
            ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ("INNERGRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#e2e8f0")),
            ("TOPPADDING", (0, 0), (-1, -1), 3.5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3.5),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ])
    )
    story.append(t_infra)
    story.append(Spacer(1, 4 * mm))

    # 7. Section: 이벤트 상세 내역 (최근 500건, 마스킹된 요약)
    story.append(Paragraph("5. 이벤트 상세 내역 (최근 500건, 민감정보 마스킹 처리됨)", head_style))
    event_data = [
        [
            Paragraph("시각(KST)", th_style),
            Paragraph("출처", th_style),
            Paragraph("상태", th_style),
            Paragraph("단계", th_style),
            Paragraph("ms", th_style),
            Paragraph("요약", th_style),
        ]
    ]
    for r in rows:
        st_raw = r.get("status", "")
        st_name = STATUS_MAP.get(st_raw, (st_raw, "#334155"))[0].split(" (")[0]
        event_data.append([
            Paragraph(_kst(r["occurred_at"]), body),
            Paragraph(escape(str(r.get("source", ""))), body_center),
            Paragraph(escape(st_name), body_center),
            Paragraph(escape(r.get("stage") or "-"), body_center),
            Paragraph(f"{float(r.get('total_ms', 0)):.0f}", body_right),
            Paragraph(escape(str(r.get("summary_redacted", ""))), body),
        ])
    t_events = Table(event_data, colWidths=[30 * mm, 20 * mm, 18 * mm, 15 * mm, 13 * mm, 86 * mm], repeatRows=1)
    t_events.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
            ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#cbd5e1")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#ffffff"), colors.HexColor("#f8fafc")]),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ])
    )
    story.append(t_events)
    story.append(Spacer(1, 5 * mm))

    # 8. Disclaimer
    story.append(
        Paragraph(
            "※ 본 보고서의 차단 비율은 실제 운영 이벤트 집계 기준이며, "
            "정답 라벨이 부여된 합성 시험셋의 방어 탐지율과 산출 기준이 다릅니다. "
            "질의·응답 원문은 저장하지 않으며, 마스킹된 요약만 표시합니다.",
            ParagraphStyle("disclaimer", fontName=font, fontSize=7, leading=10, textColor=colors.HexColor("#64748b")),
        )
    )

    buffer = io.BytesIO()
    SimpleDocTemplate(
        buffer,
        pagesize=A4,
        leftMargin=14 * mm,
        rightMargin=14 * mm,
        topMargin=14 * mm,
        bottomMargin=14 * mm,
        title="AI Security Guardrail Report",
    ).build(story)
    return buffer.getvalue()
