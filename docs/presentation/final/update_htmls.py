import re
from pathlib import Path

wbs_path = Path(r"C:\Users\user\Desktop\프로젝트\2안\AI_보안_가드레일_챗봇_WBS.html")
with open(wbs_path, "r", encoding="utf-8") as f:
    wbs_content = f.read()

# 1. Update header subtitle
wbs_content = wbs_content.replace(
    "OWASP Top 10 for LLM 기반 • 2인 팀 (A: 백엔드/보안, B: SLM/UI) • 11주 공정 24개 세부 작업 전체 (1.0 ~ 6.0)",
    "OWASP Top 10 for LLM 기반 • 1인 전담 개발 (풀스택 & AI 보안) • 11주 공정 24개 세부 작업 전체 (1.0 ~ 6.0)"
)

# 2. Update section titles
wbs_content = wbs_content.replace("3.0 AI 보안 가드레일 엔진 개발 단계 (팀원 A 담당)", "3.0 AI 보안 가드레일 엔진 개발 단계")
wbs_content = wbs_content.replace("4.0 UI 및 관제 대시보드 개발 단계 (팀원 B 담당)", "4.0 UI 및 관제 대시보드 개발 단계")

# 3. Update note box
wbs_content = re.sub(
    r'<div class="note-box">.*?</div>',
    '<div class="note-box">💡 <b>일정 계획 핵심 원칙:</b> W1 말 백엔드 API 규격을 조기에 동결한 후, 보안 가드레일 엔진과 관제 UI 파이프라인을 모듈별로 체계적으로 구현하였으며, W10~W11 주차에 충분한 버퍼(여유 기간)를 두어 안정적인 최종 발표 및 시연을 보장합니다.</div>',
    wbs_content,
    flags=re.DOTALL
)

# 4. Remove '담당' th and adjust other widths
old_thead = """        <th style="width: 7.5%;">WBS ID</th>
        <th style="width: 10.5%;">대분류</th>
        <th style="width: 18%;">세부 작업명</th>
        <th style="width: 32%;">상세 수행 내용</th>
        <th style="width: 6.5%;">담당</th>
        <th style="width: 7.5%;">선행작업</th>
        <th style="width: 5.5%;">기간</th>
        <th style="width: 12.5%;">완료 기준 (DoD)</th>"""

new_thead = """        <th style="width: 8%;">WBS ID</th>
        <th style="width: 11%;">대분류</th>
        <th style="width: 20%;">세부 작업명</th>
        <th style="width: 37%;">상세 수행 내용</th>
        <th style="width: 8%;">선행작업</th>
        <th style="width: 5%;">기간</th>
        <th style="width: 11%;">완료 기준 (DoD)</th>"""

wbs_content = wbs_content.replace(old_thead, new_thead)

# 5. In level-1 rows: colspan="7" -> colspan="6"
wbs_content = wbs_content.replace('colspan="7"', 'colspan="6"')

# 6. Remove the 담당 td in each row
wbs_content = re.sub(r'\s*<td class="center"><span class="badge [^"]+">[^<]+</span></td>', '', wbs_content)

with open(wbs_path, "w", encoding="utf-8") as f:
    f.write(wbs_content)
print(f"Updated {wbs_path} successfully!")


# -------------------------------------------------------------
# Gantt Chart Update
# -------------------------------------------------------------
gantt_path = Path(r"C:\Users\user\Desktop\프로젝트\2안\Gantt_Chart.html")
with open(gantt_path, "r", encoding="utf-8") as f:
    gantt_content = f.read()

# 1. Update header subtitle
gantt_content = gantt_content.replace(
    "팀원 2인(A, B) 역할 분담 및 선행/병렬 작업 의존성 기반 주차별 프로젝트 추진 일정표 (2026.08 ~ 2026.11)",
    "1인 전담 개발 공정 및 선행/의존성 기반 주차별 프로젝트 추진 일정표 (2026.08 ~ 2026.11)"
)

# 2. Update legend
old_legend = """    <div class="legend-container">
      <div class="legend-item"><div class="legend-color lc-a"></div>팀원 A (백엔드/보안)</div>
      <div class="legend-item"><div class="legend-color lc-b"></div>팀원 B (SLM/UI)</div>
      <div class="legend-item"><div class="legend-color lc-common"></div>공통 (협업)</div>
      <div class="legend-item"><div class="legend-color lc-cp"></div>★ 크리티컬 패스</div>
    </div>"""

new_legend = """    <div class="legend-container">
      <div class="legend-item"><div class="legend-color" style="background-color: #2563eb;"></div>1.0 기획 & 명세</div>
      <div class="legend-item"><div class="legend-color" style="background-color: #0d9488;"></div>2.0 환경 & 데이터</div>
      <div class="legend-item"><div class="legend-color" style="background-color: #059669;"></div>3.0 가드레일 엔진</div>
      <div class="legend-item"><div class="legend-color" style="background-color: #9333ea;"></div>4.0 UI & 대시보드</div>
      <div class="legend-item"><div class="legend-color" style="background-color: #d97706;"></div>5.0 통합 & 검증</div>
      <div class="legend-item"><div class="legend-color" style="background-color: #475569;"></div>6.0 시연 & 완료</div>
      <div class="legend-item"><div class="legend-color lc-cp"></div>★ 크리티컬 패스 (CP)</div>
    </div>"""

gantt_content = gantt_content.replace(old_legend, new_legend)

# 3. Update table head: remove col-assignee
gantt_content = gantt_content.replace('<th class="col-assignee" rowspan="2">투입 인원</th>', '')
# In cat-header: colspan="19" -> colspan="18"
gantt_content = gantt_content.replace('colspan="19"', 'colspan="18"')

# 4. Remove col-assignee in each row
gantt_content = re.sub(r'\s*<td class="col-assignee"><span class="badge [^"]+">[^<]+</span></td>', '', gantt_content)

# 5. Update bar styles by phase:
# 1.0 PLN -> style background #2563eb
# 2.0 ENV -> style background #0d9488
# 3.0 SEC -> style background #059669
# 4.0 UI  -> style background #9333ea
# 5.0 VAL -> style background #d97706
# 6.0 FIN -> style background #475569

# Replace classes
phase_colors = {
    "PLN": "#2563eb",
    "ENV": "#0d9488",
    "SEC": "#059669",
    "UI": "#9333ea",
    "VAL": "#d97706",
    "FIN": "#475569"
}

# Update CSS for bar colors by phase
old_bar_css = """  .bar.bar-a { background-color: var(--accent-blue); }
  .bar.bar-b { background-color: var(--accent-purple); }
  .bar.bar-common { background-color: var(--accent-green); }"""

new_bar_css = """  .bar.bar-pln { background-color: #2563eb; }
  .bar.bar-env { background-color: #0d9488; }
  .bar.bar-sec { background-color: #059669; }
  .bar.bar-ui  { background-color: #9333ea; }
  .bar.bar-val { background-color: #d97706; }
  .bar.bar-fin { background-color: #475569; }"""

gantt_content = gantt_content.replace(old_bar_css, new_bar_css)

# Replace bar classes in HTML
for prefix, col in [("PLN", "bar-pln"), ("ENV", "bar-env"), ("SEC", "bar-sec"), ("UI", "bar-ui"), ("VAL", "bar-val"), ("FIN", "bar-fin")]:
    gantt_content = re.sub(
        rf'class="bar (?:bar-a|bar-b|bar-common)" data-title="({prefix}-\d+[^"]+)" data-assignee="[^"]*"',
        rf'class="bar {col}" data-title="\1" data-assignee="1인 전담"',
        gantt_content
    )
    gantt_content = re.sub(
        rf'class="bar (?:bar-a|bar-b|bar-common) cp-bar" data-title="({prefix}-\d+[^"]+)" data-assignee="[^"]*"',
        rf'class="bar {col} cp-bar" data-title="\1" data-assignee="1인 전담"',
        gantt_content
    )

# 6. In tooltip: change 투입인원 label to 구분
gantt_content = gantt_content.replace(
    '<span class="tooltip-label">투입인원:</span>',
    '<span class="tooltip-label">수행구분:</span>'
)

with open(gantt_path, "w", encoding="utf-8") as f:
    f.write(gantt_content)
print(f"Updated {gantt_path} successfully!")
