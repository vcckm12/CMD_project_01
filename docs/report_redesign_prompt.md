# 보안 보고서(PDF) 양식 개편 작업 지시 (다른 AI에게 그대로 전달)

아래 `---` 이후 전체를 작업을 맡길 AI에게 그대로 붙여 넣으세요. 저장소 전체를 읽고 파일을 고칠 수 있는 코딩 AI를 전제로 합니다. 대시보드 디자인 지시는 [ui_redesign_prompt_ops.md](ui_redesign_prompt_ops.md)입니다.

---

## 역할과 목표

당신은 보고서 디자이너 겸 파이썬 개발자입니다. 이 저장소의 관제 대시보드에서 **"보고서 → PDF 생성"으로 받는 보안 보고서의 양식**을 새로 만듭니다.

- 지금 PDF는 A4 한 장에 표와 글만 나열한 단순한 형태입니다. 상태 이름도 `success`, `blocked`처럼 영어로 나옵니다.
- 경영진·심사위원이 첫 장만 보고도 "얼마나 들어왔고, 얼마나 막았고, 무엇이 막았는지"를 알 수 있는 보고서로 바꿉니다.
- 서비스: "GUARDRAIL FASHION" 패션 쇼핑몰의 AI 보안 가드레일 관제입니다. 대시보드·쇼핑몰과 같은 브랜드 톤을 씁니다.
- 색 기준:
  - 먹색 `#0f172a`, 샌드 `#f8f6f2`, 테두리 `#e2e8f0`, 골드 포인트 `#c5a880`
  - 상태 색: 정상 초록 `#047857`, 차단 빨강 `#b91c1c`, 가림 주황 `#b45309`, 승인 대기 파랑 `#1d4ed8`, 오류 회색 `#64748b`
  - 상태 색의 의미는 반드시 지킵니다.

## 손대도 되는 파일

| 파일 | 허용 범위 |
|---|---|
| `backend/app/audit/report.py` | **자유롭게** (주 작업 파일). 함수를 나누거나 새로 추가해도 됩니다. |
| `backend/app/api/ops.py`의 `report()` 함수 | 아래 '데이터 추가'의 쿼리 1개 추가와 `build_report_pdf` 호출 인자 추가만 |
| `backend/tests/test_report_pdf.py` (새로 만듦) | 아래 '시험' 항목 |

그 외 파일은 **수정 금지**입니다. `compute_stats`, `_filters`, `_range`, `MAX_REPORT_RANGE`, `MAX_REPORT_EVENTS`, 다른 API, `frontend/`, `migrations/`, `docker-compose.yml`, `requirements.txt`, `Dockerfile`이 모두 해당합니다.

- 새 라이브러리는 추가하지 않습니다. 이미 설치된 `reportlab==4.4.4`만 씁니다. 표·문단은 `platypus`, 차트는 `reportlab.graphics`(`Drawing`, `Pie`, `HorizontalBarChart` 등)를 씁니다.
- 글꼴은 이미지에 설치된 `NanumGothic`(`/usr/share/fonts/truetype/nanum/NanumGothic.ttf`)을 씁니다.
  - 굵은 글씨가 필요하면 같은 폴더의 `NanumGothicBold.ttf`를 쓰되, 기존 `_font()`처럼 **파일이 없으면 기본 글꼴로 대체**되게 합니다. 시험 환경에는 글꼴이 없을 수 있습니다.
- 외부 그림·URL은 쓰지 않습니다. 로고가 필요하면 reportlab 도형(사각형·글자)으로 그립니다.

## 보안 규칙 (반드시 지킬 것)

1. **사용자 원문은 절대 넣지 않습니다.** 감사 데이터에는 원문이 없고, 마스킹된 `summary_redacted`만 있습니다. 이 원칙을 유지합니다.
2. **`Paragraph`에 넣는 글자는 모두 `escape()`를 거칩니다.**
   - `Paragraph`는 `<b>`, `<font>` 같은 표시 문법을 해석합니다. 그래서 데이터(요약·룰셋 이름·세션 ID 등)를 그대로 넣으면 PDF가 깨지거나 조작될 수 있습니다.
   - 굵게·색 같은 꾸밈은 **고정 문자열이나 `ParagraphStyle`로만** 합니다. 데이터에 꾸밈 태그를 붙이지 않습니다.
   - 차트 라벨·표 칸에 들어가는 문자열도 같은 원칙입니다. 표 칸에 `Paragraph`를 쓰면 escape하고, 일반 문자열 칸은 그대로 둡니다.
3. **생성자 정보는 내부 ID만 씁니다.** 이메일·이름을 새로 조회해 넣지 않습니다. 내부 ID는 표지에서 빼도 됩니다.

## 새 보고서 구성 (A4 세로, 기본 순서)

**1쪽 — 표지 + 핵심 요약**

- 상단 띠(먹색 바탕, 흰 글자): "GUARDRAIL FASHION · AI 보안 가드레일 보고서"
- 기본 정보: 보고 기간(KST), 대상(전체 또는 세션 ID), 생성 시각, 기준 시각(as_of)과 적재 지연
- 오른쪽 위에 **결재란**(작성 / 검토 / 승인, 빈 칸 3개)을 둡니다.
- **핵심 숫자 카드 6개**(2줄×3칸 또는 1줄×6칸): 요청(이벤트) / ✅ 정상 / 🛑 차단 / 🔒 가림 / ⏳ 승인 대기 / ⚠️ 오류
  - 큰 숫자 아래에 전체 대비 비율(%)을 씁니다. 숫자 색은 상태 색입니다.
  - 이모지는 NanumGothic에 없어 깨질 수 있습니다. PDF에서는 이모지 대신 **글자나 색 막대**로 구분합니다.
- **한 줄 결론**(고정 문장 + 숫자): 예) "기간 중 요청 585건 중 44건(7.5%)을 차단했습니다. AI 판별기만 잡아낸 차단은 입력 단계 12건입니다."

**2쪽 — 차트**

- **상태 비율 도넛:** `status_counts`. 조각 색은 상태 색이고, 가운데 구멍에 총 건수를 씁니다. 범례에는 한글 이름·건수·비율을 씁니다.
- **차단을 만든 계층:** `layer_overlap`. 입력 / 도구 결과 / 출력 단계별 도넛 3개 또는 100% 누적 막대로 그립니다.
  - 조각: 규칙만 `#0f172a`, AI 판별만 `#7c3aed`, 둘 다 `#047857`, 규칙만(AI 실패) `#94a3b8`
  - 건수가 0인 단계는 "기록 없음"이라고 씁니다.
- **OWASP 2025 분류 막대:** `category_counts`, 가로 막대입니다. 단위가 "룰 적중 수"이며 이벤트 수와 다르다는 설명을 차트 아래에 남깁니다.
  - 분류 이름은 한글을 함께 씁니다: LLM01 프롬프트 인젝션, LLM02 민감정보 노출, LLM06 과도한 권한, LLM07 시스템 프롬프트 유출 (나머지는 코드 그대로).
- **차단 상위 규칙 TOP 10 표:** 아래 '데이터 추가'로 받은 `top_rules`를 씁니다. 열은 순위, 규칙 ID, 분류, 동작, 적중 수입니다.

**3쪽 이후 — 상세**

- **지연·룰 버전:** P95 처리 시간(모델 생성 시간 포함 설명 유지), 사용된 룰셋 목록
- **이벤트 요약 표:** 최근 500건, 마스킹된 요약만 씁니다.
  - 상태 칸은 한글 이름으로 쓰고, 칸 배경을 상태 색의 옅은 톤으로 칠합니다.
  - 머리 행은 쪽이 넘어가도 반복합니다(`repeatRows=1`).
- **맺음말(유지):** "이 보고서의 차단 비율은 운영 이벤트 기준이며, 정답 라벨이 있는 시험셋의 탐지율과 다릅니다."

**모든 쪽 공통**

- **머리말:** 왼쪽 "AI 보안 가드레일 보고서", 오른쪽 "대외비"
- **꼬리말:** 보고 기간, "쪽 N / 전체 M"
  - 전체 쪽수는 두 번 그리기 방식으로 계산합니다. `canvasmaker`를 쓴 NumberedCanvas 패턴입니다.

**표기 규칙**

- 상태 한글 이름: success=정상, blocked=차단, masked=가림, confirmation_required=승인 대기, error=오류
- 시각은 모두 KST `YYYY-MM-DD HH:MM:SS`로 씁니다(기존 `_kst()` 사용).
- 숫자는 천 단위 쉼표를 씁니다.
- 데이터가 비었을 때(이벤트 0건, 적중 0건)는 차트 대신 "기록 없음"을 쓰고, 0으로 나누는 오류가 없어야 합니다.

## 데이터 추가 (`ops.py`의 `report()`만)

`summary`에는 이미 다음이 있습니다. **새로 계산하지 말고 그대로 씁니다.**
`from`, `to`, `total`, `status_counts`, `category_counts`, `latency_p95_ms`, `layer_overlap`, `ruleset_versions`, `as_of`, `ingestion_lag_seconds`

차단 상위 규칙만 새로 필요합니다. `report()` 안에서 기존 `rows` 조회 바로 다음, **같은 `conn` 블록 안에** 아래 쿼리 하나만 추가합니다. `where`/`params`는 기존 것을 재사용하고, 문자열 치환 방식도 `compute_stats`와 똑같이 씁니다.

```python
        top_rules = await (
            await conn.execute(
                "SELECT h.rule_id, h.category, h.action, sum(h.match_count) AS n FROM audit.rule_hits h"
                " JOIN audit.events e USING (event_id)"
                f" WHERE {where.replace('occurred_at', 'e.occurred_at').replace('session_id', 'e.session_id')}"  # noqa: S608
                " GROUP BY h.rule_id, h.category, h.action ORDER BY n DESC, h.rule_id LIMIT 10",
                params,
            )
        ).fetchall()
```

그리고 `build_report_pdf(..., top_rules=top_rules)`처럼 **키워드 인자로** 넘깁니다. `build_report_pdf`에서는 `top_rules: list[dict] = ()`를 기본값으로 둡니다. 그러면 인자 없이 불러도 동작합니다.

이 쿼리 외에 SQL·권한·응답 헤더·파일 이름·오류 처리(`REPORT_TOO_LARGE` 등)는 바꾸지 않습니다.

## 시험

`backend/tests/test_report_pdf.py`를 새로 만들고, `build_report_pdf`를 직접 불러 확인합니다. DB 없이 돌아가는 단위 시험입니다.

1. **정상:** 예시 `summary`(위 키 전부)와 `rows` 3건, `top_rules` 2건으로 만든 결과가 `b"%PDF-"`로 시작합니다.
2. **빈 데이터:** 모든 건수가 0이고 `rows`·`top_rules`가 빈 목록이며 `latency_p95_ms=None`이어도 예외 없이 PDF가 나옵니다.
3. **표시 문법 무력화:** `summary_redacted="<b>x</b><font color=red>y</font>"`, 룰셋 label `"<para>"`가 있어도 예외 없이 PDF가 나옵니다.
4. **많은 행:** `rows` 500건이면 여러 쪽 PDF가 나옵니다. `pypdf`는 없으니 쪽 수 확인은 `content.count(b"/Type /Page")`처럼 대략 확인하거나 생략합니다.

기존 `backend/tests/test_ops_api.py::test_pdf_report`는 그대로 통과해야 합니다.

## 확인 방법 (작업 후 반드시)

1. **시험:** 저장소 루트에서 `sh scripts/test.sh`를 실행합니다. 전체가 통과해야 합니다.
2. **반영:**
   ```
   docker compose --env-file .env.lab up -d --build --wait api audit-worker scheduler
   ```
3. **실물 확인:** `https://ops.example.internal:8443` → 보고서 → 미리보기 → PDF 생성 → PDF 다운로드. 받은 PDF를 열어 확인합니다.
   - 한글이 깨지지 않습니까(□ 표시 없음)?
   - 표지·카드·차트·표가 쪽 경계에서 잘리지 않습니까?
   - 꼬리말의 쪽 번호가 맞습니까?
   - 세션 ID를 넣은 보고서와 이벤트가 없는 기간의 보고서도 정상입니까?
4. **자동 점검:** 저장소 README의 "브라우저 E2E (LAB 8443 기준)" 절 명령으로 `e2e_ops.py`가 통과해야 합니다. 이 점검은 PDF 다운로드를 확인합니다.

## 결과물

- 바꾼 파일 목록과 파일별 변경 요약
- 새 보고서의 쪽별 캡처: 1쪽, 2쪽, 상세 쪽 1장. PDF를 이미지로 바꿔 첨부합니다.
- `sh scripts/test.sh` 결과와 `e2e_ops.py` 결과
