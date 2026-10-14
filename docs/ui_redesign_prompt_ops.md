# 관제 대시보드 디자인 개편 2차 작업 지시 (다른 AI에게 그대로 전달)

아래 `---` 이후 전체를 디자인을 맡길 AI에게 그대로 붙여 넣으세요. 저장소 전체를 읽고 파일을 고칠 수 있는 코딩 AI를 전제로 합니다. 1차 지시는 [ui_redesign_prompt.md](ui_redesign_prompt.md)입니다. 이번 지시는 **관제 대시보드(`frontend/ops`)에만** 적용합니다.

---

## 역할과 목표

당신은 웹 UI 디자이너 겸 프론트엔드 개발자입니다. 이 저장소의 **관제 대시보드**(Streamlit, `frontend/ops/app.py`)의 **디자인만** 개선합니다. 기능·동작·문구·데이터 흐름은 하나도 바꾸지 않습니다.

1차 작업에서는 테마 색만 조금 바뀌어 화면이 거의 그대로였습니다. 이번에는 아래 두 가지로 눈에 띄게 바꿉니다.

1. **고정 CSS 파일 1개**를 넣어 쇼핑몰(`frontend/shop/css/style.css`)과 같은 톤으로 꾸밉니다.
2. **비율(%)을 보여 주는 차트 3개를 도넛 차트로** 바꿉니다.

- 서비스: "GUARDRAIL FASHION" 패션 쇼핑몰의 AI 보안 가드레일 관제 화면입니다.
- 원하는 분위기: 신뢰감 있는 보안 관제(SOC) 화면입니다. 쇼핑몰과 같은 브랜드로 보여야 합니다.
- 색 기준(쇼핑몰과 같음):
  - 먹색 `#0f172a`, 샌드 `#f8f6f2`, 테두리 `#e2e8f0`, 골드 포인트 `#c5a880`
  - 상태 색: 정상 초록 `#047857`, 차단 빨강 `#b91c1c`, 가림 주황 `#b45309`, 승인 대기 파랑 `#1d4ed8`
  - 상태 색의 의미는 반드시 유지합니다.

## 손대도 되는 파일

| 파일 | 허용 범위 |
|---|---|
| `frontend/ops/style.css` (새로 만듦) | **자유롭게** (주 작업 파일) |
| `frontend/ops/app.py` | 아래 '허용하는 app.py 변경'만 |
| `frontend/ops/.streamlit/config.toml` | 테마 자유 |
| `frontend/ops/Dockerfile` | `COPY app.py ops_client.py ./` 줄에 `style.css`를 추가하는 것만 (`COPY app.py ops_client.py style.css ./`) |

그 외 파일은 **수정 금지**입니다. `frontend/ops/ops_client.py`, `backend/`, `deployment/`, `scripts/`, `docker-compose.yml`, `frontend/shop/`이 모두 해당합니다.

## 1. 고정 CSS 파일 넣기 (보안 규칙 — 반드시 이 방식으로)

이 대시보드는 **공격자가 쓴 문장**을 관리자 화면에 보여 줍니다. 차단된 질문 원문, AI 답변, 규칙에 걸린 문장 같은 것들입니다. 이런 문장이 HTML로 해석되면 관리자 브라우저에서 스크립트가 실행됩니다(XSS). 그래서 아래 방식 **딱 하나만** 허용합니다.

```python
from pathlib import Path

# Fixed stylesheet from the repo; never mix data into it (no f-string, no format, no concatenation with values).
STYLE = Path(__file__).with_name("style.css").read_text("utf-8")
...
st.html(f"<style>{STYLE}</style>")  # 앱 시작 직후, st.set_page_config 다음에 한 번만
```

- `st.html`은 **이 한 곳에서만**, **`style.css` 내용만** 넣습니다. 이벤트·규칙·답변·사용자 이름·숫자 등 **어떤 데이터도** HTML에 섞지 않습니다.
- `unsafe_allow_html=True`, `st.components`, 그 밖의 `st.html` 호출은 계속 **금지**입니다.
- CSS 안에서도 외부 리소스를 쓰지 않습니다. `@import`, 외부 `url(...)`, 구글 폰트, CDN 모두 해당합니다. 글꼴은 시스템 글꼴 스택을 씁니다: `"Pretendard", "Apple SD Gothic Neo", "Malgun Gothic", "Noto Sans KR", sans-serif`.
- CSS에 `content:`로 글자를 넣지 않습니다. 화면 문구는 모두 app.py에 있어야 합니다.
- `app.py` 3번째 줄의 모듈 설명은 "Never renders HTML…"입니다. 이 문장을 "Never renders data as HTML: the only `st.html` call injects the fixed `style.css`; …"처럼 사실에 맞게 고칩니다.

**CSS로 꾸밀 대상 (예시)**

- 사이드바: 샌드 배경, 메뉴(라디오) 항목을 알약 모양 버튼처럼 보이게, 선택 항목 강조
- 상단 제목(`st.title`, `st.header`): 굵기, 자간, 아래 얇은 구분선
- `st.container(border=True)` 카드: 흰 배경, 은은한 그림자, 모서리 12px
- `st.metric` 숫자 카드: 숫자를 크게, 라벨은 작은 대문자 느낌
- 버튼: 먹색 기본 버튼, hover/`:focus-visible` 표시
- 표(`st.dataframe`) 주변 여백, 경보·정보 상자(`st.info/warning/error`) 모서리·여백

**선택자 작성 요령**

- Streamlit은 요소에 `data-testid` 속성을 붙입니다. 예: `[data-testid="stSidebar"]`, `[data-testid="stVerticalBlockBorderWrapper"]`, `[data-testid="stMetric"]`, `[data-testid="stHeading"]`, `[data-testid="stButton"] button`.
- 가능하면 이것을 쓰고, `.st-emotion-cache-xxxx`처럼 무작위로 생긴 class는 **쓰지 않습니다**. 다시 빌드하면 이름이 바뀝니다.
- Streamlit 버전은 `1.50.0`으로 고정되어 있습니다. `requirements.txt`는 바꾸지 않습니다.
- 버전이 바뀌면 일부 스타일이 풀릴 수 있습니다. 그래서 CSS가 하나도 적용되지 않아도 화면은 정상으로 읽혀야 합니다. 꾸밈은 CSS에, 의미는 글자와 아이콘에 둡니다.

## 2. 도넛 차트로 바꿀 3곳

모두 Altair `mark_arc(innerRadius=…)`로 만듭니다. HTML은 쓰지 않습니다.

- **도넛 가운데 글자:** 총 건수 같은 숫자는 `mark_text` 레이어로 넣습니다.
- **범례:** 아래쪽(`orient="bottom"`)에 두고, 항목 이름은 지금 쓰는 글자를 그대로 씁니다.
- **툴팁:** 지금 툴팁 필드를 유지하고, 비율(%)을 추가합니다.
- **색:** 기존 색 사전(`OVERLAP_STYLE`, `STATUS_STYLE`, `verdict_colors`)의 색을 그대로 씁니다. 사전 안의 색 값은 바꿔도 됩니다.
- **헬퍼:** 공통 함수 `donut(frame, label_field, value_field, colors, center_text)`를 하나 만들어 세 곳에서 같이 써도 됩니다. 새 함수 추가는 허용합니다.

| # | 위치 (함수) | 지금 | 바꿀 모양 |
|---|---|---|---|
| ① | 대시보드 `dashboard()`의 "**차단을 만든 계층** (규칙 · AI 판별)" 카드 | 단계별 100% 누적 막대 1개 | **단계별 작은 도넛 3개**(입력 / 도구 결과 / 출력)를 `st.columns(3)`로 나란히 놓습니다. 조각은 규칙만 / AI 판별만 / 둘 다 / 규칙만(AI 실패)이고, 가운데에 그 단계의 차단 건수를 넣습니다. 건수가 0인 단계는 도넛 대신 `st.caption("없음")`을 씁니다. |
| ② | 감사 상세 `layer_breakdown` 부분, 제목 "**계층별 판정·처리 시간 비중**" | 오른쪽에 처리 시간 가로 막대 | **처리 시간 비중 도넛** 1개로 바꿉니다. 조각은 표의 `계층`이고, 색은 그 계층의 `판정` 색(차단 빨강 / 통과 초록 / 판별 실패 주황 / — 회색)입니다. 같은 색이 여러 조각에 나와도 됩니다. 가운데에 총 처리 시간(`total_ms`, 예: "12,345 ms")을 넣습니다. **왼쪽 표는 그대로** 둡니다. |
| ③ | 보고서 `report_page()`의 "미리보기" 결과 | `status_counts`를 한 줄짜리 표로 표시 | **상태 비율 도넛**을 추가합니다. 조각 이름은 `STATUS_STYLE`의 표시 이름(✅ 정상 · 🛑 차단 · …)을 쓰고, 가운데에 총 이벤트 수를 넣습니다. 기존 표는 도넛 아래에 **남겨 둡니다**. |

**그대로 두는 차트:** "OWASP 2025 분류 (룰 적중 수)" 같은 항목별 건수 비교 막대는 도넛으로 바꾸지 않습니다. 막대가 더 읽기 쉽습니다.

**데이터 계산은 바꾸지 않습니다.** 차트에 넘기는 `rows`/`frame`을 만드는 코드는 그대로 두고, 차트를 그리는 부분만 교체합니다. 비율 계산을 위해 `frame`에 비율 열을 더하는 것만 허용합니다.

## 허용하는 app.py 변경 (이것만)

1. 위 1번의 `STYLE` 상수와 `st.html` 한 줄, 모듈 설명 문장 수정
2. 위 2번의 도넛 3곳과 `donut()` 헬퍼
3. 색 상수 값 변경: `STATUS_STYLE`, `OVERLAP_STYLE`, `verdict_colors`, `bar()`의 기본 색
4. Altair 차트의 색·크기·모서리·범례 위치
5. `st.columns` 비율, `st.container(border=True)`로 감싸기, 제목 옆 아이콘 이모지 추가

그 외 변경은 하지 않습니다.
- API 호출, `client()` 사용, 버튼 동작, 화면 이동, `st.session_state` 키, 함수 이름·인자, 데이터 처리 로직을 바꾸지 않습니다.
- 화면 문구를 바꾸지 않습니다.
- `PAGES`의 순서·이름도 바꾸지 않습니다.

## 바꾸면 안 되는 것 (자동 점검이 이 문구로 화면을 찾습니다)

글자 하나라도 바뀌면 자동 점검이 실패합니다. 위치·크기·색은 바꿔도 됩니다.

| 종류 | 그대로 둘 것 |
|---|---|
| 입력칸 이름 | 이메일, 비밀번호, event_id, 질의, 공격 문장, 대화(세션) ID (선택), event_id로 바로 보기 |
| 메뉴 | 대시보드, 감사 상세, 경보, 규칙·정책, 보고서, 검증 챗, LAB ON/OFF 비교, 정규식 제안 |
| 버튼 | 로그인, 새로고침, 검증, 미리보기, PDF 생성, PDF 다운로드, OFF/ON 비교, 모든 기기 로그아웃, 💬 이 대화의 다른 이벤트 보기, 마지막 요청 감사 상세 보기, YES · 관찰 모드로 추가, NO, 차단으로 전환, 삭제 |
| 탭 | 이벤트 ID로 재현, 공격 문장 직접 입력 |
| 제목 (heading 요소 유지) | 관제 대시보드, **계층별 판정·처리 시간 비중**(반드시 `st.subheader`로 둠), 경보, 합성 검증 챗, 시험셋 일괄 비교, 정규식 제안 |
| 문구 | 요청(이벤트), OWASP 2025 분류 (룰 적중 수), 최신 50건 · 10초마다 자동 갱신, "상태 점검: …", "입력 단계: …", "서버에 로드된 버전", "가드레일 활성은 운영에서 변경할 수 없는 고정값입니다.", "LAB 환경 — 합성 데이터·미끼 비밀 전용입니다.", "🔓 OFF (가드레일 없음)", "🛡️ ON (규칙 + AI 판별)", "🛡️ 요청을 보안 정책에 따라 처리할 수 없습니다.", "status blocked · stage input · rule_ids …", "⚠️ 정상 질문인데 걸림(오탐 후보)" |

## 디자인 요구

- **반응형:** 화면 폭이 900px 미만이면 열이 한 줄로 쌓여도 읽을 수 있어야 합니다. 도넛은 `use_container_width=True`를 씁니다.
- **접근성:**
  - 글자 대비는 WCAG AA 이상이어야 합니다.
  - 키보드 포커스가 보여야 합니다(`:focus-visible`).
  - 상태를 색으로만 구분하지 않습니다. 이모지·글자를 함께 씁니다. 도넛도 범례 글자로 구분할 수 있어야 합니다.
- **애니메이션:** 쓰더라도 짧게 넣고, `@media (prefers-reduced-motion: reduce)`이면 끕니다.
- **다크 모드:** 지원하지 않아도 됩니다. 테마는 `base = "light"`를 유지합니다.

## 확인 방법 (작업 후 반드시)

1. **반영:** 저장소 루트에서 아래를 실행합니다. CSS 파일은 이미지에 복사되므로 고칠 때마다 다시 빌드해야 합니다.
   ```
   docker compose --env-file .env.lab build streamlit && docker compose --env-file .env.lab up -d streamlit
   ```
2. **화면:** `https://ops.example.internal:8443`에서 다음을 직접 봅니다. 브라우저 캐시 때문에 **Ctrl+F5**로 새로고침합니다.
   - 대시보드
   - 감사 상세: 입력 단계에서 차단된 event_id
   - 보고서 미리보기
   - LAB ON/OFF 비교
   - 정규식 제안
3. **보안 확인:**
   - `grep -n "st.html\|unsafe_allow_html\|components" frontend/ops/app.py` 결과가 **`st.html(f"<style>{STYLE}</style>")` 한 줄뿐**이어야 합니다.
   - `style.css`에 `@import`, `http`, `url(`이 없어야 합니다.
4. **자동 점검:** 저장소 README의 "브라우저 E2E (LAB 8443 기준)" 절 명령으로 `e2e_ops.py`, `e2e_lab.py`가 모두 통과해야 합니다. 쇼핑몰은 건드리지 않았어도 `e2e_web.py`도 한 번 돌립니다.
5. **브라우저 콘솔:** 오류가 없어야 합니다.

## 결과물

- 바꾼 파일 목록과 파일별 변경 요약
- 전후 비교 캡처: 대시보드, 감사 상세(도넛), 보고서 미리보기(도넛), 사이드바
- 3번 보안 확인 명령의 출력
- 자동 점검 3종 결과
