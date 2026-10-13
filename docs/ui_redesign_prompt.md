# 디자인 개편 작업 지시 (다른 AI에게 그대로 전달)

아래 내용을 디자인을 맡길 AI에게 그대로 붙여 넣으세요. 저장소 전체를 볼 수 있는 코딩 AI(파일을 읽고 고칠 수 있는 도구)를 전제로 합니다.

---

## 역할과 목표

당신은 웹 UI 디자이너 겸 프론트엔드 개발자입니다. 이 저장소의 **쇼핑몰 웹**과 **관제 대시보드** 두 화면의 **디자인만** 개선해 주세요. 기능·동작·문구·데이터 흐름은 하나도 바꾸지 않습니다.

- 서비스: "GUARDRAIL FASHION" — 패션 쇼핑몰 + AI 쇼핑 도우미. 질문과 답변을 AI 보안 가드레일이 검사합니다.
- 원하는 분위기: 세련된 패션 쇼핑몰(쇼핑몰), 신뢰감 있는 보안 관제 화면(대시보드). 두 화면은 같은 브랜드처럼 보이게 색과 톤을 맞춥니다.
- 현재 색 기준: 먹색 `#111827`, 샌드 `#f6f2ec`, 보안 초록 `#047857`, 차단 빨강 `#b91c1c`, 주의 주황 `#b45309`. 바꿔도 되지만 상태 색의 의미(초록=정상, 빨강=차단, 주황=가림)는 유지합니다.

## 손대도 되는 파일

| 화면 | 파일 | 허용 범위 |
|---|---|---|
| 쇼핑몰 | `frontend/shop/css/style.css` | **자유롭게** (주 작업 파일) |
| 쇼핑몰 | `frontend/shop/img/` | 그림 추가·교체 가능 (SVG/PNG/WebP, 저장소 안 파일만) |
| 쇼핑몰 | `frontend/shop/js/app.js` | 요소에 **class 추가**, 장식용 래퍼 요소 추가만. 아래 '바꾸면 안 되는 것'은 그대로 |
| 대시보드 | `frontend/ops/.streamlit/config.toml` | 테마 자유 |
| 대시보드 | `frontend/ops/app.py` | 색 상수(`STATUS_STYLE`, `OVERLAP_STYLE`, `VERDICTS` 색), 차트 모양(Altair 색·크기·모서리), `st.columns` 비율·`st.container(border=True)` 배치, 아이콘 이모지 |

그 외 파일(`backend/`, `deployment/`, `scripts/`, `docker-compose.yml`, `frontend/shop/js/api.js`, `frontend/shop/js/dom.js`, `frontend/ops/ops_client.py`)은 **수정 금지**입니다.

## 절대 지킬 것 (보안·동작)

1. **외부 리소스 금지.** 쇼핑몰은 보안 헤더 `Content-Security-Policy: default-src 'self'; img-src 'self'; style-src 'self'; script-src 'self'`로 운영됩니다.
   - 구글 폰트·CDN·외부 이미지 URL을 쓰면 브라우저가 막습니다. 글꼴은 시스템 글꼴 스택(`"Pretendard", "Apple SD Gothic Neo", "Malgun Gothic", "Noto Sans KR", sans-serif`)을 씁니다. 웹폰트가 꼭 필요하면 파일을 `frontend/shop/` 안에 넣고 `@font-face`로 같은 출처에서 불러옵니다.
   - **인라인 스타일 금지**: HTML의 `style="…"` 속성, `<style>` 태그, JS의 `el.style.xxx =`는 CSP에 막힙니다. 모든 스타일은 `style.css`에 클래스로 작성합니다.
2. **HTML 문자열 삽입 금지.** `innerHTML`, `insertAdjacentHTML`, `outerHTML`, `document.write`를 쓰지 않습니다. 요소는 기존 `h()` 함수로 만듭니다. (AI 답변·상품명은 공격자가 조작할 수 있는 텍스트라 반드시 텍스트로만 넣어야 합니다.)
3. **대시보드도 HTML 렌더링 금지.** `unsafe_allow_html=True`, `st.html`, `st.components`를 쓰지 않습니다. Streamlit 테마·컨테이너·마크다운 색 문법(`:red[...]`)·Altair 차트로만 꾸밉니다.
4. **API 호출, 이벤트 처리, 화면 이동, `st.session_state` 키, 함수 이름·인자, 데이터 처리 로직을 바꾸지 않습니다.**

## 바꾸면 안 되는 것 (자동 점검이 이 문구·요소로 화면을 찾습니다)

글자 하나라도 바꾸면 자동 점검이 실패합니다. 위치·크기·색은 바꿔도 됩니다.

**쇼핑몰**

| 종류 | 그대로 둘 것 |
|---|---|
| id | `#email`, `#password`, `#q`, `#prompt`, `#main`, `#coupon`, `#token-name` |
| class | `article.product`, `.thumb`(상품 그림), `.bubble`과 상태 class(`me`, `bot`, `pending`, `success`, `masked`, `blocked`, `error`, `confirmation_required`), `.secret`, `table` 요소 |
| 버튼 글자 | 로그인, 계정 만들기, 검색, 장바구니 담기 제안, 전송, 이 내용으로 변경, 연결 키 발급, 확인·닫기, 모든 기기 로그아웃 |
| 링크 글자 | 상품·AI, 장바구니, 주문, 연결, 장바구니로 이동 |
| 탭 | 로그인 / 회원가입 (`role="tab"`) |
| 제목 | 변경 내용 확인, 내 주문 |
| 문구 | "계정을 만들었습니다", "장바구니가 비어 있습니다.", "변경이 적용되었습니다.", "N개 → M개" 형식, 처리 단계 문구의 "검사 중", "🛡️ 요청을 보안 정책에 따라 처리할 수 없습니다." |

**대시보드**

| 종류 | 그대로 둘 것 |
|---|---|
| 입력칸 이름 | 이메일, 비밀번호, event_id, 질의, 공격 문장, 대화(세션) ID (선택), event_id로 바로 보기 |
| 메뉴 | 대시보드, 감사 상세, 경보, 규칙·정책, 보고서, 검증 챗, LAB ON/OFF 비교 |
| 버튼 | 로그인, 새로고침, 검증, 미리보기, PDF 생성, PDF 다운로드, OFF/ON 비교, 모든 기기 로그아웃, 💬 이 대화의 다른 이벤트 보기 |
| 탭 | 이벤트 ID로 재현, 공격 문장 직접 입력 |
| 제목·문구 | 관제 대시보드, 계층별 판정·처리 시간 비중, 경보, 합성 검증 챗, 시험셋 일괄 비교, 요청(이벤트), OWASP 2025 분류 (룰 적중 수), 최신 50건 · 10초마다 자동 갱신, "상태 점검: …", "입력 단계: …", "서버에 로드된 버전", "가드레일 활성은 운영에서 변경할 수 없는 고정값입니다.", "LAB 환경 — 합성 데이터·미끼 비밀 전용입니다.", "🔓 OFF (가드레일 없음)", "🛡️ ON (규칙 + AI 판별)", "status blocked · stage input · rule_ids …" |

## 디자인 요구

- **반응형:** 900px 미만에서 한 열로 쌓입니다(쇼핑몰은 `@media (max-width: 899px)` 유지).
- **접근성:** 글자 대비 WCAG AA 이상, 키보드 포커스가 보이게(`:focus-visible`), 상태를 색으로만 구분하지 않기(아이콘·글자 함께).
- **채팅 처리 단계:** 기다리는 20~50초 동안 "질문 검사 → 답변 생성 → 답변 검사" 단계 칩(`.steps span.done / .now`)이 잘 보이게 다듬어 주세요. 시연의 핵심 장면입니다.
- **차단 표시:** 차단된 답변(`.bubble.blocked`)은 정상 답변과 한눈에 구분되게.
- **애니메이션:** 쓰더라도 짧고 은은하게. `prefers-reduced-motion`이면 끕니다.

## 확인 방법 (작업 후 반드시)

1. 화면 확인: 쇼핑몰 `https://shop.example.internal:8443`, 대시보드 `https://ops.example.internal:8443`. 쇼핑몰은 파일 저장 후 새로고침(Ctrl+F5)하면 바로 반영됩니다. 대시보드는 `docker compose --env-file .env.lab build streamlit && docker compose --env-file .env.lab up -d streamlit` 후 반영됩니다.
2. 브라우저 콘솔에 오류·CSP 위반이 없어야 합니다.
3. 자동 점검 3종이 모두 통과해야 합니다. 저장소 README의 "브라우저 E2E (LAB 8443 기준)" 절의 명령을 그대로 실행합니다(`e2e_web.py`, `e2e_ops.py`, `e2e_lab.py`). 하나라도 실패하면 '바꾸면 안 되는 것'을 건드렸는지 확인합니다.

## 결과물

- 바꾼 파일 목록과 각 파일에서 바꾼 점 요약
- 쇼핑몰(상품 목록·채팅 대기 중·차단 답변·장바구니·로그인)과 대시보드(대시보드·감사 상세·LAB 비교) 전후 비교 캡처
- 자동 점검 3종 결과
