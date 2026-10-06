"""Ops dashboard (DES-004 SCR-O01~O06). Runs behind the ops Nginx host on the management network.

Never renders HTML: answers and summaries are shown with st.text/st.dataframe, and no call uses
unsafe_allow_html. Each user's API client lives in st.session_state only.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, time, timedelta
from zoneinfo import ZoneInfo

import pandas as pd
import streamlit as st

from ops_client import ApiFailure, OpsClient

KST = ZoneInfo("Asia/Seoul")
STATUSES = ["success", "blocked", "masked", "confirmation_required", "error"]

st.set_page_config(page_title="AI 가드레일 관제", page_icon="🛡️", layout="wide")


def client() -> OpsClient:
    if "client" not in st.session_state:
        st.session_state.client = OpsClient()
    return st.session_state.client


def kst(iso: str | None) -> str:
    return datetime.fromisoformat(iso).astimezone(KST).strftime("%Y-%m-%d %H:%M:%S") if iso else ""


def fail(err: Exception) -> None:
    st.error(str(err) if isinstance(err, ApiFailure) else "API에 연결하지 못했습니다.")
    if isinstance(err, ApiFailure) and err.details:
        st.code("\n".join(err.details))


# ---------------------------------------------------------------------------- SCR-O01 login


def login_page() -> None:
    st.title("🛡️ AI 가드레일 관제")
    st.caption("관리망 전용 · 운영자/관리자 계정만 로그인할 수 있습니다. 계정은 내부 관리 명령으로 발급합니다.")
    with st.form("login"):
        email = st.text_input("이메일")
        password = st.text_input("비밀번호", type="password")
        if st.form_submit_button("로그인", type="primary"):
            try:
                client().login(email.strip(), password)
                st.rerun()
            except Exception as err:  # noqa: BLE001
                fail(err)


# ------------------------------------------------------------------------- shared filters


def period_filter(key: str, max_days: int = 90) -> tuple[str, str]:
    today = datetime.now(KST).date()
    c1, c2 = st.columns(2)
    start = c1.date_input("시작일 (KST)", today - timedelta(days=1), key=f"{key}-from")
    end = c2.date_input("종료일 (KST, 포함)", today, key=f"{key}-to")
    begin = datetime.combine(start, time.min, KST)
    finish = datetime.combine(end + timedelta(days=1), time.min, KST)
    if finish - begin > timedelta(days=max_days):
        st.warning(f"최대 {max_days}일까지 조회할 수 있습니다.")
    return begin.astimezone(UTC).isoformat(), finish.astimezone(UTC).isoformat()


def alert_banner() -> None:
    try:
        alerts = client().get("/api/v1/alerts")["items"]
    except Exception:  # noqa: BLE001 - the banner never blocks the page
        return
    critical = [a for a in alerts if a["severity"] == "critical"]
    if critical:
        st.error(f"🚨 미확인 critical 경보 {len(critical)}건: 경보 메뉴에서 확인하세요.")
    elif alerts:
        st.warning(f"⚠️ 미확인 경보 {len(alerts)}건")


# ---------------------------------------------------------------------- SCR-O02 dashboard


def dashboard() -> None:
    st.header("관제 대시보드")
    start, end = period_filter("dash")
    c1, c2 = st.columns(2)
    session = (
        c1.text_input(
            "세션 ID (선택)", key="dash-session", help="이벤트 목록의 '세션 ID' 칸 값입니다. event_id와 다릅니다."
        ).strip()
        or None
    )
    status = c2.selectbox("상태", ["(전체)", *STATUSES], key="dash-status")

    @st.fragment(run_every=10)
    def live_stats() -> None:
        try:
            s = client().get("/api/v1/audit/stats", **{"from": start, "to": end, "session_id": session})
            ready = client().request("GET", "/api/v1/health/ready")["data"]
        except Exception as err:  # noqa: BLE001
            fail(err)
            return
        cols = st.columns(6)
        cols[0].metric("요청(이벤트)", s["total"])
        for col, key, label in zip(cols[1:], STATUSES, ["정상", "차단", "정화", "승인 대기", "오류"], strict=True):
            col.metric(label, s["status_counts"][key])
        st.caption(f"기준 {kst(s['as_of'])} · 적재 지연 {s['ingestion_lag_seconds']}초 · 10초마다 갱신")
        a, b = st.columns(2)
        with a:
            st.subheader("상태별 이벤트 수")
            st.bar_chart(pd.Series(s["status_counts"]))
        with b:
            st.subheader("OWASP 2025 분류 (룰 적중 수)")
            if s["category_counts"]:
                st.bar_chart(pd.Series(s["category_counts"]))
            else:
                st.info("적중한 룰이 없습니다.")
        p95 = s["latency_p95_ms"]
        st.caption(f"서버 처리 시간 P95: {p95:.0f} ms (모델 생성 포함)" if p95 is not None else "서버 처리 시간: 데이터 없음")
        checks = ready["checks"]
        st.caption("상태 점검: " + " · ".join(f"{'✅' if ok else '❌'} {name}" for name, ok in checks.items()))

    live_stats()
    st.subheader("이벤트")
    events_table(start, end, session, None if status == "(전체)" else status)


def events_table(start: str, end: str, session: str | None, status: str | None) -> None:
    key = (start, end, session, status)
    if st.session_state.get("events_key") != key:
        st.session_state.events_key, st.session_state.events_pages = key, 1
    _events_list(start, end, session, status)


@st.fragment(run_every=10)
def _events_list(start: str, end: str, session: str | None, status: str | None) -> None:
    def fetch(cursor: str | None) -> dict | None:
        try:
            return client().get("/api/v1/audit/events", **{"from": start, "to": end, "session_id": session,
                                                           "status": status, "cursor": cursor, "limit": 50})  # fmt: skip
        except Exception as err:  # noqa: BLE001
            fail(err)
            return None

    c1, c2 = st.columns([1, 5])
    if c1.button("새로고침"):
        st.session_state.events_pages = 1
    # The first page follows new events (every 10 s); paging past it pauses refresh until 새로고침.
    if st.session_state.events_pages == 1:
        page = fetch(None)
        if page is not None:
            st.session_state.events, st.session_state.events_cursor = page["items"], page["next_cursor"]
        c2.caption("최신 50건 · 10초마다 자동 갱신")
    else:
        c2.caption("이전 이벤트를 보는 중이라 자동 갱신을 멈췄습니다. 최신 목록은 새로고침을 누르세요.")
    if st.session_state.get("events_cursor") and st.button("더 보기"):
        page = fetch(st.session_state.events_cursor)
        if page is not None:
            st.session_state.events += page["items"]
            st.session_state.events_cursor = page["next_cursor"]
            st.session_state.events_pages += 1
    rows = st.session_state.get("events", [])
    if not rows:
        st.info("이 조건의 이벤트가 없습니다.")
        return
    frame = pd.DataFrame([{"시각(KST)": kst(e["occurred_at"]), "source": e["source"], "status": e["status"],
                           "stage": e["stage"], "total_ms": e["total_ms"], "요약": e["summary_redacted"],
                           "event_id": e["event_id"], "세션 ID": e["session_id"] or ""} for e in rows])  # fmt: skip
    st.dataframe(frame, hide_index=True, use_container_width=True)
    st.caption("event_id는 감사 상세 메뉴에, 세션 ID는 위 '세션 ID' 필터나 보고서에 넣으면 그 대화의 이벤트만 봅니다.")


# ----------------------------------------------------------------------- SCR-O03 detail


def event_detail() -> None:
    st.header("감사 이벤트 상세")
    event_id = st.text_input("event_id").strip()
    if not event_id:
        return
    try:
        e = client().get(f"/api/v1/audit/events/{event_id}")
    except Exception as err:  # noqa: BLE001
        fail(err)
        return
    meta = {k: e[k] for k in ("event_id", "request_id", "session_id", "actor_id", "source", "api_path", "model",
                              "status", "stage", "ruleset_version")}  # fmt: skip
    meta["occurred_at (KST)"] = kst(e["occurred_at"])
    st.table(pd.Series(meta, name="값").astype(str))
    st.write(f"input {e['input_ms']} ms · output {e['output_ms']} ms · total {e['total_ms']} ms")
    st.subheader("마스킹 요약")
    st.text(e["summary_redacted"])
    st.subheader("룰 적중")
    st.dataframe(pd.DataFrame(e["rule_hits"]), hide_index=True) if e["rule_hits"] else st.caption("없음")
    st.subheader("Tool 실행")
    st.dataframe(pd.DataFrame(e["tool_executions"]), hide_index=True) if e["tool_executions"] else st.caption("없음")
    st.caption("원문 입력·답변은 저장하지 않으므로 볼 수 없습니다. 관리자는 고객 승인을 대신할 수 없습니다.")


# ------------------------------------------------------------------------------- alerts


def alerts_page() -> None:
    st.header("경보")
    st.caption("judge_unavailable: 모델 서버 점검 · suspicious_input_repeat: 같은 입력 반복 실패(지연 공격 의심) · "
               "outbox_dead: 감사 적재 실패. 확인 처리는 상황을 조치했다는 기록이며 원문은 제공되지 않습니다.")  # fmt: skip
    try:
        open_alerts = client().get("/api/v1/alerts")["items"]
    except Exception as err:  # noqa: BLE001
        fail(err)
        return
    if not open_alerts:
        st.success("미확인 경보가 없습니다.")
    for a in open_alerts:
        with st.container(border=True):
            st.write(f"**{a['severity'].upper()} · {a['kind']}** · {a['occurrences']}회 · "
                     f"최초 {kst(a['first_seen_at'])} · 최근 {kst(a['last_seen_at'])}")  # fmt: skip
            st.text(a["detail"] + (f" · 입력 지문 {a['fingerprint']}" if a["fingerprint"] else ""))
            if st.button("확인 처리", key=f"ack-{a['id']}"):
                try:
                    client().post(f"/api/v1/alerts/{a['id']}/acknowledge")
                    st.rerun()
                except Exception as err:  # noqa: BLE001
                    fail(err)
    with st.expander("확인된 경보"):
        try:
            done = client().get("/api/v1/alerts", state="acknowledged")["items"]
            st.dataframe(pd.DataFrame([{"kind": a["kind"], "횟수": a["occurrences"], "확인": kst(a["acknowledged_at"]),
                                        "확인자": a["acknowledged_by"]} for a in done]), hide_index=True)  # fmt: skip
        except Exception as err:  # noqa: BLE001
            fail(err)


# ---------------------------------------------------------------------- SCR-O04 rules


def rules_page() -> None:
    st.header("규칙·정책")
    st.info("🛡️ 가드레일 활성은 운영에서 변경할 수 없는 고정값입니다.")
    admin = client().user["role"] == "admin"
    try:
        listing = client().get("/api/v1/rulesets")
    except Exception as err:  # noqa: BLE001
        fail(err)
        return
    sets = listing["items"]
    active = next((s for s in sets if s["state"] == "active"), None)
    st.dataframe(pd.DataFrame([{"label": s["version_label"], "state": s["state"], "checksum": (s["checksum"] or "")[:12],
                                "게시(KST)": kst(s["activated_at"]), "id": s["id"]} for s in sets]), hide_index=True)  # fmt: skip
    st.caption(f"서버에 로드된 버전: {listing['loaded_version']}")
    choice = st.selectbox("버전 선택", sets, format_func=lambda s: f"{s['version_label']} ({s['state']})")
    if not choice:
        return
    detail = client().get(f"/api/v1/rulesets/{choice['id']}")
    rules = pd.DataFrame(detail["rules"])
    editable = admin and detail["state"] == "draft"
    edited = st.data_editor(rules, disabled=not editable, hide_index=True, use_container_width=True,
                            key=f"rules-{choice['id']}") if editable else st.dataframe(rules, hide_index=True)  # fmt: skip
    policy_text = st.text_area("정책(JSON, 더 엄격한 값만 허용)", json.dumps(detail["policy"], ensure_ascii=False),
                               disabled=not editable)  # fmt: skip
    if not admin:
        st.caption("operator는 조회만 할 수 있습니다.")
        return
    if detail["state"] == "draft":
        c1, c2 = st.columns(2)
        if c1.button("draft 저장"):
            try:
                body = {
                    "rules": json.loads(edited.to_json(orient="records")),
                    "policy": json.loads(policy_text or "{}"),
                }
                for r in body["rules"]:
                    r["pattern"] = r.get("pattern") or None
                    r["marker"] = r.get("marker") or None
                client().request("PUT", f"/api/v1/rulesets/{choice['id']}", json=body)
                st.success("저장했습니다.")
            except (ValueError, ApiFailure) as err:
                fail(err)
        if c2.button("검증"):
            try:
                client().post(f"/api/v1/rulesets/{choice['id']}/validate")
                st.success("검증을 통과했습니다. 이제 내용은 변경할 수 없습니다.")
                st.rerun()
            except Exception as err:  # noqa: BLE001
                fail(err)
    else:
        with st.form("clone"):
            label = st.text_input("새 draft 이름", value=f"{choice['version_label']}-next")
            if st.form_submit_button("복제하여 draft 만들기"):
                try:
                    client().post("/api/v1/rulesets", {"parent_id": choice["id"], "version_label": label})
                    st.success("draft를 만들었습니다.")
                    st.rerun()
                except Exception as err:  # noqa: BLE001
                    fail(err)
    if detail["state"] in ("validated", "retired"):
        action = "publish" if detail["state"] == "validated" else "rollback"
        with st.form("publish"):
            st.write(f"후보 **{detail['version_label']}** · checksum `{(detail['checksum'] or '')[:12]}` · "
                     f"현재 active `{(active or {}).get('version_label')}` · 룰 {len(detail['rules'])}개")  # fmt: skip
            password = st.text_input("비밀번호 재확인", type="password")
            sure = st.checkbox("이 버전을 운영에 적용합니다")
            if st.form_submit_button("게시" if action == "publish" else "이 버전으로 롤백", type="primary"):
                if not sure:
                    st.warning("확인란을 선택해 주세요.")
                else:
                    try:
                        client().post(f"/api/v1/rulesets/{choice['id']}/{action}",
                                      {"password": password, "expected_active_id": (active or {}).get("id")})  # fmt: skip
                        st.success("적용했습니다.")
                        st.rerun()
                    except Exception as err:  # noqa: BLE001
                        fail(err)


# ---------------------------------------------------------------------- SCR-O05 report


def report_page() -> None:
    st.header("세션 보고서")
    start, end = period_filter("report", max_days=31)
    session = (
        st.text_input("세션 ID (선택)", key="report-session", help="대시보드 이벤트 목록의 '세션 ID' 칸 값입니다.").strip()
        or None
    )
    if st.button("미리보기"):
        try:
            st.session_state.report_preview = client().get("/api/v1/audit/stats", **{"from": start, "to": end,
                                                                                    "session_id": session})  # fmt: skip
        except Exception as err:  # noqa: BLE001
            fail(err)
    preview = st.session_state.get("report_preview")
    if preview:
        st.write(f"이벤트 {preview['total']}건 · 적재 지연 {preview['ingestion_lag_seconds']}초 · 기준 {kst(preview['as_of'])}")
        st.dataframe(pd.DataFrame([preview["status_counts"]]), hide_index=True)
        if st.button("PDF 생성"):
            try:
                pdf = client().request("GET", "/api/v1/audit/report", params={k: v for k, v in
                                       {"from": start, "to": end, "session_id": session, "format": "pdf"}.items() if v},
                                       raw=True)  # fmt: skip
                st.download_button("PDF 다운로드", pdf, file_name=f"security-report-{datetime.now(KST):%Y%m%d}.pdf",
                                   mime="application/pdf")  # fmt: skip
            except Exception as err:  # noqa: BLE001
                fail(err)
    st.caption("합성 시험의 방어율과 운영 이벤트의 차단 비율은 같은 값이 아닙니다.")


# --------------------------------------------------------------------- SCR-O06 test chat


def test_chat() -> None:
    st.header("합성 검증 챗")
    st.warning("운영 보안 보호 활성 상태입니다. 실제 고객 주문·개인정보·키를 입력하지 말고 합성 데이터만 사용하세요.")
    if st.button("새 검증 세션") or "test_session" not in st.session_state:
        try:
            st.session_state.test_session = client().post("/api/v1/sessions")["data"]["session_id"]
            st.session_state.test_log = []
        except Exception as err:  # noqa: BLE001
            fail(err)
            return
    with st.form("test-chat", clear_on_submit=True):
        prompt = st.text_area("질의", max_chars=8000)
        sent = st.form_submit_button("검증", type="primary")
    if sent and prompt.strip():
        with st.spinner("검사·추론 중…"):
            try:
                body = client().request("POST", "/api/v1/chat/completions",
                                        json={"session_id": st.session_state.test_session, "prompt": prompt})  # fmt: skip
                st.session_state.test_log.insert(0, (prompt, body))
            except Exception as err:  # noqa: BLE001
                fail(err)
    for prompt, body in st.session_state.get("test_log", []):
        with st.container(border=True):
            st.text(f"질의: {prompt}")
            st.text(f"응답: {body['content']}")
            g, t = body["guardrail"], body["timing"]
            st.caption(f"status {body['status']} · stage {g['stage']} · rule_ids {', '.join(g['rule_ids']) or '-'} · "
                       f"ruleset {(g['ruleset_version'] or '')[:8]} · input {t['input_ms']} ms · output {t['output_ms']} ms · "
                       f"total {t['total_ms']:.0f} ms · request {body['request_id']}")  # fmt: skip


# ----------------------------------------------------------------- SCR-L01 lab A/B (lab only)

LAYERS = {"input_rules": "입력 규칙", "input_judge": "입력 AI 판별", "output_rules": "출력 규칙",
          "output_judge": "출력 AI 판별", "none": "통과", "error": "오류"}  # fmt: skip


def lab_available() -> bool:
    if "lab_available" not in st.session_state:
        try:
            client().get("/api/v1/lab/status")
            st.session_state.lab_available = True
        except Exception:  # noqa: BLE001 - production returns 404: no lab menu
            st.session_state.lab_available = False
    return st.session_state.lab_available


def exposed(e: dict) -> str:
    parts = [
        name
        for key, name in (("secret", "미끼 비밀"), ("pii", "합성 개인정보"), ("markup", "스크립트·외부 이미지"))
        if e.get(key)
    ]
    return ", ".join(parts) if parts else "노출 없음"


def lab_page() -> None:
    st.error("🧪 LAB 환경 — 합성 데이터·미끼 비밀 전용입니다. 운영 환경이 아닙니다.")
    st.header("가드레일 ON/OFF 비교")
    st.caption(
        "같은 문장을 실제 모델에 OFF(가드레일 없음)와 ON(규칙+AI 판별)으로 각각 보내고, "
        "사용자에게 보이는 답변에서 미끼 비밀·합성 개인정보·스크립트 노출을 비교합니다. "
        "인증·본인 데이터 조회 제한은 OFF에서도 유지됩니다."
    )
    with st.form("lab-run"):
        c1, c2 = st.columns(2)
        dataset = c1.text_input("시험셋", "lab_ab_v1")
        limit = c2.number_input("최대 사례 수 (0 = 전체)", min_value=0, max_value=200, value=0)
        if st.form_submit_button("A/B 실행", type="primary"):
            try:
                body = {"dataset": dataset} | ({"limit": int(limit)} if limit else {})
                st.session_state.lab_run = client().post("/api/v1/lab/ab-runs", body)["data"]["run_id"]
            except Exception as err:  # noqa: BLE001
                fail(err)
    runs = client().get("/api/v1/lab/status")["runs"]
    if not runs:
        st.info("아직 실행한 비교가 없습니다.")
        return
    ids = [r["run_id"] for r in runs]
    current = st.session_state.get("lab_run", ids[-1])
    chosen = st.selectbox("실행", ids, index=ids.index(current) if current in ids else len(ids) - 1)

    @st.fragment(run_every=5)
    def run_view() -> None:
        run = client().get(f"/api/v1/lab/ab-runs/{chosen}")
        st.progress(run["done"] / max(run["total"], 1), text=f"{run['state']} · {run['done']}/{run['total']}")
        s = run["summary"]
        cols = st.columns(4)
        cols[0].metric("OFF 노출 (공격)", f"{s['off_exposed']}/{s['attacks']}")
        cols[1].metric("ON 노출 (공격)", f"{s['on_exposed']}/{s['attacks']}")
        cols[2].metric("ON 차단·마스킹", s["on_blocked_or_masked"])
        cols[3].metric("정상 질문 오차단 (ON)", f"{s['benign_blocked_on']}/{s['benign']}")
        st.bar_chart(pd.Series({LAYERS[k]: v for k, v in s["stopped_by"].items()}, name="막은 계층"))
        rows = [{"사례": r["case_id"], "분류": r["category"], "구분": r["label"], "OFF 결과": exposed(r["off_exposure"]),
                 "ON 결과": f"{r['on_status']}" + (f"/{r['on_stage']}" if r["on_stage"] else ""),
                 "ON 노출": exposed(r["on_exposure"]), "막은 계층": LAYERS.get(r["stopped_by"], r["stopped_by"]),
                 "rule_ids": ", ".join(r["on_rule_ids"]), "OFF ms": r["off_ms"], "ON ms": r["on_ms"]}
                for r in run["results"]]  # fmt: skip
        if rows:
            frame = pd.DataFrame(rows)
            st.dataframe(frame, hide_index=True, use_container_width=True)
            st.download_button("CSV 다운로드", frame.to_csv(index=False).encode("utf-8-sig"),
                               file_name=f"lab-ab-{chosen[:8]}.csv", mime="text/csv")  # fmt: skip
        st.caption("OFF 응답 원문은 화면에 표시하지 않고 노출 판정만 보여 줍니다. LAB 결과는 운영 탐지율이 아닙니다.")

    run_view()


# ------------------------------------------------------------------------------ main

PAGES = {"대시보드": dashboard, "감사 상세": event_detail, "경보": alerts_page, "규칙·정책": rules_page,
         "보고서": report_page, "검증 챗": test_chat}  # fmt: skip

if client().user is None:
    login_page()
else:
    with st.sidebar:
        st.write(f"**{client().user['email']}** ({client().user['role']})")
        st.success("🛡️ 보안 보호 활성")
        if client().user["role"] == "admin" and lab_available():
            PAGES["LAB ON/OFF 비교"] = lab_page
        page = st.radio("메뉴", list(PAGES), label_visibility="collapsed")
        if st.button("모든 기기 로그아웃"):
            client().logout()
            st.session_state.clear()
            st.rerun()
    alert_banner()
    PAGES[page]()
