// Customer web (DES-004 SCR-C01~C06). History-API router, server values only, no HTML injection.
import * as api from "./api.js";
import { h, kst, krw, mount, renderAnswer, uuidv4 } from "./dom.js";

const app = document.getElementById("app");
const UUID = "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}";
const RETURN_TO = new RegExp(`^/(?:actions/${UUID}|cart|orders|settings/clients)?$`);
const STATUS_TEXT = { confirmed: "주문 확인", shipped: "배송 중", delivered: "배송 완료", cancelled: "취소 이력" };
const REASONS = {
  PRODUCT_UNAVAILABLE: "판매하지 않는 상품입니다.",
  OUT_OF_STOCK: "재고가 부족합니다.",
  NOT_IN_CART: "장바구니에 없는 상품입니다.",
  COUPON_NOT_AVAILABLE: "사용할 수 없는 쿠폰입니다.",
  MIN_SUBTOTAL_NOT_MET: "쿠폰 최소 주문 금액에 미달합니다.",
  NO_COUPON_APPLIED: "적용된 쿠폰이 없습니다.",
};

function navigate(path, replace = false) {
  history[replace ? "replaceState" : "pushState"]({}, "", path);
  route();
}

function link(path, label, extra = {}) {
  return h("a", {
    href: path,
    ...extra,
    onclick: (e) => {
      e.preventDefault();
      navigate(path);
    },
  }, label);
}

function notice(err) {
  if (!(err instanceof api.ApiError)) return "네트워크 오류가 발생했습니다. 다시 시도해 주세요.";
  const reason = err.reason && REASONS[err.reason] ? ` (${REASONS[err.reason]})` : "";
  const id = err.requestId ? ` · 문의번호 ${err.requestId.slice(0, 8)}` : "";
  return `${err.message}${reason}${id}`;
}

function errorBox(err) {
  return h("p", { class: "error", role: "alert", text: notice(err) });
}

function navLink(path, label) {
  const here = location.pathname === path || (path !== "/" && location.pathname.startsWith(path));
  return link(path, label, here ? { class: "active", "aria-current": "page" } : {});
}

function layout(...content) {
  const user = api.session.user;
  return [
    h("header", { class: "topbar" },
      h("div", { class: "brand" }, link("/", "GUARDRAIL FASHION"), h("small", {}, "AI SHOPPING ASSISTANT")),
      h("span", { class: "badge", title: "운영 환경에서는 보안 보호를 끌 수 없습니다" }, "🛡️ 보안 보호 활성"),
      user
        ? h("nav", { "aria-label": "주 메뉴" },
            navLink("/", "상품·AI"), navLink("/cart", "장바구니"), navLink("/orders", "주문"), navLink("/settings/clients", "연결"),
            h("button", { class: "link", onclick: onLogout }, "모든 기기 로그아웃"))
        : null),
    h("main", { id: "main", tabindex: "-1" }, ...content),
    h("footer", {}, h("div", { class: "inner" },
      h("span", {}, h("b", {}, "GUARDRAIL FASHION"), " · 입력·실행·출력 3단계 AI 보안 가드레일 적용"),
      h("span", {}, "AI 답변은 부정확할 수 있습니다. 상품·주문 정보와 변경 내용을 직접 확인해 주세요."))),
  ];
}

// Product illustrations live on this origin (CSP img-src 'self'); unknown SKUs get the default picture.
const CATEGORIES = [["TOP", "상의"], ["BTM", "하의"], ["OUT", "아우터"], ["SHO", "신발"], ["ACC", "잡화"], ["ELC", "디지털"]];

function categoryOf(sku) {
  const code = String(sku || "").split("-")[1];
  return CATEGORIES.find(([c]) => c === code)?.[1] || "기타";
}

// SKUs with their own illustration in /img/products/; any other product shows default.svg (no failed request).
const ARTWORK = new Set(["GF-ACC-001", "GF-ACC-002", "GF-BTM-001", "GF-BTM-002", "GF-ELC-001", "GF-ELC-002", "GF-OUT-001", "GF-OUT-002", "GF-SHO-001", "GF-TOP-001", "GF-TOP-002", "GF-TOP-003"]);

function productImage(sku, alt = "") {
  const safe = ARTWORK.has(sku) ? sku : "default";
  const img = h("img", { class: "thumb", src: `/img/products/${safe}.svg`, alt, loading: "lazy", width: 320, height: 320 });
  img.addEventListener("error", () => { img.src = "/img/products/default.svg"; }, { once: true });
  return img;
}

async function onLogout() {
  try {
    await api.logout();
  } catch {
    /* tokens are dropped locally either way */
  }
  sessionStorage.clear();
  navigate("/login", true);
}

// ------------------------------------------------------------------ SCR-C01 login / register

function loginView(params) {
  let mode = "login";
  const email = h("input", { id: "email", type: "email", autocomplete: "username", maxlength: 254, required: true });
  const password = h("input", { id: "password", type: "password", autocomplete: "current-password", maxlength: 128, required: true });
  const message = h("p", { class: "muted", "aria-live": "polite" });
  const submit = h("button", { type: "submit", class: "primary" }, "로그인");
  const tabs = h("div", { class: "tabs", role: "tablist" });
  const setMode = (next) => {
    mode = next;
    submit.textContent = next === "login" ? "로그인" : "계정 만들기";
    password.setAttribute("autocomplete", next === "login" ? "current-password" : "new-password");
    password.setAttribute("minlength", next === "login" ? 1 : 12);
    for (const b of tabs.children) b.setAttribute("aria-selected", String(b.dataset.mode === next));
  };
  tabs.append(
    h("button", { type: "button", role: "tab", "data-mode": "login", onclick: () => setMode("login") }, "로그인"),
    h("button", { type: "button", role: "tab", "data-mode": "register", onclick: () => setMode("register") }, "회원가입"),
  );
  const form = h("form", {
    class: "card narrow",
    onsubmit: async (e) => {
      e.preventDefault();
      submit.disabled = true;
      message.textContent = "";
      try {
        const addr = email.value.trim();
        if (mode === "register") {
          await api.register(addr, password.value);
          setMode("login");
          message.textContent = "계정을 만들었습니다. 로그인해 주세요.";
          return;
        }
        await api.login(addr, password.value);
        password.value = "";
        const target = params.get("return_to");
        navigate(target && RETURN_TO.test(target) ? target : "/", true);
      } catch (err) {
        message.textContent = notice(err);
      } finally {
        submit.disabled = false;
      }
    },
  },
    h("h1", {}, "AI 쇼핑 도우미"), tabs,
    h("label", { for: "email" }, "이메일"), email,
    h("label", { for: "password" }, "비밀번호 (회원가입 시 12자 이상)"), password,
    submit, message);
  setMode("login");
  const hero = h("div", { class: "auth-hero" },
    h("div", {}, h("div", { class: "kicker" }, "FW 2026 COLLECTION"),
      h("h1", {}, "찾고, 묻고, 고르세요.", h("br"), "AI 도우미가 함께합니다."),
      h("p", { class: "muted" }, "상품 추천부터 주문 조회, 장바구니 변경 제안까지.")),
    h("ul", {},
      h("li", {}, "질문과 답변을 AI 보안 가드레일이 검사합니다"),
      h("li", {}, "본인 주문·장바구니만 조회됩니다"),
      h("li", {}, "변경은 확인 화면에서 승인해야 적용됩니다")));
  return layout(h("div", { class: "auth" }, hero, form));
}

// ------------------------------------------------------------------ SCR-C02 products + chat

async function homeView() {
  const results = h("div", { class: "products", "aria-live": "polite" });
  const q = h("input", { id: "q", type: "search", maxlength: 100, placeholder: "상품명 또는 SKU 검색" });
  let items = [];
  let category = "전체";
  const chips = h("div", { class: "chips", role: "group", "aria-label": "카테고리" });
  const render = () => {
    const shown = category === "전체" ? items : items.filter((p) => categoryOf(p.sku) === category);
    mount(results, shown.length ? shown.map(productCard) : [h("p", { class: "empty" }, "검색 결과가 없습니다.")]);
    for (const b of chips.children) b.setAttribute("aria-pressed", String(b.dataset.cat === category));
  };
  for (const name of ["전체", ...CATEGORIES.map(([, n]) => n)]) {
    chips.append(h("button", { type: "button", "data-cat": name, onclick: () => { category = name; render(); } }, name));
  }
  const search = async () => {
    try {
      items = (await api.get(`/api/v1/products?limit=20&q=${encodeURIComponent(q.value.trim())}`)).data.items;
      render();
    } catch (err) {
      mount(results, errorBox(err));
    }
  };
  const searchForm = h("form", { class: "search", onsubmit: (e) => { e.preventDefault(); search(); } },
    h("label", { for: "q", class: "sr-only" }, "상품 검색"), q, h("button", { type: "submit" }, "검색"));
  search();
  const hero = h("div", { class: "hero" },
    h("div", { class: "kicker" }, "FW 2026 NEW ARRIVALS"),
    h("h1", {}, "이번 시즌, 무엇이든 AI에게 물어보세요"),
    h("p", {}, "사이즈·재고·쿠폰 확인부터 장바구니 담기까지. 모든 질문과 답변은 보안 가드레일이 검사합니다."),
    h("span", { class: "shield", "aria-hidden": "true" }, "🛡️"));
  return layout(hero, h("div", { class: "shop" },
    h("section", { "aria-labelledby": "products-title" },
      h("h2", { id: "products-title", class: "sr-only" }, "상품"),
      h("div", { class: "toolbar" }, chips, searchForm), results),
    await chatPanel()));
}

function productCard(p) {
  const qty = h("input", { type: "number", min: 1, max: 99, value: 1, "aria-label": `${p.name} 수량` });
  const soldOut = p.stock_count <= 0;
  return h("article", { class: "product" },
    productImage(p.sku),
    h("div", { class: "cat" }, categoryOf(p.sku)),
    h("h3", { text: p.name }),
    h("p", { class: "price" }, krw(p.price_krw)),
    h("p", { class: soldOut ? "stock soldout" : "stock" }, soldOut ? "품절" : `재고 ${p.stock_count}개`),
    h("div", { class: "row" }, qty,
      h("button", {
        disabled: soldOut,
        onclick: () => proposeChange("set_cart_item", { product_id: p.id, quantity: Number(qty.value) }),
      }, "장바구니 담기 제안")));
}

async function chatPanel() {
  const log = h("div", { class: "chat-log", role: "log", "aria-live": "polite" });
  const input = h("textarea", { id: "prompt", rows: 3, maxlength: 8000, placeholder: "무엇을 도와드릴까요?" });
  const counter = h("span", { class: "muted" }, "0/8000");
  const send = h("button", { type: "submit", class: "primary" }, "전송");
  input.addEventListener("input", () => {
    counter.textContent = `${[...input.value].length}/8000`;
  });
  let sessionId = sessionStorage.getItem("chat_session");
  const ensureSession = async () => {
    if (!sessionId) {
      const r = await api.post("/api/v1/sessions", {});
      sessionId = r.data.data.session_id;
      sessionStorage.setItem("chat_session", sessionId);
    }
    return sessionId;
  };
  const suggestions = h("div", { class: "suggest" }, h("p", {}, "이렇게 물어보세요"),
    ...SUGGESTIONS.map((text) => h("button", { type: "button", onclick: () => { input.value = text; input.focus(); } }, text)));
  log.append(suggestions);
  const bubble = (who, node, extra = "") => {
    suggestions.remove();
    log.append(h("div", { class: `bubble ${who} ${extra}` }, node));
    log.scrollTop = log.scrollHeight;
  };
  const form = h("form", {
    class: "chat-form",
    onsubmit: async (e) => {
      e.preventDefault();
      const prompt = input.value;
      if (!prompt.trim()) return;
      send.disabled = true; // one request per session at a time (SESSION_BUSY otherwise)
      bubble("me", h("p", { text: prompt }));
      input.value = "";
      counter.textContent = "0/8000";
      const stageText = h("span", {}, "요청을 보내는 중");
      const clock = h("span", {}, "");
      const steps = h("div", { class: "steps", "aria-hidden": "true" },
        ...["질문 검사", "답변 생성", "답변 검사"].map((name) => h("span", {}, name)));
      const waiting = h("div", { role: "status", "aria-live": "polite" },
        steps, h("p", { class: "muted small" }, stageText, clock));
      bubble("bot", waiting, "pending");
      const started = Date.now();
      const timer = setInterval(() => {
        clock.textContent = ` · ${Math.round((Date.now() - started) / 1000)}초`;
      }, 1000);
      try {
        const id = await ensureSession();
        const body = await api.streamChat("/api/v1/chat/completions", { session_id: id, prompt }, (p) => {
          stageText.textContent = stageLabel(p);
          const now = STAGE_STEP[p.stage] ?? 0;
          [...steps.children].forEach((s, i) => { s.className = i < now ? "done" : i === now ? "now" : ""; });
        });
        waiting.parentElement.remove();
        renderReply(bubble, body);
      } catch (err) {
        waiting.parentElement.remove();
        if (err.status === 404) sessionStorage.removeItem("chat_session");
        bubble("bot", errorBox(err), "error");
      } finally {
        clearInterval(timer);
        send.disabled = false;
        input.focus();
      }
    },
  }, h("label", { for: "prompt", class: "sr-only" }, "질문 입력"), input, h("div", { class: "row between" }, counter, send));
  const reset = h("button", {
    class: "link",
    onclick: () => {
      sessionStorage.removeItem("chat_session");
      sessionId = null;
      log.replaceChildren(suggestions);
    },
  }, "새 대화");
  return h("section", { class: "card chat", "aria-labelledby": "chat-title" },
    h("div", { class: "chat-head" },
      h("div", { class: "row between" }, h("h2", { id: "chat-title" }, "💬 AI 도우미"), reset),
      h("p", { class: "muted small" }, "🛡️ 질문·답변을 보안 검사합니다 · 개인정보를 가린 대화만 보관")),
    log, form);
}

const SUGGESTIONS = ["겨울 아우터 추천해줘", "내 쿠폰 뭐 있어?", "무선 마우스 장바구니에 1개 담아줘", "최근 주문 배송 상태 알려줘"];
const STAGE_STEP = { input_check: 0, generating: 1, tool: 1, output_check: 2 };

const TOOL_LABELS = {
  search_products: "상품 검색", list_orders: "주문 목록", get_order: "주문 상세", get_cart: "장바구니",
  list_coupons: "쿠폰", set_cart_item: "장바구니 변경 제안", remove_cart_item: "장바구니 삭제 제안",
  apply_coupon: "쿠폰 적용 제안", remove_coupon: "쿠폰 해제 제안",
};

// Server stage events (no text): each guardrail layer is shown as it runs.
function stageLabel(p) {
  if (p.stage === "input_check") return "① 질문 보안 검사 중";
  if (p.stage === "generating") return p.retry ? "② 답변을 다시 만드는 중" : "② 답변 생성 중";
  if (p.stage === "tool") return `② ${TOOL_LABELS[p.name] || "정보"} 조회·검사 중`;
  if (p.stage === "output_check") return "③ 답변 보안 검사 중";
  return "처리 중";
}

function renderReply(bubble, body) {
  if (body.status === "blocked") {
    bubble("bot", h("p", { text: body.content }), "blocked");
    return;
  }
  const node = h("div", {}, renderAnswer(body.content));
  if (body.status === "masked") node.append(h("p", { class: "tag" }, "🔒 개인정보 보호를 위해 일부 내용을 가렸습니다."));
  if (body.status === "confirmation_required" && body.action) {
    node.append(h("div", { class: "confirm-card" },
      h("p", {}, `확인 기한: ${kst(body.action.expires_at)}`),
      link(`/actions/${body.action.action_id}`, "변경 내용 확인하기", { class: "button" })));
  }
  bubble("bot", node, body.status);
}

async function proposeChange(tool_name, args) {
  try {
    const cart = await api.get("/api/v1/cart");
    const r = await api.post("/api/v1/actions", { tool_name, arguments: args, base_version: cart.data.version });
    navigate(`/actions/${r.data.data.action_id}`);
  } catch (err) {
    alertDialog(notice(err));
  }
}

function alertDialog(text) {
  const dialog = h("dialog", { class: "card", "aria-modal": "true" },
    h("p", { text }), h("button", { class: "primary", onclick: () => dialog.close() }, "확인"));
  dialog.addEventListener("close", () => dialog.remove());
  document.body.append(dialog);
  dialog.showModal();
}

// ------------------------------------------------------------------------ SCR-C03 cart

async function cartView() {
  let cart;
  let coupons;
  try {
    [cart, coupons] = await Promise.all([api.get("/api/v1/cart"), api.get("/api/v1/coupons")]);
  } catch (err) {
    return layout(errorBox(err));
  }
  const c = cart.data;
  const rows = c.items.map((item) => {
    const qty = h("input", { type: "number", min: 1, max: 99, value: item.quantity, "aria-label": `${item.name} 수량` });
    return h("tr", {},
      h("td", {}, h("div", { class: "cart-item" }, productImage(item.sku), h("span", { text: item.name }))), h("td", {}, krw(item.price_krw)),
      h("td", {}, qty, item.available ? null : h("span", { class: "tag warn" }, "구매 불가")),
      h("td", {},
        h("button", { onclick: () => proposeChange("set_cart_item", { product_id: item.product_id, quantity: Number(qty.value) }) }, "변경"),
        h("button", { class: "danger", onclick: () => proposeChange("remove_cart_item", { product_id: item.product_id }) }, "삭제")));
  });
  const usable = coupons.data.items.filter((x) => x.state === "available");
  const select = h("select", { id: "coupon", "aria-label": "보유 쿠폰" },
    h("option", { value: "" }, "쿠폰을 선택하세요"),
    ...usable.map((x) => h("option", { value: x.id, disabled: !x.eligible },
      `${x.code} · ${krw(x.discount_krw)} 할인 · ${krw(x.min_subtotal_krw)} 이상 · ~${kst(x.expires_at)}${x.eligible ? "" : " (조건 미충족)"}`)));
  return layout(h("section", { class: "card" },
    h("h1", {}, "장바구니"),
    c.items.length
      ? h("table", {}, h("thead", {}, h("tr", {}, h("th", {}, "상품"), h("th", {}, "단가"), h("th", {}, "수량"), h("th", {}, ""))), h("tbody", {}, rows))
      : h("div", { class: "empty" }, h("p", {}, "장바구니가 비어 있습니다."), link("/", "상품 보러 가기", { class: "button" })),
    h("h2", {}, "쿠폰"),
    c.coupon ? h("p", {}, `적용 쿠폰: ${c.coupon.code}`, c.coupon.reason ? ` (${REASONS[c.coupon.reason] || "현재 조건 미충족"})` : "",
      " ", h("button", { onclick: () => proposeChange("remove_coupon", {}) }, "해제 제안")) : null,
    usable.length
      ? h("div", { class: "row" }, select, h("button", { onclick: () => select.value && proposeChange("apply_coupon", { user_coupon_id: select.value }) }, "적용 제안"))
      : h("p", { class: "muted" }, "사용 가능한 쿠폰이 없습니다."),
    h("dl", { class: "totals" },
      h("dt", {}, "상품 합계"), h("dd", {}, krw(c.subtotal_krw)),
      h("dt", {}, "할인"), h("dd", {}, krw(c.discount_krw)),
      h("dt", {}, "예상 합계"), h("dd", { class: "strong" }, krw(c.total_krw))),
    h("p", { class: "muted small" }, "모든 변경은 확인 화면에서 승인한 뒤 적용됩니다. 장바구니 수량은 재고 예약이 아닙니다.")));
}

// ---------------------------------------------------------------- SCR-C04 change confirmation

async function actionView(actionId) {
  const area = h("section", { class: "card narrow" });
  const load = async () => {
    try {
      const a = (await api.get(`/api/v1/actions/${actionId}`)).data;
      mount(area, ...actionBody(a, load));
    } catch (err) {
      mount(area, h("h1", {}, "변경 내용 확인"), err.status === 404 ? h("p", {}, "요청을 찾을 수 없습니다.") : errorBox(err));
    }
  };
  await load();
  return layout(area);
}

function previewLines(p) {
  const lines = [];
  if (p.product) lines.push(["상품", `${p.product.name} (${krw(p.product.price_krw)})`]);
  if (p.quantity_before !== null && p.quantity_before !== undefined) lines.push(["수량", `${p.quantity_before}개 → ${p.quantity_after}개`]);
  lines.push(["쿠폰", p.coupon ? `${p.coupon.code} (${krw(p.coupon.discount_krw)} 할인)` : "없음"]);
  lines.push(["예상 합계", `${krw(p.total_before)} → ${krw(p.total_after)}`]);
  return lines;
}

function actionBody(a, reload) {
  const status = h("p", { "aria-live": "polite" });
  const p = a.preview || {};
  const parts = [
    h("h1", {}, "변경 내용 확인"),
    h("dl", { class: "totals" }, ...previewLines(p).flatMap(([k, v]) => [h("dt", {}, k), h("dd", {}, v)])),
    (p.notes || []).length ? h("p", { class: "tag warn" }, "이 변경으로 적용 중인 쿠폰 조건이 맞지 않아 쿠폰이 해제됩니다.") : null,
  ];
  if (a.state === "pending") {
    const keyName = `idem_${a.action_id}`;
    const confirmBtn = h("button", { class: "primary" }, "이 내용으로 변경");
    const cancelBtn = h("button", {}, "취소");
    confirmBtn.addEventListener("click", async () => {
      confirmBtn.disabled = cancelBtn.disabled = true;
      // The same key is reused for retries of this action, so a lost response never applies twice.
      let key = sessionStorage.getItem(keyName);
      if (!key) sessionStorage.setItem(keyName, (key = uuidv4()));
      try {
        await api.post(`/api/v1/actions/${a.action_id}/confirm`, {}, { "Idempotency-Key": key });
      } catch (err) {
        status.textContent = notice(err);
      }
      await reload();
    });
    cancelBtn.addEventListener("click", async () => {
      confirmBtn.disabled = cancelBtn.disabled = true;
      try {
        await api.post(`/api/v1/actions/${a.action_id}/cancel`, {});
      } catch (err) {
        status.textContent = notice(err);
      }
      await reload();
    });
    parts.push(h("p", {}, `확인 기한: ${kst(a.expires_at)} (서버 시각 기준)`), h("div", { class: "row between" }, cancelBtn, confirmBtn), status);
  } else {
    const text = {
      executed: "변경이 적용되었습니다.",
      cancelled: "취소된 요청입니다.",
      expired: "확인 시간이 지났습니다. 다시 요청해 주세요.",
      failed: "장바구니나 가격이 바뀌어 적용하지 않았습니다. 다시 요청해 주세요.",
    }[a.state];
    parts.push(h("p", { class: a.state === "executed" ? "ok" : "warn" }, text));
    if (a.state === "executed" && a.result) parts.push(h("p", {}, `현재 예상 합계: ${krw(a.result.total_krw)}`));
    parts.push(link("/cart", "장바구니로 이동", { class: "button" }));
  }
  return parts;
}

// ---------------------------------------------------------------------- SCR-C05 orders

async function ordersView(orderId) {
  try {
    if (orderId) {
      const o = (await api.get(`/api/v1/orders/${orderId}`)).data;
      return layout(h("section", { class: "card" },
        h("h1", {}, `주문 ${o.external_ref}`),
        h("p", {}, `${kst(o.placed_at)} · ${STATUS_TEXT[o.status] || o.status} · ${krw(o.total_krw)}`),
        h("table", {}, h("tbody", {}, o.items.map((i) => h("tr", {}, h("td", { text: i.name }), h("td", {}, `${i.quantity}개`), h("td", {}, krw(i.unit_price_krw)))))),
        link("/orders", "목록으로")));
    }
    const list = (await api.get("/api/v1/orders?limit=20")).data.items;
    return layout(h("section", { class: "card" }, h("h1", {}, "내 주문"),
      list.length
        ? h("table", {}, h("tbody", {}, list.map((o) => h("tr", {},
            h("td", {}, link(`/orders/${o.id}`, o.external_ref)), h("td", {}, kst(o.placed_at)),
            h("td", {}, STATUS_TEXT[o.status] || o.status), h("td", {}, krw(o.total_krw))))))
        : h("p", { class: "muted" }, "주문 내역이 없습니다."),
      h("p", { class: "muted small" }, "주문 조회만 가능합니다. 취소·결제는 고객센터를 이용해 주세요.")));
  } catch (err) {
    return layout(err.status === 404 ? h("p", {}, "주문을 찾을 수 없습니다.") : errorBox(err));
  }
}

// ------------------------------------------------------------- SCR-C06 AnythingLLM tokens

async function clientsView() {
  const listArea = h("div");
  const issued = h("div", { "aria-live": "polite" });
  const name = h("input", { id: "token-name", maxlength: 80, value: "내 데스크톱" });
  const load = async () => {
    try {
      const items = (await api.get("/api/v1/auth/client-tokens")).data.items;
      mount(listArea, items.length
        ? h("table", {}, h("tbody", {}, items.map((t) => h("tr", {},
            h("td", { text: t.name }), h("td", {}, t.scopes.join(", ")), h("td", {}, `~${kst(t.expires_at)}`),
            h("td", {}, { active: "사용 중", expired: "만료", revoked: "폐기" }[t.status]),
            h("td", {}, t.status === "active" ? h("button", { class: "danger", onclick: async () => { await api.del(`/api/v1/auth/client-tokens/${t.id}`); load(); } }, "폐기") : null)))))
        : h("p", { class: "muted" }, "발급한 연결 키가 없습니다."));
    } catch (err) {
      mount(listArea, errorBox(err));
    }
  };
  const issue = h("form", {
    class: "row",
    onsubmit: async (e) => {
      e.preventDefault();
      try {
        const r = (await api.post("/api/v1/auth/client-tokens", { name: name.value.trim() })).data.data;
        const value = h("code", { class: "secret" }, r.token);
        mount(issued, h("div", { class: "confirm-card" },
          h("p", { class: "strong" }, "이 키는 지금 한 번만 표시됩니다. AnythingLLM의 API Key 칸에 붙여 넣으세요."), value,
          h("div", { class: "row" },
            h("button", { onclick: () => navigator.clipboard.writeText(r.token) }, "복사"),
            h("button", { onclick: () => issued.replaceChildren() }, "확인·닫기"))));
        load();
      } catch (err) {
        mount(issued, errorBox(err));
      }
    },
  }, h("label", { for: "token-name" }, "이름"), name, h("button", { type: "submit", class: "primary" }, "연결 키 발급"));
  load();
  return layout(h("section", { class: "card" },
    h("h1", {}, "AnythingLLM 연결"),
    h("ol", {},
      h("li", {}, "AnythingLLM 설정 → LLM 제공자에서 Generic OpenAI를 선택합니다."),
      h("li", {}, `Base URL: ${location.origin}/v1`),
      h("li", {}, "Model: qwen3:8b · API Key: 아래에서 발급한 연결 키")),
    h("p", { class: "muted small" }, "연결 키는 30일간 유효하며 조회·질문·변경 제안만 할 수 있습니다. 변경 확인은 이 웹에서 합니다. 로그아웃하면 모든 연결 키도 무효가 됩니다."),
    issue, issued, h("h2", {}, "발급한 키"), listArea));
}

// ------------------------------------------------------------------------------ router

async function route() {
  const path = location.pathname;
  const params = new URLSearchParams(location.search);
  if (!api.session.signedIn) await api.refresh();
  if (path === "/login") return mount(app, loginView(params));
  if (!api.session.signedIn) return navigate(`/login?return_to=${encodeURIComponent(RETURN_TO.test(path) ? path : "/")}`, true);
  if (api.session.user?.role !== "customer") {
    await api.logout().catch(() => {});
    return navigate("/login", true);
  }
  const action = path.match(new RegExp(`^/actions/(${UUID})$`));
  const order = path.match(new RegExp(`^/orders/(${UUID})$`));
  let view;
  if (path === "/") view = await homeView();
  else if (path === "/cart") view = await cartView();
  else if (action) view = await actionView(action[1]);
  else if (path === "/orders") view = await ordersView();
  else if (order) view = await ordersView(order[1]);
  else if (path === "/settings/clients") view = await clientsView();
  else view = layout(h("p", {}, "페이지를 찾을 수 없습니다."), link("/", "처음으로"));
  mount(app, view);
  window.scrollTo(0, 0);
  document.getElementById("main")?.focus({ preventScroll: true }); // keyboard/screen-reader start point
}

window.addEventListener("popstate", route);
route();
