"""ACTION-01~04 and chat-proposed changes (DES-002 §6, DES-006 §5.3). Maps to T-14~T-17."""

import os
import threading
import time
import uuid

import psycopg
import pytest

from tests.conftest import _dsn, bearer, register_and_login

ACTIONS = "/api/v1/actions"


def superuser():
    return psycopg.connect(_dsn("postgres", os.environ["TEST_SUPERUSER_PASSWORD"]), autocommit=True)


def new_product(price=10000, stock=10, name="테스트 셔츠") -> str:
    with superuser() as conn:
        return str(conn.execute(
            "INSERT INTO commerce.products (sku, name, price_krw, stock_count) VALUES (%s, %s, %s, %s) RETURNING id",
            (f"T-{uuid.uuid4().hex[:10]}", name, price, stock),
        ).fetchone()[0])  # fmt: skip


def grant_coupon(user_id: str, discount=3000, minimum=15000) -> str:
    with superuser() as conn:
        coupon = conn.execute(
            "INSERT INTO commerce.coupons (code, discount_krw, min_subtotal_krw, expires_at)"
            " VALUES (%s, %s, %s, now() + interval '7 days') RETURNING id",
            (f"T{uuid.uuid4().hex[:10].upper()}", discount, minimum),
        ).fetchone()[0]
        return str(conn.execute(
            "INSERT INTO commerce.user_coupons (user_id, coupon_id) VALUES (%s, %s) RETURNING id", (user_id, coupon)
        ).fetchone()[0])  # fmt: skip


def outbox_status(request_id: str) -> str | None:
    with superuser() as conn:
        row = conn.execute(
            "SELECT payload->>'status' FROM audit.outbox WHERE payload->>'request_id' = %s", (request_id,)
        ).fetchone()
    return row[0] if row else None


@pytest.fixture
def shopper(client):
    _, data = register_and_login(client)
    return {"token": data["access_token"], "user_id": data["user"]["id"]}


def cart(client, shopper) -> dict:
    return client.get("/api/v1/cart", headers=bearer(shopper["token"])).json()["data"]


def propose(client, shopper, tool, arguments, base_version=None, token=None):
    version = cart(client, shopper)["version"] if base_version is None else base_version
    return client.post(
        ACTIONS,
        json={"tool_name": tool, "arguments": arguments, "base_version": version},
        headers=bearer(token or shopper["token"]),
    )


def confirm(client, shopper, action_id, key=None, body=None):
    headers = bearer(shopper["token"])
    if key is not False:
        headers["Idempotency-Key"] = str(uuid.uuid4()) if key is None else key
    return client.post(f"{ACTIONS}/{action_id}/confirm", json=body if body is not None else {}, headers=headers)


# ------------------------------------------------------------------------- happy path


def test_propose_then_confirm_once(client, shopper):
    product = new_product(price=12000)
    r = propose(client, shopper, "set_cart_item", {"product_id": product, "quantity": 2})
    assert r.status_code == 201
    data = r.json()["data"]
    assert data["state"] == "pending" and data["confirmation_url"].endswith(data["action_id"])
    assert data["preview"]["quantity_before"] == 0 and data["preview"]["total_after"] == 24000
    assert cart(client, shopper)["items"] == []  # nothing changes before confirmation
    assert outbox_status(r.headers["x-request-id"]) == "confirmation_required"

    key = str(uuid.uuid4())
    done = confirm(client, shopper, data["action_id"], key)
    assert done.status_code == 200 and done.json()["data"]["state"] == "executed"
    assert done.json()["data"]["result"]["total_krw"] == 24000
    after = cart(client, shopper)
    assert after["version"] == 1 and after["items"][0]["quantity"] == 2
    assert outbox_status(done.headers["x-request-id"]) == "success"

    # Replays (same or new key, lost response) return the stored result; the cart does not change again.
    assert confirm(client, shopper, data["action_id"], key).json()["data"]["result"] == done.json()["data"]["result"]
    assert confirm(client, shopper, data["action_id"]).status_code == 200
    assert cart(client, shopper)["version"] == 1


def test_concurrent_confirms_execute_once(client, shopper):
    product = new_product()
    action_id = propose(client, shopper, "set_cart_item", {"product_id": product, "quantity": 3}).json()["data"][
        "action_id"
    ]
    results = []

    def hit():
        results.append(confirm(client, shopper, action_id).status_code)

    threads = [threading.Thread(target=hit) for _ in range(5)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert set(results) <= {200, 409} and 200 in results
    assert cart(client, shopper)["version"] == 1


def test_remove_and_coupon_flow(client, shopper):
    product = new_product(price=20000)
    coupon = grant_coupon(shopper["user_id"], discount=3000, minimum=15000)
    for tool, args in (
        ("set_cart_item", {"product_id": product, "quantity": 1}),
        ("apply_coupon", {"user_coupon_id": coupon}),
    ):
        action = propose(client, shopper, tool, args).json()["data"]
        assert confirm(client, shopper, action["action_id"]).status_code == 200
    state = cart(client, shopper)
    assert state["discount_krw"] == 3000 and state["total_krw"] == 17000
    # Removing the item drops the subtotal below the coupon minimum: the coupon is released in the same change.
    action = propose(client, shopper, "remove_cart_item", {"product_id": product}).json()["data"]
    assert any(n.startswith("COUPON_WILL_BE_REMOVED") for n in action["preview"]["notes"])
    assert confirm(client, shopper, action["action_id"]).status_code == 200
    state = cart(client, shopper)
    assert state["items"] == [] and state["coupon"] is None and state["version"] == 3


# ------------------------------------------------------------------------ rejections


@pytest.mark.parametrize(
    ("tool", "args", "reason"),
    [
        ("set_cart_item", {"product_id": str(uuid.uuid4()), "quantity": 1}, "PRODUCT_UNAVAILABLE"),
        ("remove_cart_item", {"product_id": "PRODUCT"}, "NOT_IN_CART"),
        ("apply_coupon", {"user_coupon_id": str(uuid.uuid4())}, "COUPON_NOT_AVAILABLE"),
        ("remove_coupon", {}, "NO_COUPON_APPLIED"),
        ("set_cart_item", {"product_id": "PRODUCT", "quantity": 100}, "INVALID_ARGUMENTS"),
        ("set_cart_item", {"product_id": "PRODUCT", "quantity": 1, "user_id": "x"}, "INVALID_ARGUMENTS"),
        ("set_cart_item", {"product_id": "PRODUCT", "quantity": 1, "price_krw": 1}, "INVALID_ARGUMENTS"),
        ("delete_all", {}, "UNKNOWN_TOOL"),
    ],
)
def test_invalid_proposals(client, shopper, tool, args, reason):
    product = new_product()
    args = {k: (product if v == "PRODUCT" else v) for k, v in args.items()}
    r = propose(client, shopper, tool, args)
    assert r.status_code == 422 and r.json()["error"]["reason"] == reason


def test_out_of_stock_and_min_subtotal(client, shopper):
    r = propose(client, shopper, "set_cart_item", {"product_id": new_product(stock=1), "quantity": 2})
    assert r.json()["error"]["reason"] == "OUT_OF_STOCK"
    r = propose(client, shopper, "apply_coupon", {"user_coupon_id": grant_coupon(shopper["user_id"], minimum=50000)})
    assert r.json()["error"]["reason"] == "MIN_SUBTOTAL_NOT_MET"


def test_other_users_coupon_is_not_revealed(client, shopper):
    _, other = register_and_login(client)
    r = propose(client, shopper, "apply_coupon", {"user_coupon_id": grant_coupon(other["user"]["id"], minimum=0)})
    assert r.status_code == 422 and r.json()["error"]["reason"] == "COUPON_NOT_AVAILABLE"


def test_stale_base_version_at_proposal(client, shopper):
    r = propose(client, shopper, "set_cart_item", {"product_id": new_product(), "quantity": 1}, base_version=7)
    assert r.status_code == 409 and r.json()["error"]["code"] == "ACTION_STALE"


def test_cart_changed_before_confirm_fails_action(client, shopper):
    p1, p2 = new_product(), new_product()
    first = propose(client, shopper, "set_cart_item", {"product_id": p1, "quantity": 1}).json()["data"]
    second = propose(client, shopper, "set_cart_item", {"product_id": p2, "quantity": 1}).json()["data"]
    assert confirm(client, shopper, first["action_id"]).status_code == 200
    r = confirm(client, shopper, second["action_id"])
    assert r.status_code == 409 and r.json()["error"]["code"] == "ACTION_STALE"
    assert (
        client.get(f"{ACTIONS}/{second['action_id']}", headers=bearer(shopper["token"])).json()["data"]["state"]
        == "failed"
    )
    assert confirm(client, shopper, second["action_id"]).json()["error"]["code"] == "ACTION_TERMINAL"


def test_price_change_before_confirm_fails_action(client, shopper):
    product = new_product(price=10000)
    action = propose(client, shopper, "set_cart_item", {"product_id": product, "quantity": 1}).json()["data"]
    with superuser() as conn:
        conn.execute("UPDATE commerce.products SET price_krw = 15000 WHERE id = %s", (product,))
    r = confirm(client, shopper, action["action_id"])
    assert r.status_code == 409 and cart(client, shopper)["items"] == []


def test_expired_action(client, shopper):
    client.app.state.settings.__dict__["action_ttl_seconds"] = 1  # frozen settings; test-only override
    action = propose(client, shopper, "set_cart_item", {"product_id": new_product(), "quantity": 1}).json()["data"]
    time.sleep(1.2)
    assert (
        client.get(f"{ACTIONS}/{action['action_id']}", headers=bearer(shopper["token"])).json()["data"]["state"]
        == "expired"
    )
    r = confirm(client, shopper, action["action_id"])
    assert r.status_code == 410 and r.json()["error"]["code"] == "ACTION_EXPIRED"
    assert confirm(client, shopper, action["action_id"]).status_code == 410  # now stored as expired


def test_idempotency_key_bound_to_one_action(client, shopper):
    a = propose(client, shopper, "set_cart_item", {"product_id": new_product(), "quantity": 1}).json()["data"]
    key = str(uuid.uuid4())
    assert confirm(client, shopper, a["action_id"], key).status_code == 200
    b = propose(client, shopper, "set_cart_item", {"product_id": new_product(), "quantity": 1}).json()["data"]
    r = confirm(client, shopper, b["action_id"], key)
    assert r.status_code == 409 and r.json()["error"]["code"] == "IDEMPOTENCY_CONFLICT"


@pytest.mark.parametrize(("key", "body"), [(False, {}), ("x" * 129, {}), ("", {}), (None, {"quantity": 99})])
def test_confirm_contract(client, shopper, key, body):
    action = propose(client, shopper, "set_cart_item", {"product_id": new_product(), "quantity": 1}).json()["data"]
    assert confirm(client, shopper, action["action_id"], key, body).status_code == 422


def test_cancel(client, shopper):
    action = propose(client, shopper, "set_cart_item", {"product_id": new_product(), "quantity": 1}).json()["data"]
    url = f"{ACTIONS}/{action['action_id']}/cancel"
    r = client.post(url, json={}, headers=bearer(shopper["token"]))
    assert r.status_code == 200 and r.json()["data"]["state"] == "cancelled"
    assert client.post(url, json={}, headers=bearer(shopper["token"])).json()["data"]["state"] == "cancelled"
    assert confirm(client, shopper, action["action_id"]).json()["error"]["code"] == "ACTION_TERMINAL"
    assert cart(client, shopper)["items"] == []


def test_executed_cannot_be_cancelled(client, shopper):
    action = propose(client, shopper, "set_cart_item", {"product_id": new_product(), "quantity": 1}).json()["data"]
    confirm(client, shopper, action["action_id"])
    r = client.post(f"{ACTIONS}/{action['action_id']}/cancel", json={}, headers=bearer(shopper["token"]))
    assert r.status_code == 409 and cart(client, shopper)["items"]


def test_other_user_cannot_see_or_confirm(client, shopper):
    action = propose(client, shopper, "set_cart_item", {"product_id": new_product(), "quantity": 1}).json()["data"]
    _, other = register_and_login(client)
    stranger = {"token": other["access_token"]}
    assert client.get(f"{ACTIONS}/{action['action_id']}", headers=bearer(stranger["token"])).status_code == 404
    assert confirm(client, stranger, action["action_id"]).status_code == 404
    assert (
        client.post(f"{ACTIONS}/{action['action_id']}/cancel", json={}, headers=bearer(stranger["token"])).status_code
        == 404
    )


def test_client_token_can_propose_but_not_confirm(client, shopper):
    token = client.post("/api/v1/auth/client-tokens", json={"name": "d"}, headers=bearer(shopper["token"])).json()[
        "data"
    ]["token"]
    r = propose(client, shopper, "set_cart_item", {"product_id": new_product(), "quantity": 1}, token=token)
    assert r.status_code == 201
    action_id = r.json()["data"]["action_id"]
    assert (
        client.post(
            f"{ACTIONS}/{action_id}/confirm", json={}, headers={**bearer(token), "Idempotency-Key": "k"}
        ).status_code
        == 403
    )
    assert client.get(f"{ACTIONS}/{action_id}", headers=bearer(token)).status_code == 403


def test_audit_failure_rolls_back_the_change(client, shopper, monkeypatch):
    import app.shop.actions as module

    action = propose(client, shopper, "set_cart_item", {"product_id": new_product(), "quantity": 1}).json()["data"]

    async def broken(conn, envelope):
        raise RuntimeError("outbox down")

    monkeypatch.setattr(module, "persist_event", broken)
    r = confirm(client, shopper, action["action_id"])
    assert r.status_code == 503
    monkeypatch.undo()
    assert cart(client, shopper)["items"] == []
    assert (
        client.get(f"{ACTIONS}/{action['action_id']}", headers=bearer(shopper["token"])).json()["data"]["state"]
        == "pending"
    )


# ------------------------------------------------------------------ chat → proposal


def tool_call(name, arguments):
    return {"content": "", "tool_calls": [{"function": {"name": name, "arguments": arguments}}]}


def test_claimed_change_without_tool_is_regenerated(client, shopper, fake_model):
    product = new_product(price=9000, name="흉내 셔츠")
    session = client.post("/api/v1/sessions", json={}, headers=bearer(shopper["token"])).json()["data"]["session_id"]
    fake = "장바구니 변경 확인이 필요합니다: 흉내 셔츠 수량 0개 → 1개. 확인 화면에서 승인해야 적용됩니다."
    fake_model.replies = [{"content": fake}, tool_call("set_cart_item", {"product_id": product, "quantity": 1})]
    r = client.post("/api/v1/chat/completions", json={"session_id": session, "prompt": "흉내 셔츠 1개 담아줘"},
                    headers=bearer(shopper["token"]))  # fmt: skip
    body = r.json()
    assert body["status"] == "confirmation_required" and body["action"] is not None
    retry = fake_model.chat_calls[-1]["messages"]
    assert retry[-1]["role"] == "system" and "변경 도구를 호출" in retry[-1]["content"]


def test_claimed_change_twice_falls_back(client, shopper, fake_model):
    session = client.post("/api/v1/sessions", json={}, headers=bearer(shopper["token"])).json()["data"]["session_id"]
    fake_model.replies = [{"content": "장바구니에 셔츠를 담았습니다."}, {"content": "쿠폰을 적용했습니다!"}]
    r = client.post("/api/v1/chat/completions", json={"session_id": session, "prompt": "셔츠 담아줘"},
                    headers=bearer(shopper["token"]))  # fmt: skip
    body = r.json()
    assert body["status"] == "success" and body["action"] is None and "변경 제안을 만들지 못했습니다" in body["content"]
    assert len(fake_model.chat_calls) == 2 and cart(client, shopper)["items"] == []


def test_ordinary_answer_is_not_regenerated(client, shopper, fake_model):
    session = client.post("/api/v1/sessions", json={}, headers=bearer(shopper["token"])).json()["data"]["session_id"]
    fake_model.replies = [{"content": "장바구니에 담으시려면 상품명과 수량을 알려 주세요."}]
    r = client.post("/api/v1/chat/completions", json={"session_id": session, "prompt": "어떻게 담아?"},
                    headers=bearer(shopper["token"]))  # fmt: skip
    assert r.json()["status"] == "success" and len(fake_model.chat_calls) == 1


def test_chat_change_tool_creates_pending_action_only(client, shopper, fake_model):
    product = new_product(price=9000, name="채팅 셔츠")
    session = client.post("/api/v1/sessions", json={}, headers=bearer(shopper["token"])).json()["data"]["session_id"]
    fake_model.replies = [tool_call("set_cart_item", {"product_id": product, "quantity": 2})]
    r = client.post("/api/v1/chat/completions", json={"session_id": session, "prompt": "채팅 셔츠 2개 담아줘"},
                    headers=bearer(shopper["token"]))  # fmt: skip
    body = r.json()
    assert r.status_code == 200 and body["status"] == "confirmation_required"
    assert "채팅 셔츠 수량 0개 → 2개" in body["content"] and body["action"]["confirmation_url"].endswith(
        body["action"]["action_id"]
    )
    assert cart(client, shopper)["items"] == []
    assert confirm(client, shopper, body["action"]["action_id"]).status_code == 200
    assert cart(client, shopper)["items"][0]["quantity"] == 2


def test_chat_two_change_tools_blocked(client, shopper, fake_model):
    product = new_product()
    session = client.post("/api/v1/sessions", json={}, headers=bearer(shopper["token"])).json()["data"]["session_id"]
    fake_model.replies = [{"content": "", "tool_calls": [
        {"function": {"name": "set_cart_item", "arguments": {"product_id": product, "quantity": 1}}},
        {"function": {"name": "remove_coupon", "arguments": {}}},
    ]}]  # fmt: skip
    r = client.post(
        "/api/v1/chat/completions",
        json={"session_id": session, "prompt": "둘 다 해줘"},
        headers=bearer(shopper["token"]),
    )
    assert r.status_code == 403 and r.json()["guardrail"]["stage"] == "execution"
    with superuser() as conn:
        assert (
            conn.execute("SELECT count(*) FROM commerce.actions WHERE user_id = %s", (shopper["user_id"],)).fetchone()[
                0
            ]
            == 0
        )


def test_chat_invalid_change_is_explained_by_model(client, shopper, fake_model):
    session = client.post("/api/v1/sessions", json={}, headers=bearer(shopper["token"])).json()["data"]["session_id"]
    fake_model.replies = [tool_call("remove_coupon", {}), {"content": "적용된 쿠폰이 없어요."}]
    r = client.post(
        "/api/v1/chat/completions",
        json={"session_id": session, "prompt": "쿠폰 빼줘"},
        headers=bearer(shopper["token"]),
    )
    assert r.status_code == 200 and r.json()["status"] == "success"
    assert '"NO_COUPON_APPLIED"' in fake_model.chat_calls[1]["messages"][-1]["content"]


def test_compat_proposal_includes_link(client, shopper, fake_model):
    token = client.post("/api/v1/auth/client-tokens", json={"name": "d"}, headers=bearer(shopper["token"])).json()[
        "data"
    ]["token"]
    fake_model.replies = [tool_call("set_cart_item", {"product_id": new_product(), "quantity": 1})]
    body = {"model": "qwen3:8b", "messages": [{"role": "user", "content": "담아줘"}]}
    r = client.post("/v1/chat/completions", json=body, headers=bearer(token))
    assert r.headers["x-guardrail-status"] == "confirmation_required"
    assert "확인 링크: https://shop.example.internal/actions/" in r.json()["choices"][0]["message"]["content"]
