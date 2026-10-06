"""Per-user API client for the ops dashboard (DES-005 §1.1, D-17).

One instance lives in each user's st.session_state; nothing is shared between users or cached
globally. Calls go to the API over the internal network with X-Edge-Channel: ops. The refresh and
CSRF cookies are Secure cookies, so they are kept in memory here and attached explicitly.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any

import requests

BACKEND_URL = os.environ.get("BACKEND_URL", "http://api:8000")
OPS_ORIGIN = os.environ.get("OPS_ORIGIN", "https://ops.example.internal")
TIMEOUT = (3, 300)


@dataclass
class ApiFailure(Exception):
    status: int
    code: str
    message: str
    details: list[str] | None = None
    request_id: str | None = None

    def __str__(self) -> str:
        rid = f" · 문의번호 {self.request_id[:8]}" if self.request_id else ""
        return f"{self.message} ({self.code}){rid}"


class OpsClient:
    def __init__(self) -> None:
        self.http = requests.Session()
        self.http.trust_env = False
        self.access_token: str | None = None
        self.user: dict | None = None
        self._cookies: dict[str, str] = {}

    @property
    def headers(self) -> dict[str, str]:
        h = {"X-Edge-Channel": "ops", "Origin": OPS_ORIGIN, "Accept": "application/json"}
        if self.access_token:
            h["Authorization"] = f"Bearer {self.access_token}"
        return h

    def _keep_cookies(self, response: requests.Response) -> None:
        for name in ("guardrail_refresh", "guardrail_csrf"):
            if name in response.cookies:
                self._cookies[name] = response.cookies[name]

    def _raise(self, response: requests.Response) -> None:
        try:
            err = response.json().get("error", {})
        except ValueError:
            err = {}
        raise ApiFailure(
            response.status_code,
            err.get("code", "UNKNOWN"),
            err.get("message", "요청을 처리하지 못했습니다."),
            err.get("details"),
            response.headers.get("x-request-id"),
        )

    def login(self, email: str, password: str) -> dict:
        r = self.http.post(f"{BACKEND_URL}/api/v1/auth/login", json={"email": email, "password": password},
                           headers=self.headers, timeout=TIMEOUT)  # fmt: skip
        if not r.ok:
            self._raise(r)
        self._keep_cookies(r)
        data = r.json()["data"]
        self.access_token, self.user = data["access_token"], data["user"]
        return self.user

    def _refresh(self) -> bool:
        if "guardrail_refresh" not in self._cookies:
            return False
        r = self.http.post(f"{BACKEND_URL}/api/v1/auth/refresh",
                           headers={**self.headers, "X-CSRF-Token": self._cookies.get("guardrail_csrf", "")},
                           cookies=self._cookies, timeout=TIMEOUT)  # fmt: skip
        if not r.ok:
            self.logout_local()
            return False
        self._keep_cookies(r)
        self.access_token = r.json()["data"]["access_token"]
        return True

    def request(self, method: str, path: str, *, json: Any = None, params: dict | None = None, raw: bool = False):
        for attempt in range(2):
            r = self.http.request(method, f"{BACKEND_URL}{path}", json=json, params=params, headers=self.headers,
                                  timeout=TIMEOUT)  # fmt: skip
            if r.status_code == 401 and attempt == 0 and r.json().get("error", {}).get("code") == "TOKEN_EXPIRED":
                if self._refresh():
                    continue
            if r.status_code == 403 and path.endswith("/chat/completions"):
                return r.json()  # a blocked verification answer is a normal result here
            if not r.ok:
                self._raise(r)
            return r.content if raw else r.json()
        self._raise(r)

    def get(self, path: str, **params):
        return self.request("GET", path, params={k: v for k, v in params.items() if v not in (None, "")})["data"]

    def post(self, path: str, body: Any = None):
        return self.request("POST", path, json=body if body is not None else {})

    def logout(self) -> None:
        try:
            self.request("POST", "/api/v1/auth/logout")
        except (ApiFailure, requests.RequestException):
            pass
        self.logout_local()

    def logout_local(self) -> None:
        self.access_token, self.user, self._cookies = None, None, {}
        self.http.cookies.clear()
