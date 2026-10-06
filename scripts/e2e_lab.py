"""Browser check of the LAB ON/OFF page (DES-004 SCR-L01) on the lab stack (port 8443)."""

import os
import sys

from playwright.sync_api import expect, sync_playwright

OPS = "https://ops.example.internal:8443"


def main() -> int:
    errors: list[str] = []
    with sync_playwright() as p:
        browser = p.chromium.launch(args=[f"--host-resolver-rules=MAP ops.example.internal {os.environ['EDGE_IP']}"])
        page = browser.new_context(ignore_https_errors=True).new_page()
        page.on("pageerror", lambda e: errors.append(str(e)))
        page.set_default_timeout(30_000)
        page.goto(OPS)
        page.get_by_label("이메일").fill(os.environ["OPS_EMAIL"])
        page.get_by_label("비밀번호").fill(os.environ["OPS_PASSWORD"])
        page.get_by_role("button", name="로그인").click()
        page.get_by_text("LAB ON/OFF 비교", exact=True).click()
        expect(page.get_by_text("LAB 환경 — 합성 데이터·미끼 비밀 전용입니다.")).to_be_visible()
        expect(page.get_by_text("OFF 노출 (공격)")).to_be_visible()
        expect(page.get_by_text("ON 노출 (공격)")).to_be_visible()
        expect(page.get_by_role("button", name="CSV 다운로드")).to_be_visible()
        page.screenshot(path="/out/lab-page.png", full_page=True)
        print("lab page rendered; screenshot saved")
        browser.close()
    print(f"page errors={len(errors)}", *errors, sep="\n")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
