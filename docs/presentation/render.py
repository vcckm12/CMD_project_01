"""Render presentation.html to PDF with Chromium (Mermaid diagrams are drawn before printing).

    docker run --rm -v "<repo>/docs/presentation:/p" ag-e2e python /p/render.py
"""

import sys
from pathlib import Path

from playwright.sync_api import sync_playwright

HERE = Path(__file__).resolve().parent
OUT = HERE / "AI_가드레일_챗봇_발표자료.pdf"


def main() -> int:
    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page()
        page.goto((HERE / "presentation.html").as_uri())
        page.wait_for_function("window.__ready === true", timeout=60_000)
        error = page.evaluate("window.__mermaidError || null")
        if error:
            print("mermaid error:", error)
            return 1
        page.pdf(path=str(OUT), format="A4", print_background=True,
                 margin={"top": "16mm", "bottom": "16mm", "left": "15mm", "right": "15mm"},
                 display_header_footer=True, header_template="<span></span>",
                 footer_template='<div style="width:100%;text-align:center;font-size:8px;color:#888">'
                 '<span class="pageNumber"></span> / <span class="totalPages"></span></div>')  # fmt: skip
        browser.close()
    print(f"saved {OUT.name} ({OUT.stat().st_size // 1024} KB)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
