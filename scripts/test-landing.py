#!/usr/bin/env python3
"""Offline browser regressions for GitHub Pages. Requires Playwright."""
from contextlib import contextmanager
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
import os
from pathlib import Path
import threading
from urllib.parse import urlsplit

from playwright.sync_api import expect, sync_playwright

ROOT = Path(__file__).resolve().parent.parent


class QuietHandler(SimpleHTTPRequestHandler):
    def log_message(self, *args):
        pass


@contextmanager
def serve():
    handler = partial(QuietHandler, directory=str(ROOT))
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}/docs/"
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


def test_page(browser, url, scheme, width, height, output):
    context = browser.new_context(
        viewport={"width": width, "height": height}, color_scheme=scheme,
        reduced_motion="reduce", device_scale_factor=1,
    )
    page = context.new_page()
    errors, failures, external = [], [], []
    page.on("pageerror", lambda error: errors.append(str(error)))
    page.on("requestfailed", lambda req: failures.append(req.url))
    page.on("response", lambda res: failures.append(res.url) if res.status >= 400 else None)
    page.on("request", lambda req: external.append(req.url) if urlsplit(req.url).hostname != "127.0.0.1" else None)
    page.goto(url, wait_until="networkidle")
    expect(page.locator("h1")).to_be_visible()
    expect(page.locator(".hero-shot img")).to_be_visible()
    logos = page.locator(".chips.logos img")
    expect(logos).to_have_count(8)
    page.locator(".strip").scroll_into_view_if_needed()
    page.wait_for_function("[...document.querySelectorAll('.chips.logos img')].every(e => e.complete && e.naturalWidth > 0)")
    page.wait_for_function("document.querySelector('.hero-shot img').complete")
    assert page.locator(".hero-shot img").evaluate("e => e.currentSrc").endswith(
        "sm-secrets-dark.png" if scheme == "dark" else "sm-secrets.png"
    )
    assert page.locator(".hero-shot img").evaluate("e => e.naturalWidth") == 2560
    if width >= 1024:
        hero = page.locator("h1").evaluate("e => ({height:e.offsetHeight,line:parseFloat(getComputedStyle(e).lineHeight)})")
        assert hero["height"] / hero["line"] <= 2.1, hero
        assert page.locator(".hero-copy .cta-row").bounding_box()["y"] < height
    if output and width in (1440, 390):
        page.screenshot(path=str(output / f"hero-{scheme}-{width}.png"))

    page.get_by_role("button", name="Intel", exact=True).click()
    expect(page.locator("#download-code")).to_contain_text("'sm-darwin-amd64*'")
    expect(page.locator("#download-code")).to_contain_text("sm-darwin-amd64.sha256")
    expect(page.locator("#install-code")).to_contain_text("mv sm-darwin-amd64")
    expect(page.get_by_role("button", name="Intel", exact=True)).to_have_attribute("aria-pressed", "true")
    # Intercept clipboard writes to assert the precise copied text without an
    # OS clipboard permission or a real shell execution.
    page.evaluate("Object.defineProperty(navigator, 'clipboard', {configurable:true, value:{writeText:async text=>{window.copied=text;}}})")
    page.get_by_role("button", name="Copy Download and verify commands").click()
    expect(page.get_by_role("button", name="Copy Download and verify commands")).to_have_text("Copied")
    assert page.evaluate("window.copied") == page.locator("#download-code").text_content()
    assert "Copied" not in page.evaluate("window.copied")
    page.get_by_role("button", name="Apple Silicon", exact=True).click()
    expect(page.locator("#install-code")).to_contain_text("sm-darwin-arm64")

    page.locator(".architecture-details summary").click()
    expect(page.locator(".architecture-details")).to_have_attribute("open", "")
    page.locator(".architecture-details img").scroll_into_view_if_needed()
    page.wait_for_function("[...document.images].every(e=>e.complete && e.naturalWidth > 0)")
    page.locator(".architecture-details summary").click()
    # A denied clipboard permission falls back to selecting the real text.
    page.evaluate("() => { navigator.clipboard.writeText = async () => { throw new Error('denied'); }; }")
    page.get_by_role("button", name="Copy Install commands").click()
    expect(page.get_by_role("button", name="Copy Install commands")).to_have_text("Selected")
    assert page.evaluate("getSelection().toString()") == page.locator("#install-code").text_content()

    assert page.evaluate("document.documentElement.scrollWidth <= innerWidth"), f"page overflows at {width}"
    if output and width in (1440, 390):
        page.evaluate("getSelection().removeAllRanges()")
        page.evaluate("scrollTo(0,0)")
        page.screenshot(path=str(output / f"page-{scheme}-{width}.png"), full_page=True)
    assert not errors, errors
    assert not failures, failures
    assert not external, external
    context.close()


def run():
    output = os.environ.get("SM_LANDING_SCREENSHOTS")
    output = Path(output) if output else None
    if output:
        output.mkdir(parents=True, exist_ok=True)
    with serve() as url, sync_playwright() as pw:
        browser = pw.chromium.launch()
        try:
            for scheme in ("light", "dark"):
                for width, height in ((1440, 900), (1280, 800), (1024, 768), (768, 1024), (390, 844), (320, 740)):
                    test_page(browser, url, scheme, width, height, output)
            context = browser.new_context(java_script_enabled=False, color_scheme="dark")
            page = context.new_page()
            page.goto(url, wait_until="networkidle")
            expect(page.locator(".hero-shot img")).to_be_visible()
            expect(page.locator("#download-code")).to_contain_text("sha256")
            context.close()
        finally:
            browser.close()
    print("PASS: 12 theme/viewport combinations, images, CPU selector, copy/fallback, architecture, no JS, zero external requests")


if __name__ == "__main__":
    run()
