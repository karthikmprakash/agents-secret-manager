#!/usr/bin/env python3
"""Refresh documentation screenshots from the real UI with dummy data only.

Requires Playwright (the same setup as scripts/test-ui.py). No real Keychain,
vault, provider credentials, or installed harness settings are accessed.
"""
import os
from pathlib import Path
import signal
import subprocess

from playwright.sync_api import expect, sync_playwright

ROOT = Path(__file__).resolve().parent.parent
ASSETS = ROOT / "docs" / "assets"


def capture(url):
    with sync_playwright() as pw:
        browser = pw.chromium.launch()
        try:
            context = browser.new_context(
                viewport={"width": 1280, "height": 800}, device_scale_factor=2,
                color_scheme="light", reduced_motion="reduce",
            )
            page = context.new_page()
            page.goto(url, wait_until="networkidle")
            assert page.request.post(url.split("?")[0] + "api/initialize", data={}).ok
            entries = [
                ("R2_ACCESS_KEY_ID", "demo-access-key-not-real", "cloudflare", True),
                ("R2_SECRET_ACCESS_KEY", "demo-secret-key-not-real", "cloudflare", True),
                ("R2_ENDPOINT", "https://demo.r2.cloudflarestorage.com", "cloudflare", False),
                ("OPENAI_API_KEY", "demo-openai-key-not-real", "openai", True),
                ("OPENAI_MODEL", "demo-model", "openai", False),
                ("STRIPE_API_KEY", "demo-stripe-key-not-real", "stripe", True),
                ("STRIPE_BASE_URL", "https://api.stripe.com", "stripe", False),
            ]
            for name, value, service, sensitive in entries:
                response = page.request.post(url.split("?")[0] + "api/add", data={
                    "name": name, "value": value, "service": service,
                    "sensitive": sensitive, "scope": "global",
                })
                assert response.ok, f"Could not add dummy entry {name}"

            for scheme in ("light", "dark"):
                page.emulate_media(color_scheme=scheme)
                page.goto(url, wait_until="networkidle")
                expect(page.locator(".secret-name")).to_have_count(len(entries))
                # Omit the fixture's random temporary path, not app content.
                page.add_style_tag(content=".rail-foot .path { visibility: hidden; }")
                suffix = "" if scheme == "light" else "-dark"
                page.screenshot(path=str(ASSETS / f"sm-secrets{suffix}.png"))

                page.locator("#importBtn").click()
                page.locator("#pasteData").fill("GITHUB_TOKEN=demo-github-token-not-real")
                page.locator("#detectBtn").click()
                row = page.locator(".review-entry")
                expect(row).to_have_count(1)
                expect(row.locator(".review-name")).to_have_value("GITHUB_TOKEN")
                expect(page.locator("#saveBtn")).to_be_enabled()
                row.screenshot(path=str(ASSETS / f"sm-import{suffix}.png"))
            context.close()
        finally:
            browser.close()


if __name__ == "__main__":
    env = dict(os.environ, SM_UI_PREVIEW="1", SM_UI_PREVIEW_SEEDED="0")
    process = subprocess.Popen(
        ["go", "test", "-count=1", "-v", "./internal/uiserver", "-run",
         "^TestInteractivePreview$", "-timeout", "16m"],
        cwd=ROOT, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, start_new_session=True,
    )
    try:
        for line in process.stdout:
            if "UI_PREVIEW_URL=" in line:
                capture(line.strip().split("UI_PREVIEW_URL=", 1)[1])
                print("Updated light/dark Secrets and Import screenshots (dummy data only).")
                break
        else:
            raise RuntimeError("Isolated UI fixture did not start")
    finally:
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGTERM)
        process.wait(timeout=15)
