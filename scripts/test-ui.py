#!/usr/bin/env python3
"""Opt-in browser regressions. Starts isolated Go fixtures; never the real vault.

Requires: python3 -m pip install playwright && python3 -m playwright install chromium
Run from the repository root: python3 scripts/test-ui.py
"""
import json
import os
from pathlib import Path
import signal
import subprocess
import tempfile
from urllib.parse import urlsplit

from playwright.sync_api import sync_playwright, expect

ROOT = Path(__file__).resolve().parent.parent
processes = []


def fixture(seeded):
    env = dict(os.environ, SM_UI_PREVIEW="1", SM_UI_PREVIEW_SEEDED="1" if seeded else "0")
    process = subprocess.Popen(
        ["go", "test", "-v", "./internal/uiserver", "-run", "^TestInteractivePreview$", "-timeout", "16m"],
        cwd=ROOT, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, start_new_session=True,
    )
    processes.append(process)
    for line in process.stdout:
        if "UI_PREVIEW_URL=" in line:
            return line.strip().split("UI_PREVIEW_URL=", 1)[1]
    raise RuntimeError("Isolated UI fixture did not start")


def import_text(page, text):
    page.locator("#importBtn").click()
    page.locator("#pasteData").fill(text)
    with page.expect_response(lambda res: res.url.endswith("/api/detect")):
        page.locator("#detectBtn").click()
    expect(page.locator(".review-entry").first).to_be_visible()


def save_import(page):
    expect(page.locator("#saveBtn")).to_be_enabled(timeout=10000)
    with page.expect_response(lambda res: res.url.endswith("/api/add-detected")) as response:
        page.locator("#saveBtn").click()
    assert response.value.ok
    expect(page.locator("#sheet")).to_be_hidden()


def run():
    seeded, fresh = fixture(True), fixture(False)
    with tempfile.TemporaryDirectory(prefix="sm-ui-regressions-") as temp_output, sync_playwright() as pw:
        output = os.environ.get("SM_UI_SCREENSHOTS", temp_output)
        Path(output).mkdir(parents=True, exist_ok=True)
        browser = pw.chromium.launch()
        context = browser.new_context(viewport={"width": 1440, "height": 960}, accept_downloads=True)
        page = context.new_page()
        errors = []
        external_requests = []
        def watch(target):
            target.on("pageerror", lambda error: errors.append(str(error)))
            target.on("request", lambda request: external_requests.append("external") if urlsplit(request.url).scheme in ("http", "https") and urlsplit(request.url).hostname != "127.0.0.1" else None)
        watch(page)
        page.goto(seeded, wait_until="networkidle")
        text = "my email address is first@example.org\nsecond@example.org\nOPENAI_API_KEY=dummy-new-key\nCUSTOM_SETTING=opaque-value\nBASE_URL=https://example.org?signature=dummy\nunrecognized sentence"
        import_text(page, text)
        expect(page.locator(".review-entry")).to_have_count(5)
        expect(page.locator("#detectWarnings")).to_contain_text("Line 6")
        first = page.locator(".review-entry").nth(0)
        first.locator(".review-name").fill("PERSONAL_EMAIL")
        first.locator(".review-value").fill("edited@example.org")
        first.locator(".review-service").fill("personal")
        first.locator(".review-kind").select_option("secret")
        expect(first.locator(".review-value")).to_have_attribute("type", "password")
        expect(page.locator(".review-entry").nth(3).locator(".review-kind")).to_have_value("secret")
        expect(page.locator(".review-entry").nth(4).locator(".review-kind")).to_have_value("secret")
        expect(page.locator("#saveBtn")).to_be_enabled(timeout=10000)
        page.screenshot(path=str(Path(output) / "editable-review.png"))
        save_import(page)
        expect(page.locator('.secret-group[aria-label="personal"]')).to_be_visible()

        import_text(page, "AWS_ACCESS_KEY_ID=different-dummy-value")
        row = page.locator(".review-entry").first
        row.locator(".review-select").check()
        expect(page.locator("#reviewStatus")).to_contain_text("conflicts", timeout=10000)
        expect(page.locator("#saveBtn")).to_be_disabled()
        row.locator(".review-name").fill("SECOND_AWS_KEY")
        save_import(page)

        # Group edits act only on labels and have a guarded Undo.
        page.locator('.secret-group[aria-label="personal"]').get_by_role("button", name="Manage group").click()
        page.locator("#fGroup").fill("contacts")
        page.locator("#fGroup").press("Escape")
        page.locator("#saveBtn").click()
        expect(page.locator('.secret-group[aria-label="contacts"]')).to_be_visible()
        page.locator(".toast").filter(has=page.get_by_role("button", name="Undo")).get_by_role("button", name="Undo").click()
        expect(page.locator('.secret-group[aria-label="personal"]')).to_be_visible()

        # Export and verify locally. Only encrypted bytes leave the HTTP response.
        page.locator('[data-view="recovery"]').click()
        password = "browser test recovery passphrase"
        page.locator("#backupPassword").fill(password)
        page.locator("#backupConfirm").fill(password)
        with page.expect_download(timeout=60000) as download:
            page.locator("#backupBtn").click()
        archive = Path(output) / "test-recovery.age"
        download.value.save_as(archive)
        assert b"dummy-new-key" not in archive.read_bytes()
        page.locator("#restoreFile").set_input_files(archive)
        page.locator("#restorePassword").fill(password)
        page.locator("#verifyBackupBtn").click()
        expect(page.locator("#restoreStatus")).to_contain_text("Verified:", timeout=60000)
        expect(page.locator("#restoreBtn")).to_be_hidden()
        page.screenshot(path=str(Path(output) / "recovery.png"))

        destination = context.new_page()
        watch(destination)
        destination.goto(fresh, wait_until="networkidle")
        destination.locator('[data-view="recovery"]').click()
        with destination.expect_file_chooser() as chooser:
            destination.locator("#restoreFileBtn").click()
        chooser.value.set_files(str(archive))
        expect(destination.locator("#restoreFileName")).to_contain_text(archive.name)
        destination.locator("#restorePassword").fill(password)
        destination.locator("#verifyBackupBtn").click()
        expect(destination.locator("#restoreBtn")).to_be_visible(timeout=60000)
        destination.locator("#restoreBtn").click()
        expect(destination.locator("#restoreStatus")).to_contain_text("Restore complete", timeout=60000)
        destination.locator('[data-view="secrets"]').click()
        expect(destination.locator(".secret-name").filter(has_text="PERSONAL_EMAIL")).to_be_visible()
        destination.close()

        for scheme in ("light", "dark"):
            for width, height in ((1440, 960), (1040, 720), (390, 844)):
                test_page = browser.new_page(viewport={"width": width, "height": height}, color_scheme=scheme)
                watch(test_page)
                test_page.goto(seeded, wait_until="networkidle")
                import_text(test_page, '{"modal":{"tokenId":"dummy-token-id","profile":"sandbox"}}')
                expect(test_page.locator(".review-entry")).to_have_count(2)
                geometry = test_page.evaluate("""() => ({
                  width: innerWidth,
                  scroll: document.documentElement.scrollWidth,
                  formWidth: document.getElementById('secretForm').clientWidth,
                  formScroll: document.getElementById('secretForm').scrollWidth
                })""")
                assert geometry["scroll"] <= geometry["width"], geometry
                assert geometry["formScroll"] <= geometry["formWidth"], geometry
                # Screenshots use only the fixture's dummy values.
                test_page.screenshot(path=str(Path(output) / f"import-{scheme}-{width}.png"))
                test_page.close()
        assert not errors, errors
        assert not external_requests, "The UI attempted a non-loopback request"
        browser.close()
    print("PASS: editable import, conflict checks, group Undo, encrypted recovery, 6 theme/viewport combinations")


if __name__ == "__main__":
    try:
        run()
    finally:
        for process in processes:
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
