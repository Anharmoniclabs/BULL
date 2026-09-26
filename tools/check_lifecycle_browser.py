#!/usr/bin/env python3
"""Offline Chromium render checks; HTTP endpoint behavior is tested separately."""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import shutil
from playwright.sync_api import sync_playwright


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("report", type=Path)
    parser.add_argument("--output", type=Path, default=Path("/tmp/bull-lifecycle-browser"))
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    checks, errors = [], []
    content = args.report.read_text(encoding="utf-8")
    with sync_playwright() as p:
        options = {"headless": True}
        browser_path = shutil.which("chromium") or shutil.which("chromium-browser")
        if browser_path:
            options["executable_path"] = browser_path
        browser = p.chromium.launch(**options)
        for width, height in [(1440, 1080), (1024, 900), (768, 1024), (390, 844)]:
            page = browser.new_page(viewport={"width": width, "height": height})
            page.emulate_media(reduced_motion="reduce")
            page.on("pageerror", lambda exc: errors.append(str(exc)))
            page.set_content(content, wait_until="load")
            assert page.locator("h1").is_visible()
            assert page.locator(".step").count() == 12
            assert page.locator("#limits").is_visible()
            overflow = page.evaluate("document.documentElement.scrollWidth > innerWidth + 1")
            assert not overflow, f"horizontal overflow at {width}"
            page.locator("#replay").click()
            assert page.locator("#step-1").get_attribute("class") == "step focus"
            assert "No action is being executed" in page.locator("#progress").inner_text()
            page.locator("#audit summary").click()
            assert page.locator("#audit table").is_visible()
            page.evaluate("window.scrollTo(0,0)")
            page.wait_for_timeout(50)
            page.screenshot(path=str(args.output / f"viewer-{width}.png"), full_page=True)
            page.screenshot(path=str(args.output / f"preview-{width}.png"), full_page=False)
            checks.append({"viewport": [width, height], "body_visible": True, "steps": 12,
                           "horizontal_overflow": False, "replay": "pass", "audit_expand": "pass"})
            page.close()
        browser.close()
    assert not errors, errors
    (args.output / "browser-checks.json").write_text(json.dumps({"checks": checks, "page_errors": errors}, indent=2))
    print(f"{len(checks)} viewport checks passed; {len(errors)} browser errors")


if __name__ == "__main__":
    main()
