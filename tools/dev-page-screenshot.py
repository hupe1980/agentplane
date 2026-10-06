#!/usr/bin/env python3
"""Capture the dev page for the guide: a run's timeline and its conversation,
each in the light and the dark theme.

Usage: dev-page-screenshot.py <browser> <page url> <profile dir> <out dir>

Drives headless Chromium over the DevTools socket `dev-page-smoke.py` already
speaks, so the two share one transport and this adds no dependency.
"""

from __future__ import annotations

import base64
import importlib.util
import json
import pathlib
import sys
import time
import urllib.request

HERE = pathlib.Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("smoke", HERE / "dev-page-smoke.py")
smoke = importlib.util.module_from_spec(spec)
spec.loader.exec_module(smoke)

WIDTH, HEIGHT = 1280, 860
VIEWS = {
    "timeline": "document.querySelector('[data-view=timeline]').click()",
    "conversation": "document.querySelector('[data-view=conversation]').click()",
}


def main() -> int:
    browser, url, profile, out = sys.argv[1:5]
    out_dir = pathlib.Path(out)
    chrome, port = smoke.launch(browser, profile, "--hide-scrollbars")
    try:
        deadline = time.monotonic() + smoke.TIMEOUT_SECONDS
        targets = json.load(urllib.request.urlopen(f"http://127.0.0.1:{port}/json/list"))
        page = smoke.Socket(next(t for t in targets if t.get("type") == "page")["webSocketDebuggerUrl"])
        page.send("Page.enable")
        page.send(
            "Emulation.setDeviceMetricsOverride",
            {"width": WIDTH, "height": HEIGHT, "deviceScaleFactor": 1, "mobile": False},
        )
        for theme in ("light", "dark"):
            page.send(
                "Emulation.setEmulatedMedia",
                {"features": [{"name": "prefers-color-scheme", "value": theme}]},
            )
            page.send("Page.navigate", {"url": url})
            # Until the run's whole journal is on the page, then one more poll.
            while time.monotonic() < deadline:
                done = smoke.evaluate(
                    page,
                    "[...document.querySelectorAll('#timeline .kind')].some((k) => k.textContent === 'RunConcluded')",
                )
                if done:
                    break
                time.sleep(0.25)
            else:
                raise RuntimeError("the run's journal never reached the page")
            time.sleep(1.6)
            for view, click in VIEWS.items():
                smoke.evaluate(page, click)
                time.sleep(0.4)
                shot = page.send("Page.captureScreenshot", {"format": "png"})
                path = out_dir / f"dev-page-{view}-{theme}.png"
                path.write_bytes(base64.b64decode(shot["data"]))
                print(f"wrote {path}")
    finally:
        chrome.kill()
        chrome.wait()
    return 0


if __name__ == "__main__":
    sys.exit(main())
