#!/usr/bin/env python3
"""Drive headless Chromium over the DevTools protocol and judge the dev page.

Usage: dev-page-smoke.py <browser> <page url> <run id> <profile dir> <second run id>

Standard library only: the DevTools socket is a WebSocket, and the few frames
this needs are written here rather than taken from a package the gate would
have to install. The page is loaded, given until its timeline shows the run,
and then read back: its text, the elements it holds and its own count of
content-security-policy violations.
"""

from __future__ import annotations

import base64
import json
import os
import pathlib
import socket
import struct
import subprocess
import sys
import time
import urllib.request

TIMEOUT_SECONDS = 60


class Socket:
    """A WebSocket client: text frames out, text frames in."""

    def __init__(self, url: str) -> None:
        rest = url.removeprefix("ws://")
        authority, _, path = rest.partition("/")
        host, _, port = authority.partition(":")
        self.sock = socket.create_connection((host, int(port)), timeout=TIMEOUT_SECONDS)
        key = base64.b64encode(os.urandom(16)).decode()
        self.sock.sendall(
            (
                f"GET /{path} HTTP/1.1\r\nHost: {authority}\r\nUpgrade: websocket\r\n"
                f"Connection: Upgrade\r\nSec-WebSocket-Key: {key}\r\n"
                "Sec-WebSocket-Version: 13\r\n\r\n"
            ).encode()
        )
        head = b""
        while b"\r\n\r\n" not in head:
            head += self.sock.recv(1)
        if b" 101 " not in head.split(b"\r\n", 1)[0]:
            raise RuntimeError(f"DevTools refused the socket: {head!r}")
        self.next_id = 0

    def _read(self, n: int) -> bytes:
        data = b""
        while len(data) < n:
            chunk = self.sock.recv(n - len(data))
            if not chunk:
                raise RuntimeError("DevTools closed the socket")
            data += chunk
        return data

    def send(self, method: str, params: dict | None = None) -> dict:
        self.next_id += 1
        payload = json.dumps({"id": self.next_id, "method": method, "params": params or {}}).encode()
        mask = os.urandom(4)
        header = bytes([0x81])
        if len(payload) < 126:
            header += bytes([0x80 | len(payload)])
        elif len(payload) < 1 << 16:
            header += bytes([0x80 | 126]) + struct.pack(">H", len(payload))
        else:
            header += bytes([0x80 | 127]) + struct.pack(">Q", len(payload))
        masked = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
        self.sock.sendall(header + mask + masked)
        while True:
            message = self._receive()
            if message.get("id") == self.next_id:
                if "error" in message:
                    raise RuntimeError(f"{method}: {message['error']}")
                return message.get("result", {})

    def _receive(self) -> dict:
        text = b""
        while True:
            first, second = self._read(2)
            length = second & 0x7F
            if length == 126:
                length = struct.unpack(">H", self._read(2))[0]
            elif length == 127:
                length = struct.unpack(">Q", self._read(8))[0]
            data = self._read(length)
            opcode = first & 0x0F
            if opcode == 0x8:
                raise RuntimeError("DevTools closed the socket")
            if opcode in (0x1, 0x0):
                text += data
                if first & 0x80:
                    return json.loads(text)


def evaluate(page: Socket, expression: str):
    result = page.send(
        "Runtime.evaluate", {"expression": expression, "returnByValue": True}
    )
    return result.get("result", {}).get("value")


PROBE = """(() => {
  for (const d of document.querySelectorAll('#timeline details')) d.open = true;
  const all = [...document.querySelectorAll('*')];
  return {
    text: document.body ? document.body.innerText : '',
    timeline: document.querySelectorAll('#timeline li').length,
    timelineText: document.getElementById('timeline').innerText,
    seqs: [...document.querySelectorAll('#timeline li .seq')].map((e) => Number(e.textContent)),
    images: document.querySelectorAll('img').length,
    scripts: [...document.scripts].map((s) => s.getAttribute('src')),
    handlers: all.flatMap((e) => [...e.attributes].map((a) => a.name)).filter((n) => n.startsWith('on')),
    links: [...document.querySelectorAll('a[href]')].map((a) => a.getAttribute('href')),
    violations: document.getElementById('violations').textContent,
    decisions: [...document.querySelectorAll('#tasks button')].map((b) => b.textContent),
    title: document.title,
  };
})()"""


def launch(browser: str, profile: str, *flags: str) -> tuple[subprocess.Popen, str]:
    """Start headless Chromium on `profile` and return it with its DevTools port.

    The browser's stderr goes to `<profile>.log`, and a browser that exits or
    opens no port is reported with its exit code and the end of that log: on
    Linux a sandbox refused by the kernel exits at once and says so only there.
    """
    log_path = pathlib.Path(f"{profile}.log")
    log = log_path.open("wb")
    chrome = subprocess.Popen(
        [
            browser,
            "--headless=new",
            "--disable-gpu",
            "--no-first-run",
            "--no-default-browser-check",
            f"--user-data-dir={profile}",
            "--remote-debugging-port=0",
            *flags,
            "about:blank",
        ],
        stdout=subprocess.DEVNULL,
        stderr=log,
    )
    log.close()
    port_file = pathlib.Path(profile) / "DevToolsActivePort"
    deadline = time.monotonic() + TIMEOUT_SECONDS
    while not port_file.exists() or not port_file.read_text().strip():
        status = chrome.poll()
        if status is not None or time.monotonic() > deadline:
            if status is None:
                chrome.kill()
                chrome.wait()
            tail = log_path.read_text(errors="replace").strip().splitlines()[-15:]
            said = "\n".join(f"    {line}" for line in tail) or "    (nothing)"
            how = f"exited with {status}" if status is not None else f"opened no port in {TIMEOUT_SECONDS}s"
            raise RuntimeError(f"the browser {how}; its stderr ends:\n{said}")
        time.sleep(0.1)
    return chrome, port_file.read_text().split()[0]


def main() -> int:
    browser, url, run, profile, second = sys.argv[1:6]
    chrome, port = launch(browser, profile)
    try:
        deadline = time.monotonic() + TIMEOUT_SECONDS
        targets = json.load(urllib.request.urlopen(f"http://127.0.0.1:{port}/json/list"))
        target = next(t for t in targets if t.get("type") == "page")
        page = Socket(target["webSocketDebuggerUrl"])
        page.send("Page.enable")
        page.send("Page.navigate", {"url": url})

        state = None
        tabs = None
        while time.monotonic() < deadline:
            state = evaluate(page, PROBE)
            if state and state["timeline"] > 0 and "RunAdmitted" in state["text"]:
                # One more poll interval, so the worklist has rendered too.
                time.sleep(2)
                state = evaluate(page, PROBE)
                break
            time.sleep(0.25)
        tabs = evaluate(
            page,
            "(() => { document.querySelector('[data-tab=worklist]').click();"
            " const shown = (id) => getComputedStyle(document.getElementById(id)).display !== 'none';"
            " const r = { worklist: shown('tab-worklist'), run: shown('tab-run') };"
            " document.querySelector('[data-tab=run]').click(); return r; })()",
        )
        # Switch runs back and forth faster than a poll answers, then let the
        # page settle on the second.
        switch = (
            "(() => { for (const r of [%s, %s, %s, %s]) {"
            " document.querySelector('#runs-list button[data-run=\"' + r + '\"]').click(); } })()"
            % (json.dumps(second), json.dumps(run), json.dumps(run), json.dumps(second))
        )
        switched = None
        while time.monotonic() < deadline:
            options = evaluate(page, "[...document.querySelectorAll('#runs-list button[data-run]')].map((b) => b.dataset.run)")
            if options and second in options:
                evaluate(page, switch)
                time.sleep(4)
                switched = evaluate(page, PROBE)
                break
            time.sleep(0.25)
    finally:
        chrome.kill()
        chrome.wait()

    failures = []

    def need(ok: bool, what: str) -> None:
        if not ok:
            failures.append(what)

    if not state:
        print("dev-page-smoke: the page never answered", file=sys.stderr)
        return 1
    text = state["text"]
    need(state["timeline"] > 0 and run in text, "the timeline never rendered the hostile run")
    need("<img src=x onerror=" in text, "the <img onerror> string does not appear as text")
    need("</script><script>" in text, "the </script> string does not appear as text")
    need("javascript:alert(1)" in text, "the javascript: URL does not appear as text")
    need("\\u{202E}" in text, "the bidi override does not appear escaped")
    need("\u202e" not in text, "the bidi override reached the document raw")
    need("ZXZpbA==" in text, "the OSC-52 sequence does not appear as text")
    need(state["images"] == 0, "an <img> element was created")
    need(state["scripts"] == ["/assets/app.js"], f"scripts on the page: {state['scripts']}")
    need(not state["handlers"], f"handler attributes were created: {state['handlers']}")
    need(
        all(link.startswith("blob:") for link in state["links"]),
        f"a link was made from data: {state['links']}",
    )
    need("Approve" in state["decisions"], f"the worklist offers no decision on the open task: {state['decisions']}")
    need(state["title"] == "agentplane dev", f"a recorded script ran: title {state['title']!r}")
    need(state["violations"] == "0", f"the page counted {state['violations']} policy violations")
    need(
        bool(tabs) and tabs["worklist"] and not tabs["run"],
        f"choosing the worklist tab did not show it alone: {tabs}",
    )
    if not switched:
        failures.append("the second run never reached the run list")
    else:
        shown = switched["timelineText"]
        seqs = switched["seqs"]
        need("second-run-marker" in shown, "the switched timeline does not show the second run")
        need("onerror" not in shown, "the switched timeline shows the first run's records")
        need(
            seqs == list(range(1, len(seqs) + 1)) and seqs,
            f"the switched timeline's sequences are not each record once: {seqs}",
        )
        need(switched["violations"] == "0", f"the page counted {switched['violations']} policy violations")

    if failures:
        print("dev-page-smoke: FAILED", file=sys.stderr)
        for failure in failures:
            print(f"  {failure}", file=sys.stderr)
        return 1
    print("dev-page-smoke: every hostile record rendered as text; 0 policy violations")
    return 0


if __name__ == "__main__":
    sys.exit(main())
