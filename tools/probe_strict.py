#!/usr/bin/env python3
"""Send every shape in tests/wire/strict-probe.json to OpenAI as a strict tool.

The offline test holds the strict check to this table; this re-measures the
table against the API, so a provider change is a diff, not an argument. Each
shape is sent as the parameters of one function tool with ``strict: true``.

    OPENAI_API_KEY=... python3 tools/probe_strict.py [--update]

Exit 1 when the API now answers a shape differently from the table. With
``--update`` the table is rewritten with today's verdicts and date instead.
"""

import datetime
import json
import os
import pathlib
import sys
import urllib.error
import urllib.request

TABLE = pathlib.Path(__file__).resolve().parent.parent / "tests" / "wire" / "strict-probe.json"


def accepted(key: str, model: str, schema: object) -> tuple[bool, str]:
    body = {
        "model": model,
        "input": "call t",
        "max_output_tokens": 16,
        "tools": [
            {"type": "function", "name": "t", "description": "x", "strict": True, "parameters": schema}
        ],
    }
    request = urllib.request.Request(
        "https://api.openai.com/v1/responses",
        data=json.dumps(body).encode(),
        headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=60):
            return True, ""
    except urllib.error.HTTPError as error:
        if error.code != 400:
            raise
        detail = json.load(error).get("error", {}).get("message", "")
        return False, detail[:160]


def main() -> int:
    key = os.environ.get("OPENAI_API_KEY")
    if not key:
        print("skipping: OPENAI_API_KEY is not set", file=sys.stderr)
        return 0
    table = json.loads(TABLE.read_text())
    changed = []
    for name, case in sorted(table["cases"].items()):
        now, detail = accepted(key, table["model"], case["schema"])
        if now != case["accepted"]:
            changed.append(f"{name}: table says {case['accepted']}, API says {now} {detail}")
            case["accepted"] = now
    if "--update" in sys.argv:
        table["probed"] = datetime.date.today().isoformat()
        TABLE.write_text(json.dumps(table, indent=1, sort_keys=True) + "\n")
    for line in changed:
        print(line)
    print(f"{len(table['cases'])} shapes probed, {len(changed)} changed", file=sys.stderr)
    return 1 if changed and "--update" not in sys.argv else 0


if __name__ == "__main__":
    sys.exit(main())
