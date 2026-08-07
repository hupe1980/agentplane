#!/usr/bin/env python3
"""A minimal MCP server over stdio: one tool, `read`."""
import json, sys

def send(obj):
    sys.stdout.write(json.dumps(obj) + "\n"); sys.stdout.flush()

TOOLS = [{
    "name": "read",
    "description": "Read a ticket by id",
    "inputSchema": {"type": "object", "required": ["id"],
                    "properties": {"id": {"type": "string"}}},
}]

for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    req = json.loads(line)
    m, rid = req.get("method"), req.get("id")
    if m == "initialize":
        send({"jsonrpc": "2.0", "id": rid, "result": {
            "protocolVersion": req["params"]["protocolVersion"],
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "tickets", "version": "1.0.0"}}})
    elif m == "tools/list":
        send({"jsonrpc": "2.0", "id": rid, "result": {"tools": TOOLS}})
    elif m == "tools/call":
        tid = req["params"]["arguments"].get("id", "?")
        send({"jsonrpc": "2.0", "id": rid, "result": {
            "content": [{"type": "text", "text": f"ticket {tid}: printer on fire"}],
            "isError": False}})
    elif rid is not None:
        send({"jsonrpc": "2.0", "id": rid,
              "error": {"code": -32601, "message": f"no such method: {m}"}})
