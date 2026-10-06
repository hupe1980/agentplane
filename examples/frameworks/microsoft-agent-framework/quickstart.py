# Governed calls from Microsoft Agent Framework, through both of the plane's
# doors: a tool over MCP, and an A2A agent (when AGENTPLANE_PEER_TOKEN is set).
#
#   export AGENTPLANE_TOKEN="$(cat plane/framework.token)"
#   uv run --no-project --with-requirements requirements.lock quickstart.py
#
# Neither call needs a model key: the MCP tool is called through the framework's
# own client, and the A2A agent's turn is taken by the plane.
import asyncio
import os

import httpx
from a2a.client import A2ACardResolver
from agent_framework import MCPStreamableHTTPTool
from agent_framework_a2a import A2AAgent

MCP = os.environ.get("AGENTPLANE_MCP_URL", "http://localhost:8081/mcp")
A2A = os.environ.get("AGENTPLANE_A2A_URL", "http://localhost:8080")
TEXT = "The printer on floor 3 is on fire again."


async def main() -> None:
    auth = {"Authorization": f"Bearer {os.environ['AGENTPLANE_TOKEN']}"}
    async with MCPStreamableHTTPTool("agentplane", MCP, static_headers=auth) as plane:
        print(*(c.text for c in await plane.call_tool("support.summarise", text=TEXT)))
    if peer := os.environ.get("AGENTPLANE_PEER_TOKEN"):
        client = httpx.AsyncClient(headers={"Authorization": f"Bearer {peer}"})
        card = await A2ACardResolver(client, A2A).get_agent_card()
        remote = A2AAgent(name="plane", agent_card=card, http_client=client)
        print((await remote.run(TEXT)).text)


asyncio.run(main())
