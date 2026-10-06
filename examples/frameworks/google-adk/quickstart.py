# Governed calls from Google ADK, through both of the plane's doors: a tool over
# MCP, and a remote agent over A2A (when AGENTPLANE_PEER_TOKEN is set).
#
#   export AGENTPLANE_TOKEN="$(cat plane/framework.token)"
#   uv run --no-project --with-requirements requirements.lock quickstart.py
#
# Neither call needs a model key: ADK's toolset runs the tool, the plane the turn.
import asyncio
import os

import httpx
from google.adk.agents.remote_a2a_agent import RemoteA2aAgent
from google.adk.runners import InMemoryRunner
from google.adk.tools.mcp_tool import McpToolset, StreamableHTTPConnectionParams
from google.genai import types

MCP = os.environ.get("AGENTPLANE_MCP_URL", "http://localhost:8081/mcp")
A2A = os.environ.get("AGENTPLANE_A2A_URL", "http://localhost:8080")
TEXT = "The printer on floor 3 is on fire again."


async def main() -> None:
    auth = {"Authorization": f"Bearer {os.environ['AGENTPLANE_TOKEN']}"}
    plane = McpToolset(connection_params=StreamableHTTPConnectionParams(url=MCP, headers=auth))
    tool = next(t for t in await plane.get_tools() if t.name == "support.summarise")
    print(await tool.run_async(args={"text": TEXT}, tool_context=None))  # no agent loop
    await plane.close()
    if peer := os.environ.get("AGENTPLANE_PEER_TOKEN"):
        client = httpx.AsyncClient(headers={"Authorization": f"Bearer {peer}"})
        remote = RemoteA2aAgent(name="plane", agent_card=f"{A2A}/.well-known/agent-card.json",
                                httpx_client=client, use_legacy=False)
        runner = InMemoryRunner(agent=remote, app_name="quickstart")
        session = await runner.session_service.create_session(app_name="quickstart", user_id="me")
        message = types.Content(role="user", parts=[types.Part(text=TEXT)])
        async for event in runner.run_async(user_id="me", session_id=session.id, new_message=message):
            assert not event.error_message, event.error_message
            print(event.content)


asyncio.run(main())
