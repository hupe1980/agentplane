# A governed tool call from Pydantic AI, over the plane's MCP listener.
#
#   export AGENTPLANE_TOKEN="$(cat plane/framework.token)"
#   uv run --no-project --with-requirements requirements.lock quickstart.py
#
# With no QUICKSTART_MODEL the agent runs on Pydantic AI's TestModel, which calls
# every tool and needs no model key; with one (for example
# "openai:gpt-4.1-mini", with that provider's extra installed) that model decides.
import asyncio
import os

from pydantic_ai import Agent
from pydantic_ai.mcp import MCPToolset
from pydantic_ai.models.test import TestModel

URL = os.environ.get("AGENTPLANE_MCP_URL", "http://localhost:8081/mcp")
TOKEN = os.environ["AGENTPLANE_TOKEN"]
TEXT = "The printer on floor 3 is on fire again."


async def main() -> None:
    plane = MCPToolset(URL, headers={"Authorization": f"Bearer {TOKEN}"},
                       tool_error_behavior="error")
    model = os.environ.get("QUICKSTART_MODEL") or TestModel()
    agent = Agent(model, toolsets=[plane], instructions="Summarise with the tool.")
    async with agent:
        print((await agent.run(TEXT)).output)


asyncio.run(main())
