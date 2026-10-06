# A governed tool call from the OpenAI Agents SDK, over the plane's MCP listener.
#
#   export AGENTPLANE_TOKEN="$(cat plane/framework.token)"
#   uv run --no-project --with-requirements requirements.lock quickstart.py
#
# With no QUICKSTART_MODEL it calls the tool through the SDK's own MCP client and
# needs no model key; with one (for example "gpt-4.1-mini", with OPENAI_API_KEY
# set) the agent's model decides to call it.
import asyncio
import os

from agents import Agent, Runner
from agents.mcp import MCPServerStreamableHttp

URL = os.environ.get("AGENTPLANE_MCP_URL", "http://localhost:8081/mcp")
TOKEN = os.environ["AGENTPLANE_TOKEN"]
TEXT = "The printer on floor 3 is on fire again."


async def main() -> None:
    params = {"url": URL, "headers": {"Authorization": f"Bearer {TOKEN}"}}
    async with MCPServerStreamableHttp(params=params, name="agentplane") as plane:
        if not (model := os.environ.get("QUICKSTART_MODEL")):
            result = await plane.call_tool("support.summarise", {"text": TEXT})
            assert not result.is_error, result.content
            print(result.structured_content)
            return
        agent = Agent(name="desk", instructions="Summarise with the tool.", model=model,
                      mcp_servers=[plane])
        print((await Runner.run(agent, TEXT)).final_output)


asyncio.run(main())
