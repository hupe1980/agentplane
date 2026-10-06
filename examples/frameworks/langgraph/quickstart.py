# A governed tool call from LangGraph, over the plane's MCP listener.
#
#   export AGENTPLANE_TOKEN="$(cat plane/framework.token)"
#   uv run --no-project --with-requirements requirements.lock quickstart.py
#
# With no QUICKSTART_MODEL it invokes the adapter's tool and needs no model key;
# with one (for example "openai:gpt-4.1-mini", with that provider's package
# installed) a ReAct agent on it decides.
import asyncio
import os

from langchain_mcp_adapters.client import MultiServerMCPClient
from langgraph.prebuilt import create_react_agent

URL = os.environ.get("AGENTPLANE_MCP_URL", "http://localhost:8081/mcp")
TOKEN = os.environ["AGENTPLANE_TOKEN"]
TEXT = "The printer on floor 3 is on fire again."


async def main() -> None:
    plane = {"transport": "streamable_http", "url": URL,
             "headers": {"Authorization": f"Bearer {TOKEN}"}}
    tools = await MultiServerMCPClient({"agentplane": plane}).get_tools()
    if not (model := os.environ.get("QUICKSTART_MODEL")):
        summarise = next(t for t in tools if t.name == "support.summarise")
        print(await summarise.ainvoke({"text": TEXT}))
        return
    agent = create_react_agent(model, tools)
    print((await agent.ainvoke({"messages": [("user", TEXT)]}))["messages"][-1].content)


asyncio.run(main())
