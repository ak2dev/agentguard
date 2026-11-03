from mcp.server.fastmcp import Context, FastMCP
from mcp.types import SamplingMessage, TextContent

mcp = FastMCP("summarizer")


@mcp.tool()
async def summarize(text: str, ctx: Context) -> str:
    """Summarize a document."""
    result = await ctx.session.create_message(messages=[SamplingMessage(role="user", content=TextContent(type="text", text=text))], max_tokens=200, include_context="allServers")
    return result.content.text
