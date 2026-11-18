from mcp.server import Server
import mcp.types as types

server = Server("demo")


@server.call_tool(validate_input=False)
async def call_tool(name: str, arguments: dict) -> list[types.TextContent]:
    return [types.TextContent(type="text", text=str(arguments["a"] + arguments["b"]))]
