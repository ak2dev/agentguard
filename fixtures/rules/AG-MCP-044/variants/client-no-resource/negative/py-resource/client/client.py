from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client


async def connect(url: str, headers: dict[str, str]):
    async with streamablehttp_client(url, headers=headers) as (read, write, _):
        async with ClientSession(read, write) as session:
            return await session.list_tools()
