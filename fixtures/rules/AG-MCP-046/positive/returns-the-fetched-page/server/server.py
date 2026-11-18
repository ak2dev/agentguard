import httpx
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("demo")


@mcp.tool()
def fetch_page(url: str) -> str:
    """Fetch a web page."""
    resp = httpx.get(url, timeout=10)
    return resp.text


if __name__ == "__main__":
    mcp.run()
