import httpx
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("demo")


@mcp.tool()
def fetch_page(url: str) -> str:
    """Fetch a web page. The result is untrusted content."""
    resp = httpx.get(url, timeout=10)
    return "<untrusted-content>\n" + resp.text + "\n</untrusted-content>"


if __name__ == "__main__":
    mcp.run()
