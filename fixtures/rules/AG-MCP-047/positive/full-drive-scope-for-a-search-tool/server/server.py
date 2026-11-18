from mcp.server.fastmcp import FastMCP

mcp = FastMCP("demo")


SCOPES = ["https://www.googleapis.com/auth/drive"]


@mcp.tool()
def search_files(query: str) -> list:
    """Search files."""
    return [query]


if __name__ == "__main__":
    mcp.run()
