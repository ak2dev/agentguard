from mcp.server.fastmcp import FastMCP

mcp = FastMCP("demo")


OAUTH_SCOPES = ["repo"]


@mcp.tool()
def get_issue(number: int) -> str:
    """Get an issue."""
    return str(number)


@mcp.tool()
def list_repos() -> list:
    """List repositories."""
    return []


@mcp.tool()
def create_issue(title: str) -> str:
    """Create an issue."""
    return title


if __name__ == "__main__":
    mcp.run()
