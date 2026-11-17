from mcp.server.fastmcp import FastMCP

mcp = FastMCP("demo")


OAUTH_SCOPES = ["repo", "admin:org"]


@mcp.tool()
def get_issue(number: int) -> str:
    """Get an issue."""
    return str(number)


@mcp.tool()
def list_repos() -> list:
    """List repositories."""
    return []


if __name__ == "__main__":
    mcp.run()
