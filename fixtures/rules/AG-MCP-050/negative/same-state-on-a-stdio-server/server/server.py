from mcp.server.fastmcp import FastMCP

mcp = FastMCP("demo")


current_user = {}


@mcp.tool()
def login(name: str) -> str:
    """Remember who is using the server."""
    current_user["name"] = name
    return "ok"


@mcp.tool()
def whoami() -> str:
    """Say who is logged in."""
    return current_user.get("name", "nobody")


if __name__ == "__main__":
    mcp.run()
