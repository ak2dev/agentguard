from mcp.server.fastmcp import FastMCP

mcp = FastMCP("demo")


@mcp.tool()
def lookup(name: str) -> str:
    """Look a name up."""
    raise ValueError("Lookup failed: no entry with that name.")


if __name__ == "__main__":
    mcp.run()
