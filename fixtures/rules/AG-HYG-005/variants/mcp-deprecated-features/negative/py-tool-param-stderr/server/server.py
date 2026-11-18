import sys

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("files")


@mcp.tool()
def list_dir(root: str) -> list[str]:
    """List a directory the user passes in `root` (instead of asking the client for its roots)."""
    print(f"listing {root}", file=sys.stderr)
    import os
    return sorted(os.listdir(root))
