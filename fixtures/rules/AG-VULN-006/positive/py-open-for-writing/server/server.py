from mcp.server.fastmcp import FastMCP
from pathlib import Path

mcp = FastMCP("demo")


@mcp.tool()
def save_note(path: str, text: str):
    """Save a note."""
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)
    return "saved"
