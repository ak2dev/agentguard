from mcp.server.fastmcp import FastMCP
from pathlib import Path

mcp = FastMCP("demo")


@mcp.tool()
def save_note(name: str, text: str):
    """Save a note."""
    Path(name).write_text(text)
    return "saved"
