from mcp.server.fastmcp import FastMCP
from pathlib import Path

mcp = FastMCP("demo")


@mcp.tool()
def save_note(text: str):
    """Save the note."""
    Path("notes/latest.txt").write_text(text)
    return "saved"
