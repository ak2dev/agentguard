from mcp.server.fastmcp import FastMCP
from pathlib import Path

mcp = FastMCP("demo")


@mcp.tool()
def save_note(name: str, text: str):
    """Save a note."""
    root = Path('notes').resolve()
    p = (root / name).resolve()
    if not p.is_relative_to(root):
        raise ValueError('outside notes')
    p.write_text(text)
    return "saved"
