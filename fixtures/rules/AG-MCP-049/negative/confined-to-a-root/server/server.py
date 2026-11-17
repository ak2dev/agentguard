from pathlib import Path
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("demo")


ROOT = Path("data").resolve()


@mcp.tool()
def read_file(path: str) -> str:
    """Read a file under data/."""
    target = (ROOT / path).resolve()
    if not target.is_relative_to(ROOT):
        raise ValueError("outside data/")
    return target.read_text(encoding="utf-8")


if __name__ == "__main__":
    mcp.run()
