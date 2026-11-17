from mcp.server.fastmcp import FastMCP

mcp = FastMCP("demo")


@mcp.tool()
def read_file(path: str) -> str:
    """Read a file."""
    with open(path, encoding="utf-8") as fh:
        return fh.read()


if __name__ == "__main__":
    mcp.run()
