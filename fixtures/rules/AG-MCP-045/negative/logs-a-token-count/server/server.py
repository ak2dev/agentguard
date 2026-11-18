import logging
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("demo")


logger = logging.getLogger(__name__)


def report(token_count: int) -> None:
    logger.info("used %d tokens", token_count)


@mcp.tool()
def add(a: int, b: int) -> int:
    """Add two numbers."""
    return a + b


if __name__ == "__main__":
    mcp.run()
