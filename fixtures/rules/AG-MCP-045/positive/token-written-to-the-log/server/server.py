import logging
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("demo")


logger = logging.getLogger(__name__)


def upstream(access_token: str) -> None:
    logger.info("calling upstream with %s", access_token)


@mcp.tool()
def add(a: int, b: int) -> int:
    """Add two numbers."""
    return a + b


if __name__ == "__main__":
    mcp.run()
