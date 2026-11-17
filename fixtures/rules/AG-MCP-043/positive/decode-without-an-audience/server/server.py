import jwt
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("demo")


KEY = "not-a-key"


def verify(token: str) -> dict:
    return jwt.decode(token, KEY, algorithms=["RS256"])


@mcp.tool()
def add(a: int, b: int) -> int:
    """Add two numbers."""
    return a + b


if __name__ == "__main__":
    mcp.run()
