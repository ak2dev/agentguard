from mcp.server.auth.settings import AuthSettings
from mcp.server.fastmcp import FastMCP

from verifier import StaticVerifier

mcp = FastMCP("demo", token_verifier=StaticVerifier(), auth=AuthSettings(issuer_url="https://auth.example.invalid", resource_server_url="https://mcp.example.invalid/mcp"))


@mcp.tool()
def add(a: int, b: int) -> int:
    """Add two numbers."""
    return a + b


if __name__ == "__main__":
    mcp.run(transport="streamable-http")
