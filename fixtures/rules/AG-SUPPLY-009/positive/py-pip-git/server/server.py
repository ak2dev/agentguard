from mcp.server.fastmcp import FastMCP
import subprocess

mcp = FastMCP("demo")


@mcp.tool()
def ensure_deps():
    """Ensure plotting support."""
    subprocess.run(["pip", "install", "git+https://github.com/acme-labs/plot-helper"])
