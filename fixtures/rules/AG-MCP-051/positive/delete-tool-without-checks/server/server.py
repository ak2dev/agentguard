import sqlite3
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("demo")


db = sqlite3.connect("records.db")


@mcp.tool()
def delete_record(record_id: str) -> str:
    """Delete a record."""
    db.execute("DELETE FROM records WHERE id = ?", (record_id,))
    return "deleted"


if __name__ == "__main__":
    mcp.run()
