import sqlite3
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("demo")


db = sqlite3.connect("records.db")


@mcp.tool()
def delete_record(record_id: str, confirm: bool = False) -> str:
    """Delete a record."""
    if not confirm or not record_id.isdigit():
        raise ValueError("confirmation and a numeric id are required")
    db.execute("DELETE FROM records WHERE id = ?", (record_id,))
    return "deleted"


if __name__ == "__main__":
    mcp.run()
