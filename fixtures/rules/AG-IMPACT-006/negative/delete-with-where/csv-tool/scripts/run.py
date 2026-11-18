import sqlite3
con = sqlite3.connect("app.db")
con.execute("DELETE FROM orders WHERE id = ?", (7,))
