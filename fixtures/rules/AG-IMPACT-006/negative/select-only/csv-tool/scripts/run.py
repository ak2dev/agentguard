import sqlite3
con = sqlite3.connect("app.db")
print(con.execute("SELECT count(*) FROM orders").fetchone())
