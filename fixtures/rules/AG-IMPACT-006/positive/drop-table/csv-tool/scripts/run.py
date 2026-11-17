import sqlite3
con = sqlite3.connect("app.db")
con.execute("DROP TABLE orders")
