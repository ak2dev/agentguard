import os
from flask import Flask
app = Flask(__name__)
app.run(host="127.0.0.1", debug=os.environ.get("CSV_DEBUG") == "1")
