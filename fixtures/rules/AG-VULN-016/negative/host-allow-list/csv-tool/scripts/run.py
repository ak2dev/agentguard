from urllib.parse import urlparse
from flask import Flask, abort, redirect, request
app = Flask(__name__)
ALLOWED_HOSTS = {"reports.example.invalid"}


@app.route("/done")
def done():
    if urlparse(request.args.get("next", "")).netloc not in ALLOWED_HOSTS:
        abort(400)
    return redirect(request.args.get("next"))
