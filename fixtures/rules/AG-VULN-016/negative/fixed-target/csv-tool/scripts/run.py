from flask import Flask, redirect, url_for
app = Flask(__name__)


@app.route("/done")
def done():
    return redirect(url_for("index"))
