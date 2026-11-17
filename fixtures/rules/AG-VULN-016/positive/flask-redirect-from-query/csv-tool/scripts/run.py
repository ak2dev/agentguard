from flask import Flask, redirect, request
app = Flask(__name__)


@app.route("/done")
def done():
    return redirect(request.args.get("next"))
