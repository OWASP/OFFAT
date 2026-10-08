# Fixture app for gray-box tests: real routes whose handlers contain sinks,
# plus an unreachable helper sink. Not executed; parsed only.
import sqlite3

from flask import Flask, request

app = Flask(__name__)


@app.route("/users/<uid>", methods=["GET"])
def get_user(uid):
    db = sqlite3.connect("app.db")
    cur = db.cursor()
    cur.execute("SELECT * FROM users WHERE id = '%s'" % uid)  # SQLi, reachable
    return cur.fetchone()


@app.get("/echo")
def echo():
    msg = request.args.get("msg", "")
    return f"<div>{msg}</div>"  # reflected content
