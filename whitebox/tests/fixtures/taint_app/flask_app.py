import os
import pickle

import requests
from flask import Flask, abort, redirect, render_template_string, request, send_file
from flask_login import current_user, login_required

from pkg import db
from pkg.db import lookup
from pkg.shell import Runner
from models import Order, User

app = Flask(__name__)
UPLOADS = "/srv/uploads"


@app.route("/search")
def search():
    term = request.args.get("q", "")
    return {"rows": db.find_user_by_name(term)}                 # VULN sqli (2 hops)


@app.route("/search-safe")
def search_safe():
    return {"row": db.find_user_safe(request.args["q"])}        # SAFE parameterized


@app.route("/ping", methods=["POST"])
def ping():
    host = request.json["host"]
    return {"rc": Runner(host).ping().returncode}               # VULN cmdi via self.host


@app.route("/ping-quoted", methods=["POST"])
def ping_quoted():
    return {"rc": Runner(request.json["host"]).ping_quoted().returncode}   # SAFE quoted


@app.route("/files/<name>")
def download(name):
    return send_file(os.path.join(UPLOADS, name))               # VULN path traversal


@app.route("/files-safe/<name>")
def download_safe(name):
    return send_file(os.path.join(UPLOADS, os.path.basename(name)))   # SAFE basename


@app.route("/fetch")
def fetch():
    url = request.args.get("url")
    r = requests.get(url, timeout=5)                            # VULN ssrf
    return r.text


@app.route("/next")
def go_next():
    return redirect(request.args.get("next", "/"))              # VULN open redirect


@app.route("/hello")
def hello():
    name = request.args.get("name", "")
    return render_template_string("Hello " + name)              # VULN ssti


@app.route("/count/<int:n>")
def count(n):
    return render_template_string("n=%d" % n)                   # SAFE int converter


@app.route("/import", methods=["POST"])
def import_blob():
    return {"obj": str(pickle.loads(request.get_data()))}       # VULN deserialization


@app.route("/calc")
def calc():
    expr = request.args["e"]
    expr = int(expr)
    return {"v": eval(str(expr))}                               # SAFE reassigned via int()


@app.route("/strip")
def strip_it():
    a = lookup(request.args["x"])
    b = lookup("constant")
    os.system("echo " + b)                                      # SAFE: b comes from constant call
    return a


@app.route("/users", methods=["POST"])
def create_user():
    user = User(**request.get_json())                           # VULN mass assignment
    return {"id": user.id}


@app.route("/orders/<order_id>")
@login_required
def get_order(order_id):
    order = Order.query.get(order_id)                           # VULN BOLA (no owner check)
    return {"total": order.total}


@app.route("/my-orders/<order_id>")
@login_required
def get_my_order(order_id):
    order = Order.query.filter_by(id=order_id, owner_id=current_user.id).first()   # SAFE scoped
    return {"total": order.total}


@app.route("/receipts/<order_id>")
@login_required
def get_receipt(order_id):
    order = Order.query.get(order_id)
    if order.owner_id != current_user.id:                       # SAFE ownership check
        abort(403)
    return {"total": order.total}


def unused_helper():
    return pickle.loads(open("cache.bin", "rb").read())         # not a flow: no source
