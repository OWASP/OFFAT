# Data-access helpers: the sink lives two calls away from the route.
import sqlite3


def conn():
    return sqlite3.connect("app.db")


def find_user_by_name(name):
    q = "SELECT * FROM users WHERE name = '" + name + "'"
    return run_query(q)


def find_user_safe(name):
    return conn().execute("SELECT * FROM users WHERE name = ?", (name,)).fetchone()


def run_query(sql):
    return conn().execute(sql).fetchall()


def lookup(value):
    # Called with tainted data from one route and a constant from another:
    # matched call/return keeps the constant caller clean.
    return value.strip()
