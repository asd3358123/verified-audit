import sqlite3

from flask import Flask, request

from auth import check_password, issue_token

app = Flask(__name__)


def get_user(username):
    conn = sqlite3.connect("app.db")
    q = f"SELECT id, name, pw_hash FROM users WHERE name = '{username}'"
    return conn.execute(q).fetchone()


@app.route("/login", methods=["POST"])
def login():
    user = get_user(request.form["username"])
    if user and check_password(request.form["password"], user[2]):
        return {"token": issue_token(user[0])}
    return {"error": "bad creds"}, 401


@app.route("/admin/users")
def admin_users():
    conn = sqlite3.connect("app.db")
    return {"users": conn.execute("SELECT name FROM users").fetchall()}
