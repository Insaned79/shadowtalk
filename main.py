import os
import re
import sqlite3
import time
import uuid

from flask import Flask, render_template, request, redirect, url_for, session
from jinja2.utils import markupsafe
from passlib.context import CryptContext

from filters import linebreaksbr

markupsafe.Markup()

app = Flask(__name__)
app.secret_key = os.urandom(24)
app.jinja_env.filters['linebreaksbr'] = linebreaksbr
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def connect_db():
    conn = sqlite3.connect("app.db")
    return conn


def create_tables(conn):
    c = conn.cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS users (
                    id TEXT PRIMARY KEY,
                    username TEXT NOT NULL,
                    password_hash TEXT NOT NULL
                );
                """)
    c.execute("""CREATE TABLE IF NOT EXISTS messages (
                    `id`	INTEGER PRIMARY KEY AUTOINCREMENT,
                    `user_id`	TEXT NOT NULL,
                    `message`	TEXT NOT NULL,
                    `uid`	TEXT,
                    `timestamp`	INTEGER,
                    FOREIGN KEY(`user_id`) REFERENCES `users`(`id`)
                );
                """)
    conn.commit()


def check_password(conn, username, password):
    cur = conn.cursor()
    result = cur.execute("SELECT id, password_hash FROM users WHERE username=?", (username,)).fetchone()
    if result is None:
        return None
    user_id, password_hash = result
    if pwd_context.verify(password, password_hash):
        return user_id
    else:
        return None


# def add_message(conn, user_id, message):
#     c = conn.cursor()
#     c.execute("INSERT INTO messages (user_id, message) VALUES (?, ?)", (user_id, message))
#     conn.commit()


# def get_messages(conn, user_id):
#     c = conn.cursor()
#     messages = c.execute("SELECT message FROM messages WHERE user_id=?", (user_id,)).fetchall()
#     return [message[0] for message in messages]


def delete_message_db(message_id):
    conn = connect_db()
    c = conn.cursor()
    c.execute("DELETE FROM messages WHERE uid=?", (message_id,))
    conn.commit()


@app.route("/")
def index():
    return render_template("index.html")


def add_user(conn, username, password_hash):
    c = conn.cursor()
    c.execute("SELECT id FROM users WHERE username = ?", (username,))
    user_exists = c.fetchone()
    if user_exists:
        return None
    user_id = str(uuid.uuid4())
    c.execute("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)", (user_id, username, password_hash))
    conn.commit()
    return user_id


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        # Check if the username is too simple
        if len(username) < 5 or re.search("[a-zA-Z0-9]+", username) is None:
            return "Username is too simple. Please use a more complex username."

        # Check if the password is too simple
        if len(password) < 8 or re.search("[a-z]+", password) is None or re.search("[A-Z]+",
                                                                                   password) is None or re.search(
            "[0-9]+", password) is None:
            return "Password is too simple. Please use a more complex password."

        conn = connect_db()
        password_hash = pwd_context.hash(password)
        user_id = add_user(conn, username, password_hash)

        # Check if the user_id is None, which means that the username already exists
        if user_id is None:
            return "Username already exists. Please use a different username."

        return redirect(url_for("login"))
    else:
        return render_template("register.html")


@app.route("/change_password", methods=["GET", "POST"])
def change_password():
    user_id = session.get("user_id")
    if user_id is None:
        return redirect("/login")

    if request.method == "POST":
        username = session.get("user_id")
        old_password = request.form["old_password"]
        new_password = request.form["new_password"]

        # Check if the password is too simple
        if len(new_password) < 8 or re.search("[a-z]+", new_password) is None or re.search("[A-Z]+",
                                                                                           new_password) is None or re.search(
            "[0-9]+", new_password) is None:
            return "Password is too simple. Please use a more complex password."

        conn = connect_db()
        c = conn.cursor()
        c.execute("SELECT password_hash FROM users WHERE id = ?", (username,))
        result = c.fetchone()
        if result is None:
            return "ID not found."
        password_hash = result[0]
        if not pwd_context.verify(old_password, password_hash):
            return "Old password is incorrect."

        new_password_hash = pwd_context.hash(new_password)
        c.execute("UPDATE users SET password_hash = ? WHERE id = ?", (new_password_hash, username))
        conn.commit()

        return redirect(url_for("login"))
    else:
        return render_template("change_password.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        conn = connect_db()
        user_id = check_password(conn, username, password)
        if user_id is not None:
            session["user_id"] = user_id
            return redirect("/messages")
        else:
            return render_template("login.html", error="Incorrect username or password")
    else:
        return render_template("login.html")


def get_messages_for_user(conn, user_id):
    cur = conn.cursor()
    result = cur.execute("SELECT message, timestamp,uid FROM messages WHERE user_id=?", (user_id,)).fetchall()
    return [{"message": message, "timestamp": time.ctime(timestamp), "id": uid, } for (message, timestamp, uid) in
            result]


@app.route("/messages")
def messages():
    user_id = session.get("user_id")
    if user_id is None:
        return redirect("/login")
    conn = connect_db()
    messages = get_messages_for_user(conn, user_id)
    return render_template("messages.html", messages=messages, user_id=user_id)


@app.route("/delete_message/<message_id>", methods=["POST", "GET"])
def delete_message(message_id):
    user_id = session.get("user_id")
    if user_id is None:
        return redirect("/login")
    # conn = connect_db()
    delete_message_db(message_id)
    return redirect("/messages")


def leave_message_for_user(user_id, message):
    if len(message) > 4096:
        return "Message too long, maximum length is 4096 characters"

    conn = connect_db()
    cur = conn.cursor()

    # Check if the user exists
    cur.execute("SELECT * FROM users WHERE id=?", (user_id,))
    user = cur.fetchone()
    if not user:
        return "User not found"

    # Get the user's messages in the last minute
    cur.execute("SELECT * FROM messages WHERE user_id=? AND timestamp > datetime('now', '-1 minute')", (user_id,))
    recent_messages = cur.fetchall()
    if len(recent_messages) >= 5:
        return "Too many messages, try again later"

    cur.execute("INSERT INTO messages (user_id, message, timestamp, uid) VALUES (?, ?, ?, ?)",
                (user_id, message, int(time.time()), str(uuid.uuid4())))
    conn.commit()
    return "Message left"


@app.route("/leave_message", methods=["GET", "POST"])
def leave_message():
    if request.method == "POST":
        user_id = request.form["user_id"]
        message = request.form["message"]
        result = leave_message_for_user(user_id, message)
        if result in ["User not found",
                      "Too many messages, try again later",
                      "Message too long, maximum length is 4096 characters"
                      ]:
            return result
        return redirect(url_for("index"))
    return render_template("leave_message.html")


@app.route("/leave_message4user/<user_id>", methods=["GET", "POST"])
def leave_message4user(user_id):
    if request.method == "POST":
        message = request.form["message"]
        result = leave_message_for_user(user_id, message)
        if result in ["User not found",
                      "Too many messages, try again later",
                      "Message too long, maximum length is 4096 characters"
                      ]:
            return result
        return redirect(url_for("index"))
    return render_template("leave_message4user.html", user_id=user_id)


@app.route("/logout")
def logout():
    # Clear the user session to log the user out
    session.clear()
    # Redirect the user to the login page
    return redirect(url_for("index"))


if __name__ == "__main__":
    import bjoern

    create_tables(connect_db())
    conn = connect_db()
    # app.run()
    bjoern.run(app, "127.0.0.1", 5000)
