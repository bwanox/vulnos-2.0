"""Intentionally vulnerable sample Flask app.

Planted flaws (for the CORE slicer to detect):
1. Command injection: request.args -> subprocess.run(shell=True)
2. SQL injection: request.args -> cursor.execute(string concat)
3. Safe parameterized query (should NOT be flagged — false-positive case)
"""

from __future__ import annotations

import sqlite3
import subprocess
from flask import Flask, request

app = Flask(__name__)


@app.route("/ping")
def ping():
    """VULN: command injection via user-controlled ``host``."""
    host = request.args.get("host", "")
    command = f"ping -c 1 {host}"
    subprocess.run(command, shell=True)
    return "ok"


@app.route("/user")
def user():
    """VULN: SQL injection via string concatenation into ``execute``."""
    user_id = request.args.get("id", "")
    conn = sqlite3.connect(":memory:")
    cur = conn.cursor()
    cur.execute("CREATE TABLE users (id INTEGER)")
    query = "SELECT * FROM users WHERE id = " + user_id
    cur.execute(query)
    return str(cur.fetchall())


@app.route("/user_safe")
def user_safe():
    """SAFE: parameterized query — slicer should not flag this."""
    user_id = request.args.get("id", "")
    conn = sqlite3.connect(":memory:")
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    return str(cur.fetchall())


@app.route("/open_file")
def open_file():
    """VULN: arbitrary file read via user-controlled path to ``open()``."""
    path = request.args.get("path", "")
    with open(path) as fh:  # noqa: S102 (intentional for demo)
        return fh.read()
