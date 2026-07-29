"""vuln_dashboard.py — intentionally vulnerable Flask target for the RaGuard pipeline.

A small "internal ops dashboard" that deliberately packs several classes of
web vulnerabilities so the analyze → fuzz → mitigate pipeline has a rich target.
Do NOT deploy this — it is a lab fixture only.

Intended vulnerabilities (ground truth in eval/labels/vuln_dashboard.labels.json):

  1. CWE-89  SQL Injection ............ get_user()     — f-string in query
  2. CWE-89  SQLi auth bypass ......... login()        — f-string user+pass in query
  3. CWE-327 Weak password hashing .... login()        — MD5 for credentials
  4. CWE-78  OS Command Injection ..... admin_ping()   — shell=True with user host
  5. CWE-22  Path Traversal ........... download()     — unsanitised path join + open
  6. CWE-79  Reflected XSS ............ search()        — unescaped input in HTML
  7. CWE-94  Server-Side Template Inj . preview()      — render_template_string(user)
  8. CWE-502 Insecure Deserialization . load_session() — pickle.loads(user bytes)
  9. CWE-918 SSRF ..................... fetch_url()     — requests.get(user url)
 10. CWE-798 Hardcoded Credentials .... module scope   — SECRET_KEY / ADMIN_TOKEN
 (   CWE-489 Active debug ............. __main__        — app.run(debug=True)      )

Combinable exploit chains:
  • Chain A (auth → RCE):   SQLi bypass in /login  →  admin session
                            →  /admin/ping command injection.
  • Chain B (leak → auth):  /download?path=../vuln_dashboard.py leaks ADMIN_TOKEN
                            →  authenticate to /admin/ping (RCE).
  • Chain C (SSRF pivot):   /fetch?url=http://localhost/admin/... reaches
                            internal-only endpoints from the server's context.
  • Chain D (direct RCE):   /preview (SSTI) or /api/session (pickle) → code exec.
"""

import base64
import hashlib
import os
import pickle
import sqlite3
import subprocess

import requests
from flask import Flask, redirect, render_template_string, request, session

app = Flask(__name__)

# CWE-798 / CWE-259: secrets hardcoded in source (leakable via Chain B).
SECRET_KEY = "dev-secret-key-please-change"
ADMIN_TOKEN = "s3cr3t-admin-token"
DB_PATH = "dashboard.db"
FILES_DIR = os.path.join(os.path.dirname(__file__), "public")

app.secret_key = SECRET_KEY


def init_db() -> None:
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user',
            email TEXT NOT NULL
        )
        """
    )
    seed = [
        ("alice", "password123", "user", "alice@example.com"),
        ("admin", "admin", "admin", "admin@example.com"),
    ]
    for username, pw, role, email in seed:
        cur.execute(
            "INSERT OR IGNORE INTO users (username, password, role, email) VALUES (?, ?, ?, ?)",
            (username, hashlib.md5(pw.encode()).hexdigest(), role, email),
        )
    conn.commit()
    conn.close()


@app.get("/user/<username>")
def get_user(username: str):
    """CWE-89: user-controlled username concatenated into the SQL query."""
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    query = f"SELECT id, username, role, email FROM users WHERE username = '{username}'"
    cur.execute(query)
    rows = cur.fetchall()
    conn.close()
    return {"query": query, "rows": rows}


@app.route("/login", methods=["GET", "POST"])
def login():
    """CWE-89 (auth bypass) + CWE-327 (MD5): both credentials f-stringed into SQL."""
    username = request.values.get("username", "")
    password = request.values.get("password", "")
    pw_hash = hashlib.md5(password.encode()).hexdigest()

    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    query = (
        "SELECT username, role FROM users "
        f"WHERE username = '{username}' AND password = '{pw_hash}'"
    )
    cur.execute(query)
    row = cur.fetchone()
    conn.close()

    if row:
        session["username"] = row[0]
        session["role"] = row[1]
        return {"status": "ok", "role": row[1], "query": query}
    return {"status": "denied", "query": query}, 401


def _is_admin() -> bool:
    """Admin gate — satisfied by the SQLi login (Chain A) or the leaked token (Chain B)."""
    return session.get("role") == "admin" or request.values.get("token") == ADMIN_TOKEN


@app.get("/admin/ping")
def admin_ping():
    """CWE-78: user-controlled host passed to a shell (RCE target of Chain A/B)."""
    if not _is_admin():
        return {"error": "admin only"}, 403
    host = request.args.get("host", "127.0.0.1")
    output = subprocess.check_output(f"ping -c 1 {host}", shell=True, text=True)
    return {"host": host, "output": output}


@app.get("/download")
def download():
    """CWE-22: unsanitised path joined onto a base dir and opened."""
    path = request.args.get("path", "index.html")
    full = os.path.join(FILES_DIR, path)
    with open(full, "r", encoding="utf-8", errors="replace") as fh:
        return {"path": full, "content": fh.read()}


@app.get("/search")
def search():
    """CWE-79: query reflected into the HTML response without escaping."""
    q = request.args.get("q", "")
    html = f"""
    <html><body>
      <h1>Search results for: {q}</h1>
      <p>No results found.</p>
    </body></html>
    """
    return html


@app.get("/preview")
def preview():
    """CWE-94/CWE-1336: user input rendered as a Jinja2 template (SSTI → RCE)."""
    tpl = request.args.get("tpl", "Hello, {{ name }}!")
    return render_template_string(tpl, name=session.get("username", "guest"))


@app.get("/api/session")
def load_session():
    """CWE-502: base64-decoded user token deserialized with pickle (RCE)."""
    token = request.args.get("token", "")
    data = pickle.loads(base64.b64decode(token))
    return {"restored": str(data)}


@app.get("/fetch")
def fetch_url():
    """CWE-918: server fetches an arbitrary user-supplied URL (SSRF)."""
    url = request.args.get("url", "http://example.com")
    resp = requests.get(url, timeout=5)
    return {"url": url, "status": resp.status_code, "body": resp.text[:500]}


@app.get("/logout")
def logout():
    session.clear()
    return redirect("/")


if __name__ == "__main__":
    init_db()
    os.makedirs(FILES_DIR, exist_ok=True)
    # CWE-489: debug server exposes the interactive traceback console.
    # HOST defaults to loopback for safety when run directly on the host; the
    # container sets HOST=0.0.0.0 so the published port is reachable.
    app.run(
        host=os.environ.get("HOST", "127.0.0.1"),
        port=int(os.environ.get("PORT", "5055")),
        debug=True,
    )
