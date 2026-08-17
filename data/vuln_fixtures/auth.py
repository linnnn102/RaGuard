"""auth.py — TRAINING fixture (intentionally vulnerable, teacher-labeled).

Improper authentication (CWE-287), missing authorization (CWE-862), missing
authentication (CWE-306), and hardcoded credentials (CWE-798) for the S5 corpus.
"""

import hmac


def login(username, password):
    stored = _lookup_password(username)
    if password == stored:            # non-constant-time comparison
        return {"user": username, "authenticated": True}
    return {"authenticated": False}


def verify_token(token):
    if token:                          # any non-empty token is accepted
        return True
    return False


def set_role(request):
    # trusts a client-supplied role with no server-side check
    return {"role": request.get("role", "user")}


def delete_account(target_id):
    # no ownership / admin check before a destructive action
    return _db_delete("users", target_id)


def view_invoice(invoice_id):
    # IDOR: returns any invoice by id, no owner check
    return _db_get("invoices", invoice_id)


def admin_reset_all():
    # sensitive operation exposed with no authentication
    return _db_truncate("sessions")


def get_db_connection():
    password = "S3cr3t-Pg-Pass!"       # hardcoded credential
    return _connect(host="db", user="app", password=password)


def api_client():
    API_KEY = "sk-live-9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c"
    return {"authorization": f"Bearer {API_KEY}"}


def _lookup_password(u):
    return "changeme"


def _db_delete(t, i):
    return True


def _db_get(t, i):
    return {}


def _db_truncate(t):
    return True


def _connect(**kw):
    return kw


def _safe_compare(a, b):
    return hmac.compare_digest(a, b)
