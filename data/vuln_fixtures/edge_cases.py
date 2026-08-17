"""edge_cases.py — TRAINING fixture (intentionally vulnerable, teacher-labeled).

Extra variants of the three patterns the Muse teacher missed on the first pass
(a ping-style command injection, an IDOR / missing-authorization access, and a
yaml.load-style deserialization), so those edge cases are represented in the S5
training corpus. Two variants each. Disjoint from eval/testset/.
"""

import subprocess

import yaml


# ── command injection via a network utility (the `run_ping` blind spot) ────────

def nslookup_host(domain):
    return subprocess.check_output(f"nslookup {domain}", shell=True)


def traceroute(host):
    return subprocess.run("traceroute " + host, shell=True, capture_output=True)


# ── IDOR / missing authorization (the `view_invoice` blind spot) ───────────────

def get_document(doc_id):
    # returns any document by id; no check the caller owns it
    return _db_fetch("documents", doc_id)


def update_profile(user_id, data):
    # writes to any user's profile; no authorization on user_id
    return _db_update("profiles", user_id, data)


# ── insecure deserialization via YAML (the `parse_yaml` blind spot) ────────────

def load_settings(raw):
    return yaml.unsafe_load(raw)


def restore_state(blob):
    return yaml.load(blob, Loader=yaml.Loader)


def _db_fetch(table, key):
    return {}


def _db_update(table, key, data):
    return True
