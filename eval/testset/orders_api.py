"""orders_api.py — HELD-OUT eval fixture (NOT part of the training corpus).

Intentionally-vulnerable handlers used only to score RaGuard's detector against
the gold labels in eval/labels/orders_api.labels.json. This file must never be
scanned for training data — keep it out of config/corpus_sources.yaml.

Three functions, one per label class: a SQL injection, an OS command injection,
and a benign handler that should produce no findings.
"""

import os
import sqlite3

DB = "orders.db"


def get_order(order_id):
    # CWE-89: `order_id` is f-string-concatenated straight into the SQL text.
    conn = sqlite3.connect(DB)
    cur = conn.cursor()
    cur.execute(f"SELECT * FROM orders WHERE id = '{order_id}'")
    return cur.fetchall()


def export_orders(fmt):
    # CWE-78: user-controlled `fmt` is interpolated into a shell command.
    os.system(f"tar czf /tmp/orders.{fmt} /var/orders")
    return f"/tmp/orders.{fmt}"


def list_orders(limit):
    # Benign: parameterized query, no shell, input coerced to int → expect [].
    conn = sqlite3.connect(DB)
    cur = conn.cursor()
    cur.execute("SELECT id, total FROM orders LIMIT ?", (int(limit),))
    return cur.fetchall()
