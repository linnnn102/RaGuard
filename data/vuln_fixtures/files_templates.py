"""files_templates.py — TRAINING fixture (intentionally vulnerable, teacher-labeled).

Path traversal (CWE-22) and server-side template injection (CWE-1336) patterns
for the S5 corpus.
"""

import os

from flask import render_template_string, send_file
from jinja2 import Environment


def read_file(filename):
    with open("/var/data/" + filename) as f:
        return f.read()


def download(path):
    return send_file(path)


def get_log(name):
    with open(os.path.join("/logs", name)) as f:
        return f.read()


def render_page(template):
    return render_template_string(template)


def greet(name):
    return render_template_string("<p>Hello " + name + "</p>")


def make_email(user):
    env = Environment()
    return env.from_string(f"Dear {user}, your order shipped.").render()
