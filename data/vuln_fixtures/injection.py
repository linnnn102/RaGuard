"""injection.py — TRAINING fixture (intentionally vulnerable, teacher-labeled).

OS command injection patterns for the S5 corpus. Not runnable app code; used
only so the teacher produces CWE-78 training labels. Kept out of the eval set.
"""

import os
import subprocess


def run_ping(host):
    return os.system(f"ping -c 1 {host}")


def backup_database(name):
    subprocess.run(f"pg_dump {name} > /tmp/{name}.sql", shell=True)
    return f"/tmp/{name}.sql"


def convert_image(path):
    return os.popen("convert " + path + " /tmp/out.png").read()


def tail_log(service):
    cmd = "journalctl -u %s -n 100" % service
    return subprocess.check_output(cmd, shell=True)
