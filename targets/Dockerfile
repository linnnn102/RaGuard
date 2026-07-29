# Target-app sandbox for the RaGuard pipeline.
# =============================================
# Runs an INTENTIONALLY VULNERABLE Flask app (SQLi, CWE-78 command injection,
# CWE-94 SSTI, CWE-502 pickle, CWE-918 SSRF, CWE-22 path traversal) inside a
# container so that any payload that lands during fuzzing executes in throwaway
# container isolation instead of on the host.
#
#   Recommended (compose, from the repo root):
#     docker compose up --build target
#
#   Standalone (compose applies further runtime hardening — see docker-compose.yml):
#     docker build -t vuln-target targets/
#     docker run --rm -p 5055:5055 \
#         --read-only --tmpfs /data:rw,noexec,nosuid,size=32m \
#         --tmpfs /tmp:rw,noexec,nosuid,size=16m \
#         --cap-drop ALL --security-opt no-new-privileges:true vuln-target
#
# NOT for deployment. This is a lab fixture — never expose it to an untrusted
# network. The build context is ./targets so the image stays tiny.
FROM python:3.12-slim

# iputils-ping: gives the CWE-78 /admin/ping endpoint a real base command to run.
RUN apt-get update && \
    apt-get install -y --no-install-recommends iputils-ping && \
    rm -rf /var/lib/apt/lists/*

# flask: the app framework. requests: used by the CWE-918 SSRF /fetch endpoint.
RUN pip install --no-cache-dir flask requests

# --- rootless (OWASP Docker Security Cheat Sheet, Rule 2) ---------------------
# A fixed high UID/GID with no login shell. Nothing in the image is owned by
# this user, so a landed RCE payload cannot rewrite the app's own code — /app
# stays root-owned and world-readable only. Declared here (not just in compose)
# so a bare `docker run` is rootless too.
RUN groupadd --gid 10001 app && \
    useradd --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin app

# The app source lives in /app, owned by root and never written to. The .dockerignore
# drops caches and any stale *.db so init_db() seeds fresh.
# public/ is the base dir the CWE-22 path-traversal endpoint reads from; create it
# explicitly so the app's os.makedirs(..., exist_ok=True) is a no-op under a
# read-only rootfs.
COPY . /app/
RUN mkdir -p /app/public && chmod -R a-w /app

# --- writable state, isolated from the code ----------------------------------
# The targets create their SQLite DB (dashboard.db / sqli_lab.db) with a RELATIVE
# path, i.e. in the working directory. Pointing WORKDIR at /data means that write
# lands in a tmpfs the compose file mounts there — so the container's root
# filesystem can stay read-only (Cheat Sheet Rule 8) and the DB is discarded on
# exit, which also guarantees a clean seed every run.
RUN mkdir -p /data && chown 10001:10001 /data
WORKDIR /data

# Which target app to serve. Override at build time to swap targets, e.g.:
#   docker build -t vuln-target --build-arg APP=test_target2.py targets/
ARG APP=vuln_dashboard.py
ENV APP=${APP}

# Bind to all interfaces INSIDE the container so the published port is reachable
# from the host / fuzzer. (The app itself defaults to 127.0.0.1 on the host.)
ENV HOST=0.0.0.0
ENV PORT=5055

# No .pyc writes to attempt against the read-only /app; unbuffered so `docker
# compose logs` shows request lines as they happen.
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

EXPOSE 5055

USER 10001:10001

# /user/<name> exists on every target app and returns 200, so it is a stable
# liveness probe regardless of which APP is served.
HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=5 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:5055/user/hc')" || exit 1

# Absolute path: WORKDIR is /data (writable state), the code is in /app.
CMD ["sh", "-c", "exec python /app/\"$APP\""]
