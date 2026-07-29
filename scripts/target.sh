#!/usr/bin/env bash
# target.sh — bring the vulnerable target app up/down in its isolation container.
#
#   scripts/target.sh up     # build + start (detached), wait until healthy
#   scripts/target.sh down   # stop + remove
#   scripts/target.sh logs   # follow the container logs
#   scripts/target.sh status # show health
#
# Reaches localhost:5055 on the host and host.docker.internal:5055 from the
# fuzzer container — the URL the pipeline already fuzzes.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

cmd="${1:-up}"
case "$cmd" in
  up)
    docker compose up --build -d target
    echo "Waiting for the target to become healthy..."
    for _ in $(seq 1 30); do
      status="$(docker inspect -f '{{.State.Health.Status}}' raguard-target 2>/dev/null || echo starting)"
      [ "$status" = "healthy" ] && { echo "Target healthy on http://localhost:5055"; exit 0; }
      sleep 1
    done
    echo "Target did not report healthy in time; check 'scripts/target.sh logs'." >&2
    exit 1
    ;;
  down)   docker compose down ;;
  logs)   docker compose logs -f target ;;
  status) docker inspect -f '{{.State.Health.Status}}' raguard-target ;;
  *) echo "usage: $0 {up|down|logs|status}" >&2; exit 2 ;;
esac
