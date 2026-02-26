#!/bin/bash
set -e

PAUSE_DIR="/tmp/storage-run-1000/libpod/tmp"
PAUSE_PID_FILE="${PAUSE_DIR}/pause.pid"

mkdir -p "$PAUSE_DIR"

# Start a background process to occupy a PID
sleep infinity &
STALE_PID=$!

# Write that occupied PID into the pause.pid file so Podman sees a live
# process that is NOT the real pause process — a stale/mismatched entry.
echo "$STALE_PID" > "$PAUSE_PID_FILE"

echo "Planted stale pause.pid at ${PAUSE_PID_FILE} with PID ${STALE_PID}"
echo "PID ${STALE_PID} is occupied by: $(cat /proc/${STALE_PID}/cmdline 2>/dev/null | tr '\0' ' ')"

exec "$@"
