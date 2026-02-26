#!/bin/bash
set -e

# Start a background process IMMEDIATELY (before any subshells) so it
# grabs the lowest available PID in the container (typically PID 2).
sleep infinity &
STALE_PID=$!

PAUSE_DIR="/tmp/storage-run-$(id -u)/libpod/tmp"
PAUSE_PID_FILE="${PAUSE_DIR}/pause.pid"
mkdir -p "$PAUSE_DIR"

# Write the occupied PID into pause.pid so Podman sees a live process
# that is NOT the real pause process — a stale/mismatched entry.
printf '%d' "$STALE_PID" > "$PAUSE_PID_FILE"

echo "Planted stale pause.pid at ${PAUSE_PID_FILE} with PID ${STALE_PID}"
echo "PID ${STALE_PID} is occupied by: $(cat /proc/${STALE_PID}/cmdline 2>/dev/null | tr '\0' ' ')"

exec "$@"
