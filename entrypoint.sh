#!/bin/bash
set -e

# Start a background process IMMEDIATELY (before any subshells) so it
# grabs the lowest available PID in the container (typically PID 2).
sleep infinity &
STALE_PID=$!

# Discover the correct pause.pid location for rootless podman.
# For rootless, pause.pid lives at $XDG_RUNTIME_DIR/libpod/tmp/pause.pid.
# The storage RunRoot sits under the same runtime dir (sometimes with a
# /containers/storage suffix), so we strip that suffix to recover the
# base runtime directory.
find_pause_dir() {
    if [ -n "$XDG_RUNTIME_DIR" ]; then
        echo "${XDG_RUNTIME_DIR}/libpod/tmp"
        return
    fi

    local run_root
    run_root=$(podman info --format '{{.Store.RunRoot}}' 2>/dev/null) || true
    if [ -n "$run_root" ]; then
        local runtime_dir="${run_root%/containers/storage*}"
        echo "${runtime_dir}/libpod/tmp"
        return
    fi

    echo "/tmp/storage-run-$(id -u)/libpod/tmp"
}

PAUSE_DIR=$(find_pause_dir)
PAUSE_PID_FILE="${PAUSE_DIR}/pause.pid"
mkdir -p "$PAUSE_DIR"

# Write the occupied PID into pause.pid so Podman sees a live process
# that is NOT the real pause process — a stale/mismatched entry.
echo "$STALE_PID" > "$PAUSE_PID_FILE"

echo "Planted stale pause.pid at ${PAUSE_PID_FILE} with PID ${STALE_PID}"
echo "PID ${STALE_PID} is occupied by: $(cat /proc/${STALE_PID}/cmdline 2>/dev/null | tr '\0' ' ')"

exec "$@"
