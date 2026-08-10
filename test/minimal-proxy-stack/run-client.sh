#!/bin/sh
set -eu

wait_host="${DENBROWSER_WAIT_HOST:-proxy}"
wait_port="${DENBROWSER_WAIT_PORT:-8081}"
attempt=0

until python3 -c \
    'import socket, sys; socket.create_connection((sys.argv[1], int(sys.argv[2])), 1).close()' \
    "$wait_host" "$wait_port" 2>/dev/null; do
    attempt=$((attempt + 1))
    if [ "$attempt" -ge 30 ]; then
        echo "[machine-client] proxy did not listen on $wait_host:$wait_port within 30s" >&2
        exit 1
    fi
    sleep 1
done

exec python3 -u /usr/local/bin/test_roundtrip.py
