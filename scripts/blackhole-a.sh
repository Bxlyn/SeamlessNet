#!/bin/sh
# Simulate silent loss on outer QUIC Network A, leaving its interface UP.
set -eu
ACTION="${1:-}"
SRC="172.20.0.20"
DST="172.20.0.10"
PORT="4433"

show_time() {
    printf '[TEST] utc=%s uptime_s=%s action=%s\n' \
        "$(date -u '+%Y-%m-%dT%H:%M:%S.%3NZ')" \
        "$(awk '{print $1}' /proc/uptime)" "$ACTION"
}

has_rule() {
    iptables -C OUTPUT -s "$SRC" -d "$DST" -p udp --dport "$PORT" -j DROP 2>/dev/null
}

case "$ACTION" in
    on)
        if has_rule; then
            echo '[TEST] Network A blackhole rule already present'
        else
            show_time
            iptables -I OUTPUT 1 -s "$SRC" -d "$DST" -p udp --dport "$PORT" -j DROP
            echo '[TEST] Network A QUIC outbound traffic now dropped (interface remains UP)'
        fi
        ;;
    off)
        if has_rule; then
            show_time
            iptables -D OUTPUT -s "$SRC" -d "$DST" -p udp --dport "$PORT" -j DROP
            echo '[TEST] Network A blackhole removed'
        else
            echo '[TEST] No Network A blackhole rule to remove'
        fi
        ;;
    status)
        show_time
        if has_rule; then echo '[TEST] Network A blackhole: ON';
        else echo '[TEST] Network A blackhole: OFF'; fi
        ;;
    *)
        echo 'Usage: sh scripts/blackhole-a.sh on|off|status' >&2
        exit 2
        ;;
esac
