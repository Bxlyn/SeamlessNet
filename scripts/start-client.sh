#!/bin/sh
set -eu
cd /usr/local/SeamlessNet
mkdir -p build

echo '[BUILD] Compiling client'
gcc client/src/main.c client/src/client.c client/src/tun.c \
    -std=gnu11 -Iclient/src -Icommon -I/usr/local/picoquic/picoquic \
    -Wl,--start-group \
    /usr/local/picoquic/libpicoquic-core.a \
    /usr/local/picoquic/libpicoquic-log.a \
    /usr/local/picoquic/_deps/picotls-build/libpicotls-core.a \
    /usr/local/picoquic/_deps/picotls-build/libpicotls-openssl.a \
    /usr/local/picoquic/_deps/picotls-build/libpicotls-minicrypto.a \
    /usr/local/picoquic/_deps/picotls-build/libpicotls-fusion.a \
    -Wl,--end-group -lssl -lcrypto -pthread -lm \
    -o build/seamlessnet-client

./build/seamlessnet-client &
client_pid=$!
trap 'kill "$client_pid" 2>/dev/null || true' INT TERM

echo '[NETWORK] Waiting for client tun0'
attempt=0
until ip -4 addr show dev tun0 2>/dev/null | grep -q '10.10.0.1/24'; do
    if ! kill -0 "$client_pid" 2>/dev/null; then
        echo '[ERROR] Client exited before tun0 was ready' >&2
        wait "$client_pid" || true
        exit 1
    fi
    attempt=$((attempt + 1))
    if [ "$attempt" -ge 100 ]; then
        echo '[ERROR] Timed out waiting for tun0' >&2
        kill "$client_pid" 2>/dev/null || true
        wait "$client_pid" || true
        exit 1
    fi
    sleep 0.2
done

# Only application traffic to the test destination enters the TUN.
# The outer QUIC routes to 172.20.0.10 and 172.21.0.10 remain direct.
ip route replace 172.20.0.30/32 dev tun0 advmss 900

echo '[NETWORK] Test route configured'
ip route get 172.20.0.30
ip route get 172.20.0.10
ip route get 172.21.0.10

echo '[CLIENT] Ready; trigger migration with:'
echo '         docker compose exec client touch /tmp/seamlessnet-migrate'
wait "$client_pid"
