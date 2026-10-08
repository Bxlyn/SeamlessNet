
#!/bin/sh
set -eu

cd /usr/local/SeamlessNet

echo "[SETUP] Preparing SeamlessNet client..."

mkdir -p build

# Compile client.
echo "[BUILD] Compiling client..."


gcc \
    client/src/main.c \
    client/src/client.c \
    client/src/tun.c \
    -Iclient/src \
    -I/usr/local/picoquic/picoquic \
    -Wl,--start-group \
    /usr/local/picoquic/libpicoquic-core.a \
    /usr/local/picoquic/libpicoquic-log.a \
    /usr/local/picoquic/_deps/picotls-build/libpicotls-core.a \
    /usr/local/picoquic/_deps/picotls-build/libpicotls-openssl.a \
    /usr/local/picoquic/_deps/picotls-build/libpicotls-minicrypto.a \
    /usr/local/picoquic/_deps/picotls-build/libpicotls-fusion.a \
    -Wl,--end-group \
    -lssl \
    -lcrypto \
    -pthread \
    -lm \
    -o build/seamlessnet-client


echo "[BUILD] Client compiled successfully."

# Start client in background so we can configure
# the interface it creates.
./build/seamlessnet-client &
client_pid=$!

trap 'kill "$client_pid" 2>/dev/null || true' INT TERM

echo "[NETWORK] Waiting for tun0..."

attempt=0

until ip -4 addr show dev tun0 2>/dev/null |
      grep -q "10.10.0.1/24"; do

    if ! kill -0 "$client_pid" 2>/dev/null; then
        echo "[ERROR] SeamlessNet client exited."
        wait "$client_pid" || true
        exit 1
    fi

    attempt=$((attempt + 1))

    if [ "$attempt" -ge 100 ]; then
        echo "[ERROR] Timed out waiting for tun0."
        kill "$client_pid" 2>/dev/null || true
        wait "$client_pid" || true
        exit 1
    fi

    sleep 0.2
done

echo "[NETWORK] tun0 is ready."

# Route only the HTTP test destination into the tunnel.
ip route replace \
    172.20.0.30/32 \
    dev tun0 \
    advmss 900

echo "[NETWORK] HTTP test route configured."

ip route get 172.20.0.30

echo "[CLIENT] SeamlessNet startup complete."

# Keep the container alive while the client runs.
wait "$client_pid"
