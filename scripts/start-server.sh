
#!/bin/sh
set -eu

cd /usr/local/SeamlessNet

echo "[SETUP] Preparing SeamlessNet server..."

mkdir -p build certs

# Generate development TLS certificate if missing.
if [ ! -s certs/cert.pem ] || [ ! -s certs/key.pem ]; then
    echo "[SETUP] Generating development certificate..."

    openssl req -x509 \
        -newkey rsa:2048 \
        -keyout certs/key.pem \
        -out certs/cert.pem \
        -days 365 \
        -nodes \
        -subj "/CN=seamlessnet-server"
fi

chmod 600 certs/key.pem

# Compile server.
echo "[BUILD] Compiling server..."


gcc \
    server/src/main.c \
    server/src/server.c \
    server/src/tun.c \
    -Iserver/src \
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
    -o build/seamlessnet-server


echo "[BUILD] Server compiled successfully."

# Docker Compose enables IP forwarding via sysctl.
if [ "$(cat /proc/sys/net/ipv4/ip_forward)" != "1" ]; then
    echo "[ERROR] IPv4 forwarding is disabled."
    exit 1
fi

echo "[NETWORK] Configuring NAT and forwarding..."

# Add rules only if they do not already exist.
iptables -t nat -C POSTROUTING \
    -s 10.10.0.0/24 -o eth0 -j MASQUERADE \
    2>/dev/null || \
iptables -t nat -A POSTROUTING \
    -s 10.10.0.0/24 -o eth0 -j MASQUERADE

iptables -C FORWARD \
    -i tun0 -o eth0 -j ACCEPT \
    2>/dev/null || \
iptables -A FORWARD \
    -i tun0 -o eth0 -j ACCEPT

iptables -C FORWARD \
    -i eth0 -o tun0 \
    -m conntrack --ctstate RELATED,ESTABLISHED \
    -j ACCEPT 2>/dev/null || \
iptables -A FORWARD \
    -i eth0 -o tun0 \
    -m conntrack --ctstate RELATED,ESTABLISHED \
    -j ACCEPT

echo "[NETWORK] NAT and forwarding configured."

echo "[SERVER] Starting SeamlessNet..."

exec ./build/seamlessnet-server
