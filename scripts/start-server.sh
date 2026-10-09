#!/bin/sh
set -eu
cd /usr/local/SeamlessNet

mkdir -p build certs

if [ ! -s certs/cert.pem ] || [ ! -s certs/key.pem ]; then
    echo '[SETUP] Generating development-only TLS certificate'
    openssl req -x509 -newkey rsa:2048 \
        -keyout certs/key.pem -out certs/cert.pem \
        -days 365 -nodes -subj '/CN=seamlessnet-server'
fi
chmod 600 certs/key.pem

echo '[BUILD] Compiling server'
gcc server/src/main.c server/src/server.c server/src/tun.c \
    -Iserver/src -I/usr/local/picoquic/picoquic \
    -Wl,--start-group \
    /usr/local/picoquic/libpicoquic-core.a \
    /usr/local/picoquic/libpicoquic-log.a \
    /usr/local/picoquic/_deps/picotls-build/libpicotls-core.a \
    /usr/local/picoquic/_deps/picotls-build/libpicotls-openssl.a \
    /usr/local/picoquic/_deps/picotls-build/libpicotls-minicrypto.a \
    /usr/local/picoquic/_deps/picotls-build/libpicotls-fusion.a \
    -Wl,--end-group -lssl -lcrypto -pthread -lm \
    -o build/seamlessnet-server

echo '[NETWORK] Configuring forwarding and NAT'
[ "$(cat /proc/sys/net/ipv4/ip_forward)" = 1 ] || {
    echo '[ERROR] Enable net.ipv4.ip_forward=1 in compose.yaml' >&2
    exit 1
}

# These rules only forward to the controlled test destination.
# No assumption that Docker Network A is eth0 or eth1.
iptables -t nat -C POSTROUTING -s 10.10.0.0/24 -d 172.20.0.30/32 \
    -j MASQUERADE 2>/dev/null || \
iptables -t nat -A POSTROUTING -s 10.10.0.0/24 -d 172.20.0.30/32 \
    -j MASQUERADE
iptables -C FORWARD -i tun0 -d 172.20.0.30/32 \
    -j ACCEPT 2>/dev/null || \
iptables -A FORWARD -i tun0 -d 172.20.0.30/32 -j ACCEPT
iptables -C FORWARD -o tun0 -s 172.20.0.30/32 \
    -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || \
iptables -A FORWARD -o tun0 -s 172.20.0.30/32 \
    -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

echo '[SERVER] Starting SeamlessNet'
exec ./build/seamlessnet-server
