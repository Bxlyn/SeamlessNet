# SeamlessNet Stage 1: manual QUIC path migration

These files are **replacements** for the corresponding paths in your existing repository.
Keep the existing `Dockerfile`, `client/src/main.c`, `server/src/main.c`, and `tun.c` / `tun.h` files.

The code assumes:
- Picoquic is built in `/usr/local/picoquic` with Picotls as in your existing Dockerfile.
- `client/src/main.c` connects to `172.20.0.10:4433`.
- Client TUN is `10.10.0.1/24` with MTU 1000; server TUN is `10.10.0.2/24` with MTU 1000.
- Docker image has `gcc`, `iproute2`, `iptables`, `curl`, `openssl`, and `iputils-ping` installed.
- Linux containers run with `NET_ADMIN` and `/dev/net/tun` access.
- This is a single-client development test with the client TLS verifier disabled.

## Windows PowerShell

```powershell
docker compose down
docker compose up -d
docker compose ps
docker compose logs --tail=80 client server
```

Check addresses:

```powershell
docker compose exec client ip -o -4 addr show
docker compose exec server ip -o -4 addr show
docker compose exec client ping -c 2 -I 172.20.0.20 172.20.0.10
docker compose exec client ping -c 2 -I 172.21.0.20 172.21.0.10
docker compose exec client ip route get 172.20.0.30
```

Run the migration test in three terminals:

```powershell
# Terminal 1
docker compose exec client ping -D -i 0.2 -c 200 172.20.0.30
```

```powershell
# Terminal 2
docker compose logs -f client server
```

```powershell
# Terminal 3
docker compose exec client touch /tmp/seamlessnet-migrate
```

Wait for `[MIGRATION] Network B validated on ORIGINAL QUIC connection`.
Then identify the client interface that owns `172.20.0.20`:

```powershell
docker compose exec client ip -o -4 addr show
```

Only after validation, disable the Network A interface (replace `eth0` with the correct interface):

```powershell
docker compose exec client ip link set dev eth0 down
```

The continuous ping should keep receiving replies. Restore it after the test:

```powershell
docker compose exec client ip link set dev eth0 up
```

**Important:** A successful probe return code (`0`) does not mean migration is complete. Verify path validation, the stable connection start time, and continued application traffic after Network A is disabled. Docker bridges simulate two network paths; this is not yet a real Wi-Fi-to-cellular handover.

If a shell script reports a strange `not found` error on Windows, convert its line endings to LF in VS Code.
