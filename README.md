# SeamlessNet

**SeamlessNet** is a Stage 1 proof-of-concept for keeping an application's connection alive when the underlying network changes. It tunnels IP packets through [Picoquic](https://github.com/private-octopus/picoquic) and uses QUIC connection migration to move traffic between two simulated network paths.

The prototype runs in Docker with a C-based client and server. **Network A** and **Network B** are Docker bridges used to simulate different access networks; this is not yet a test on real Wi-Fi, cellular, or satellite connections.

## How it works

```text
 Application (ping / HTTP / iperf3)
              |
 Client TUN (10.10.0.1)
              |
       Picoquic / QUIC
              |
    +---------+---------+
    |                   |
 Network A             Network B
 172.20.0.0/24         172.21.0.0/24
    |                   |
    +---------+---------+
              |
       QUIC server
              |
 Server TUN (10.10.0.2) -> NAT -> Test server (172.20.0.30)
```

The client monitors the active path with heartbeats. If Network A stops passing traffic, it detects degradation, probes Network B, and migrates the **existing QUIC connection**. The application's virtual IP address stays the same.

## Implemented features

- Bidirectional IP-over-QUIC tunnelling with Linux TUN interfaces.
- TCP, UDP, and ICMP traffic through the tunnel.
- Automatic Network A -> Network B migration, including silent failures while the interface stays UP.
- Early degradation detection, event logs, and one-second traffic statistics.
- Optional per-packet debug logging (off by default).

## Run locally

**Requirements:** Docker Engine / Docker Desktop with Linux containers and Docker Compose v2. Run from the project root in PowerShell or a Linux shell.

```bash
docker compose up --build -d
docker compose ps
```

Test the tunnel:

```bash
docker compose exec client curl --noproxy '*' --max-time 15 http://172.20.0.30:8080/
```

Expected response: `SeamlessNet-HTTP-OK`.

Stop everything:

```bash
docker compose down
```

## Demo and results

**[View the step-by-step demo, terminal screenshots, and analysis](docs/DEMO.md)**

Representative results from local Docker tests:

| Test | Observed result |
| --- | --- |
| Early-failover ICMP test | 116 / 120 replies; **3.33%** packet loss |
| QUIC migration probe -> path validated | **4 ms** |
| Migration probe -> first application IP reply | **208 ms** |
| Earlier 40-second TCP continuity test | **95.2 Mbit/s** receiver average; **454 MiB** received |

These are individual prototype runs, not guarantees across real networks. The 4 ms path-validation time is **not** the total application interruption.

## Scope and limitations

This is a demonstration prototype: the TUN MTU is 1000 bytes, failover currently runs **A -> B**, and only one QUIC path carries application traffic at a time. True simultaneous multipath, automatic B -> A switching, performance optimization, and real access-network testing are future work. TLS peer verification is disabled for local development and **must be enabled before deployment**.
