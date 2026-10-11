# SeamlessNet

SeamlessNet is a **Stage 1 proof-of-concept** for keeping an application's connection alive when its underlying network path changes. It uses [Picoquic](https://github.com/private-octopus/picoquic), Linux TUN interfaces, and Docker to carry IP traffic through a QUIC tunnel and automatically migrate from Network A to Network B.

Both networks are simulated Docker bridges, not real Wi-Fi, cellular, or satellite links.

## How it works

```text
Application (HTTP / ping / iperf3)
              |
       Client TUN (10.10.0.1)
              |
          QUIC client
              |
     +--------+--------+
     |                 |
 Network A          Network B
172.20.0.0/24      172.21.0.0/24
     |                 |
     +--------+--------+
              |
          QUIC server
              |
       Server TUN (10.10.0.2)
              |
       NAT -> test server (172.20.0.30)
```

The client monitors connection health using heartbeats. If Network A stops passing QUIC packets, the client detects degradation and migrates the **existing QUIC connection** to Network B. The application's virtual IP address remains unchanged.

## Implemented

- Bidirectional IP-over-QUIC transport for ICMP, TCP, and UDP.
- Automatic A -> B migration, including silent failures while Network A remains UP (verified in the demo).
- Heartbeat-based degradation detection and early failover.
- Event logs, one-second packet/byte/queue statistics, and optional debug-only per-packet logs.
- Docker Compose setup for a reproducible local demo.

## Run

Requires Docker with Linux containers and Docker Compose v2. From the project root:

```bash
docker compose up --build -d
docker compose ps
```

Test HTTP through the tunnel:

```bash
docker compose exec client curl --noproxy '*' --max-time 15 http://172.20.0.30:8080/
```

Expected: `SeamlessNet-HTTP-OK`. Stop the environment with `docker compose down`.

## Demo ex and results

**[View the step-by-step demo, screenshots, and analysis](docs/DEMO.md)**

| Measurement | Observed local result |
| --- | ---: |
| Continuous ICMP test | 2,098 / 2,102 replies; **0.1903%** loss |
| ICMP test duration | **428.313 s** (about 7 min 8 s) |
| ICMP run: probe -> Network B validated | **4 ms** |
| ICMP run: probe -> first application IP reply | **208 ms** |
| Separate 40-second TCP test | **2.35 GBytes**, **504 Mbit/s** receiver average |
| TCP run: probe -> Network B validated | **11 ms** |
| TCP run: probe -> first application IP reply | **664 ms** |

These are results from local Docker experiments, not performance guarantees. Probe-to-reply time is **not** the full time since network failure. The TCP test also recorded **6,614 retransmissions**.

## Prototype scope

The TUN MTU is 1000 bytes. Both simulated networks are available at the same time, but **one QUIC path carries application traffic at a time**; this is not simultaneous multipath transport. Automatic failover currently goes from A to B, not back again.

The QUIC idle timeout is configured to **300 seconds (5 minutes) of QUIC inactivity**. Heartbeat packets can keep the connection active even when there is no application traffic; it is not a five-minute limit on a running demo.

Real access-network testing, multipath, further optimization, and production TLS peer verification remain future work. Certificate verification is disabled for local development and must be enabled before deployment.
