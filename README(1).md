# SeamlessNet Stage 1 — Early failover and timing instrumentation

This iteration modifies the **previously working** silent-failover implementation. It is designed for your current Docker/Picoquic prototype, with a 1000-byte TUN MTU, existing single-path QUIC connection, and two Docker networks.

## Files to copy into the existing repository

- Replace `client/src/client.c`.
- Replace `common/seamlessnet_monitor.h`.
- Replace `compose.yaml` (or add only `SEAMLESSNET_EARLY_WARNING_MS` under client.environment).
- Add `scripts/blackhole-a.sh` (optional but recommended for reproducible testing).
- `tests/test_heartbeat.c` and `tests/stubs/` are optional local unit/syntax tests.

`server/src/server.c`, `main.c`, `tun.c`, `tun.h`, and both existing startup scripts are unchanged. Keep your existing working versions. **Do not replace your Dockerfile.**

## What this version actually implements

- **Early switching:** After 750 ms with neither heartbeat ACKs nor authenticated application replies, the client initiates the existing Network A → Network B single-path QUIC migration, without waiting for the 1500 ms hard-failure threshold. Network B must already be interface-UP.
- **Hard timeout:** Still logged at 1500 ms if the path remains unresponsive; it is a fallback/diagnostic threshold, not a prerequisite for the early switch.
- **Interface-down failover:** Still requests immediate migration, checked every 100 ms.
- **Migration timing:** Logs monotonic timestamps and durations for probe request → path available and path available → first valid IP reply. These are not exact failure-onset timestamps. The blackhole helper logs the approximate fault-injection time.
- **Logging:** The original event logs, 1-second traffic/queue/drop/heartbeat statistics, and opt-in per-packet debugging remain intact.
- **Retries:** The existing 3-attempt, 3-second retry mechanism is unchanged.
- **Scope:** A → B only. A path probe on **single-path** QUIC replaces the default path once validated; this is **not** simultaneous standby-path validation. Bidirectional failback and multipath standby are future steps.

## Configure and restart — Windows PowerShell

Save/commit the working version first. Then replace/add the files and run:

```powershell
docker compose up -d --force-recreate client
docker compose logs --tail=50 client
```

The client startup script compiles `client.c` at container startup. No Docker image rebuild is required for these source-only changes.

Defaults in `compose.yaml`:

```yaml
SEAMLESSNET_HEARTBEAT_INTERVAL_MS: 250
SEAMLESSNET_EARLY_WARNING_MS: 750
SEAMLESSNET_FAILOVER_TIMEOUT_MS: 1500
SEAMLESSNET_DEBUG_PACKETS: 0
```

**Thresholds are experimental**. Lower warning values can trigger false switches during congestion, scheduling delays, or occasional heartbeat loss. For example, to compare with the old behavior set `SEAMLESSNET_EARLY_WARNING_MS=1500` and `SEAMLESSNET_FAILOVER_TIMEOUT_MS=1750` before recreating the client. When benchmarking, repeat at least 5 times and compare loss and handover interruption, not just one run.

## Reproducible silent-failure experiment

Verify `docker compose exec client ip -br addr` shows Network A (`172.20.0.20`) and Network B (`172.21.0.20`) UP. Ensure the previous firewall blackhole rule is removed:

```powershell
docker compose exec client sh scripts/blackhole-a.sh off
```

In **PowerShell terminal 1**, start application traffic:

```powershell
docker compose exec client ping -D -i 0.2 -c 120 172.20.0.30
```

In **terminal 2**, watch events (1-second STATS remain available in full logs):

```powershell
docker compose logs -f client server | Select-String 'HEALTH|FAILOVER|MIGRATION|PATH|RECOVERY|ERROR'
```

In **terminal 3**, wait 5 seconds and inject a silent outage:

```powershell
docker compose exec client sh scripts/blackhole-a.sh on
```

Expected events: `Network A DEGRADED` → `reason=5` probe → `PATH AVAILABLE` on 172.21 → `Network B validated` → `RECOVERY first IP reply`. The original QUIC connection start time should not change. The application IP route remains via `tun0`.

Restore Network A for subsequent runs:

```powershell
docker compose exec client sh scripts/blackhole-a.sh off
```

**For another A → B test**, recreate the client so the QUIC connection starts again on Network A:

```powershell
docker compose up -d --force-recreate client
```

## How to read timing events

- `mono_ms`: client CLOCK_MONOTONIC milliseconds; comparable between client events.
- `probe_to_validated_ms`: time from most recent migration request to Picoquic's `path_available` callback.
- `last_good_to_validated_ms`: time since last observed heartbeat ACK or authenticated application response when the request was made, plus validation time. **Not** exact failure-onset → recovery time.
- `validation_to_app_reply_ms`: time from path validation until the first successfully injected application IP packet. This depends on application traffic timing and is **not** the total handover interruption.
- Missing ping sequence numbers × 200 ms gives an approximate interruption/loss window. Use `ping -D` timestamps for a better application-level timeline.

`quic_tx` in STATS counts accepted DATAGRAM queue submissions, **not** confirmed physical network transmissions. Per-packet logs remain disabled unless `SEAMLESSNET_DEBUG_PACKETS=1`.

## What is next

Once early switching reduces packet loss reliably without spurious migration, implement **bidirectional A ↔ B failover** with hysteresis, followed by **negotiated QUIC multipath** if a validated standby path is required. Do not confuse early single-path migration with multipath prevalidation.

## Validation limitations

This patch can be checked using GCC syntax stubs and heartbeat unit tests, but those stubs are not Picoquic. Run the real compilation and Docker test in your environment. The prototype still disables TLS peer verification with `picoquic_set_null_verifier()`; it must not be deployed as-is on an untrusted network.
