# SeamlessNet — Stage 1 demo

This page documents how SeamlessNet keeps an application running when **Network A silently stops passing QUIC traffic**. The client should detect the problem, migrate the **same QUIC connection** to Network B, and resume application traffic without restarting `ping` or `iperf3`.

The screenshots below are **placeholders** until you add your own PNGs to `docs/images/`. Use the filenames shown so the images appear automatically on GitHub.

## Demo environment

| Component | Address / role |
| --- | --- |
| Client TUN | `10.10.0.1/24`, MTU 1000 |
| Server TUN | `10.10.0.2/24`, MTU 1000 |
| Network A | Client `172.20.0.20` -> server `172.20.0.10` |
| Network B | Client `172.21.0.20` -> server `172.21.0.10` |
| Test destination | `172.20.0.30` (HTTP 8080, iperf3 5201) |

Use **three PowerShell terminals** in your project directory: one for application traffic, one for logs, and one for failure injection. Network A's Linux interface name may vary; the addresses above identify the networks reliably.

## 1. Start SeamlessNet

Start from a clean, working Network A connection:

```powershell
docker compose up --build -d
docker compose exec client sh scripts/blackhole-a.sh off
docker compose up -d --force-recreate client
docker compose ps
docker compose exec client ip -br addr
docker compose exec client ip route get 172.20.0.30
```

**Screenshot 01 — `01-startup.png`:** Show the three running containers, the client addresses on both networks, and the test destination routed through `tun0`.

![Docker containers, network interfaces, and TUN route](images/01-startup.png)

**Interpretation:** The client and server have two potential outer paths, while the application's traffic enters the same virtual TUN interface. This is the baseline before failover.

## 2. Confirm the application works

In **Terminal 1**, test HTTP:

```powershell
docker compose exec client curl --noproxy '*' --max-time 15 http://172.20.0.30:8080/
```

Expected: `SeamlessNet-HTTP-OK`.

Then start a timed ping test and **leave it running**:

```powershell
docker compose exec client ping -D -i 0.2 -c 120 172.20.0.30
```

**Screenshot 02 — `02-before-failure.png`:** Show the successful HTTP response and/or the first several successful ping replies before failure injection.

![Successful HTTP and baseline ping](images/02-before-failure.png)

**Interpretation:** The tunnel transports real application traffic before any network disruption.

## 3. Show the monitoring logs

In **Terminal 2**, follow event logs and one-second statistics:

```powershell
docker compose logs -f client server | Select-String 'STATS|HEALTH|FAILOVER|MIGRATION|PATH|RECOVERY|ERROR'
```

**Screenshot 03 — `03-monitoring.png`:** Capture one or two `[STATS]` entries with packet counts, bytes, throughput, drops, and queue occupancy. Keep per-packet debug logging disabled.

![One-second SeamlessNet statistics](images/03-monitoring.png)

**Interpretation:** Statistics summarize tunnel activity without producing a log entry for every packet. These are application/tunnel-level counters, not a measurement of physical wire throughput.

## 4. Simulate a silent Network A failure

While the ping test is running, in **Terminal 3** run:

```powershell
docker compose exec client sh scripts/blackhole-a.sh on
docker compose exec client sh scripts/blackhole-a.sh status
docker compose exec client ip -br addr
```

**Screenshot 04 — `04-silent-failure.png`:** Show the blackhole status as ON and the Network A interface still UP.

![Silent failure injected while interface remains up](images/04-silent-failure.png)

**Interpretation:** The script drops outbound QUIC packets on Network A without administratively disabling the interface. This is a more realistic failure-detection test than `ip link set down`.

## 5. Capture automatic migration and recovery

Wait a few seconds, then in **Terminal 3** run:

```powershell
docker compose logs --since=2m client server | Select-String 'HEALTH|FAILOVER|MIGRATION|PATH|RECOVERY|ERROR'
```

**Screenshot 05 — `05-migration-events.png`:** Include the `Network A DEGRADED` event, failover request, probe, `PATH AVAILABLE` with `172.21.0.20`, and first application-reply recovery event. Keep the connection start value visible if possible.

![Early warning, QUIC path validation, and application recovery](images/05-migration-events.png)

**Interpretation:** Picoquic validates Network B on the existing connection. The inner application IP address remains unchanged. A successful probe request alone is not enough; the `PATH AVAILABLE` and application-recovery events are the meaningful evidence.

## 6. Record the ping result

Allow the original 120-packet ping to finish **without restarting it**.

**Screenshot 06 — `06-ping-results.png`:** Show the missing ICMP sequence numbers around the failure and the final ping statistics in the same terminal capture (use two screenshots if needed).

![Ping resumes and final loss statistics](images/06-ping-results.png)

**Interpretation:** The application resumes after a short interruption. Missing sequences estimate application-level packet loss, not the exact internal QUIC migration time.

### Recorded early-failover result

The following numbers come from a previous successful early-failover test. Replace them with your final demo's values if different.

| Measurement | Observed |
| --- | ---: |
| ICMP requests sent | 120 |
| ICMP replies received | 116 |
| Packet loss | **3.33% (4 packets)** |
| Probe request -> Network B validated | **4 ms** |
| Path validation -> first IP reply | **204 ms** |
| Probe request -> first IP reply | **208 ms** |
| Last observed good traffic -> validation | **810 ms** |

The previous silent-failure version lost **8 of 91 pings (8.79%)** in a separate test. The new result is encouraging, but single runs of different lengths do not establish a repeatable improvement. The **208 ms** figure is measured from the migration probe, not from the moment the network originally failed.

## 7. Optional: prove a TCP session also survives

For a stronger demo, run a **separate** 40-second test. First restore Network A and restart the client so the connection starts on Network A again:

```powershell
docker compose exec client sh scripts/blackhole-a.sh off
docker compose up -d --force-recreate client
```

In **Terminal 1**:

```powershell
docker compose exec client iperf3 -c 172.20.0.30 -p 5201 -t 40 -i 1 -M 900
```

About 10 seconds into the test, in **Terminal 3**:

```powershell
docker compose exec client sh scripts/blackhole-a.sh on
```

Let `iperf3` finish normally; **do not press Ctrl+C**. Then capture the migration events again:

```powershell
docker compose logs --since=2m client server | Select-String 'HEALTH|FAILOVER|MIGRATION|PATH|RECOVERY|ERROR'
```

**Screenshot 07 — `07-tcp-results.png`:** Show the final sender **and receiver** summaries of the uninterrupted 40-second `iperf3` command.

![TCP transfer completed during failover](images/07-tcp-results.png)

**Screenshot 08 — `08-tcp-migration.png`:** Show the automatic migration events from that same TCP run.

![Automatic migration events during the TCP transfer](images/08-tcp-migration.png)

**Interpretation:** If the same TCP command completes with matching sender/receiver data totals and Network B validation appears in the corresponding logs, the test demonstrates application-session continuity. An earlier, separate TCP failover test completed **454 MiB** at **95.2 Mbit/s** receiver average, with **694 retransmissions**; don't label those earlier values as results of this new run unless your new output matches.

## 8. Restore the test environment

```powershell
docker compose exec client sh scripts/blackhole-a.sh off
docker compose up -d --force-recreate client
```

For a complete shutdown:

```powershell
docker compose down
```

## Conclusion

The Stage 1 prototype demonstrates IP-over-QUIC tunnelling, automatic detection of an unresponsive network path, migration to another Docker network, and application traffic recovery **without recreating the QUIC connection**. The current implementation is a controlled A -> B prototype; real Wi-Fi/cellular/satellite switching, simultaneous standby paths, and production-grade security remain future work.

---

### Screenshot checklist

Save screenshots from Windows using **Win + Shift + S**. Store them as PNG files in `docs/images/` and commit them with this page.

| Filename | What must be visible |
| --- | --- |
| `01-startup.png` | Containers, both outer IPs, `tun0` route |
| `02-before-failure.png` | HTTP response and successful baseline ping |
| `03-monitoring.png` | `[STATS]` with 1-second counters |
| `04-silent-failure.png` | Blackhole ON; interface still UP |
| `05-migration-events.png` | Degraded -> probe -> validated -> recovery |
| `06-ping-results.png` | Missing sequences and final ping summary |
| `07-tcp-results.png` | Completed TCP sender and receiver summaries (optional) |
| `08-tcp-migration.png` | Migration events from the same TCP run (optional) |

Crop out unrelated terminals and personal paths; leave commands, timestamps, and results legible. Use actual terminal output, not edited or recreated results.
