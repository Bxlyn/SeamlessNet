#ifndef SEAMLESSNET_MONITOR_H
#define SEAMLESSNET_MONITOR_H

/* Shared, header-only Stage 1 instrumentation and heartbeat framing.
 * QUIC DATAGRAMs are unreliable: the client sends SNHB probes and the
 * server echoes acknowledgements. They never enter either TUN device.
 */
#include <inttypes.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define SN_HB_SIZE 16
#define SN_HB_PING 1
#define SN_HB_ACK  2

static inline uint64_t sn_monotonic_ms(void)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) return 0;
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}

static inline void sn_log(const char* role, const char* level, const char* fmt, ...)
{
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    struct tm utc;
    gmtime_r(&ts.tv_sec, &utc);
    char when[32];
    strftime(when, sizeof(when), "%H:%M:%S", &utc);
    flockfile(stdout);
    fprintf(stdout, "[%s.%03ldZ] [%s] [%s] ", when, ts.tv_nsec / 1000000L, role, level);
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stdout, fmt, ap);
    va_end(ap);
    fputc('\n', stdout);
    fflush(stdout);
    funlockfile(stdout);
}

static inline int sn_env_flag(const char* name)
{
    const char* v = getenv(name);
    return v != NULL && (!strcmp(v, "1") || !strcmp(v, "true") || !strcmp(v, "yes"));
}

static inline unsigned sn_env_u32(const char* name, unsigned fallback,
                                   unsigned min_value, unsigned max_value)
{
    const char* v = getenv(name);
    if (v == NULL || *v == '\0') return fallback;
    char* end = NULL;
    unsigned long n = strtoul(v, &end, 10);
    if (*end != '\0' || n < min_value || n > max_value) return fallback;
    return (unsigned)n;
}

/* Network-byte-order independent wire encoding. */
static inline void sn_hb_make(uint8_t out[SN_HB_SIZE], uint8_t type, uint64_t sequence)
{
    out[0] = 'S'; out[1] = 'N'; out[2] = 'H'; out[3] = 'B';
    out[4] = 1; out[5] = type; out[6] = 0; out[7] = 0;
    for (unsigned i = 0; i < 8; ++i)
        out[8 + i] = (uint8_t)(sequence >> (56 - 8 * i));
}

/* Returns 1 only for a recognized heartbeat. */
static inline int sn_hb_parse(const uint8_t* p, size_t n,
                              uint8_t* type, uint64_t* sequence)
{
    if (n != SN_HB_SIZE || memcmp(p, "SNHB", 4) != 0 || p[4] != 1 ||
        (p[5] != SN_HB_PING && p[5] != SN_HB_ACK) || p[6] || p[7]) return 0;
    uint64_t seq = 0;
    for (unsigned i = 0; i < 8; ++i) seq = (seq << 8) | p[8 + i];
    *type = p[5];
    *sequence = seq;
    return 1;
}

/* Only infer a silent failure after probes have been sent AND neither
 * heartbeat acknowledgements nor authenticated application replies arrive. */
static inline int sn_silent_failure(uint64_t now_ms, uint64_t last_ack_ms,
                                    uint64_t last_rx_ms, uint64_t heartbeat_tx,
                                    uint64_t timeout_ms)
{
    return heartbeat_tx > 0 && last_ack_ms && last_rx_ms &&
           now_ms >= last_ack_ms && now_ms >= last_rx_ms &&
           now_ms - last_ack_ms >= timeout_ms &&
           now_ms - last_rx_ms >= timeout_ms;
}

typedef struct {
    atomic_uint_fast64_t tun_in_pkts, tun_in_bytes;
    atomic_uint_fast64_t tun_out_pkts, tun_out_bytes;
    atomic_uint_fast64_t quic_tx_pkts, quic_tx_bytes;
    atomic_uint_fast64_t quic_rx_pkts, quic_rx_bytes;
    atomic_uint_fast64_t drops, queue_full, queue_errors;
    atomic_uint_fast64_t hb_tx, hb_rx;
    atomic_uint_fast64_t queue_peak;
} sn_stats_t;

static inline void sn_stats_init(sn_stats_t* s)
{
    atomic_init(&s->tun_in_pkts, 0);
    atomic_init(&s->tun_in_bytes, 0);
    atomic_init(&s->tun_out_pkts, 0);
    atomic_init(&s->tun_out_bytes, 0);
    atomic_init(&s->quic_tx_pkts, 0);
    atomic_init(&s->quic_tx_bytes, 0);
    atomic_init(&s->quic_rx_pkts, 0);
    atomic_init(&s->quic_rx_bytes, 0);
    atomic_init(&s->drops, 0);
    atomic_init(&s->queue_full, 0);
    atomic_init(&s->queue_errors, 0);
    atomic_init(&s->hb_tx, 0);
    atomic_init(&s->hb_rx, 0);
    atomic_init(&s->queue_peak, 0);
}

typedef struct {
    uint64_t tun_in_pkts, tun_in_bytes;
    uint64_t tun_out_pkts, tun_out_bytes;
    uint64_t quic_tx_pkts, quic_tx_bytes;
    uint64_t quic_rx_pkts, quic_rx_bytes;
    uint64_t drops, queue_full, queue_errors;
    uint64_t hb_tx, hb_rx;
    uint64_t last_report_ms;
} sn_stats_snapshot_t;

static inline void sn_stats_peak(sn_stats_t* s, uint64_t value)
{
    uint_fast64_t old = atomic_load(&s->queue_peak);
    while (value > old && !atomic_compare_exchange_weak(&s->queue_peak, &old, value)) { }
}

static inline void sn_stats_report(const char* role, sn_stats_t* s,
                                   sn_stats_snapshot_t* prev,
                                   unsigned queue_occupancy, unsigned queue_capacity,
                                   uint64_t heartbeat_ack_age_ms)
{
    uint64_t now = sn_monotonic_ms();
    if (now - prev->last_report_ms < 1000) return;
    double seconds = prev->last_report_ms ? (double)(now - prev->last_report_ms) / 1000.0 : 1.0;
    uint64_t ti = atomic_load(&s->tun_in_pkts), tib = atomic_load(&s->tun_in_bytes);
    uint64_t to = atomic_load(&s->tun_out_pkts), tob = atomic_load(&s->tun_out_bytes);
    uint64_t qt = atomic_load(&s->quic_tx_pkts), qtb = atomic_load(&s->quic_tx_bytes);
    uint64_t qr = atomic_load(&s->quic_rx_pkts), qrb = atomic_load(&s->quic_rx_bytes);
    uint64_t drops = atomic_load(&s->drops);
    uint64_t full = atomic_load(&s->queue_full);
    uint64_t qerr = atomic_load(&s->queue_errors);
    uint64_t hbtx = atomic_load(&s->hb_tx), hbrx = atomic_load(&s->hb_rx);
    uint64_t delta_qtb = qtb - prev->quic_tx_bytes;
    uint64_t delta_qrb = qrb - prev->quic_rx_bytes;
    sn_log(role, "STATS",
           "tun_in=%" PRIu64 "pkt/%" PRIu64 "B tun_out=%" PRIu64 "pkt/%" PRIu64 "B "
           "quic_tx=%" PRIu64 "pkt/%" PRIu64 "B quic_rx=%" PRIu64 "pkt/%" PRIu64 "B "
           "tx=%.2fMbps rx=%.2fMbps drops=%" PRIu64 "(+%" PRIu64 ") "
           "q=%u/%u peak=%" PRIu64 " q_full=%" PRIu64 " q_err=%" PRIu64 " "
           "hb_tx=%" PRIu64 " hb_rx=%" PRIu64 " hb_ack_age=%" PRIu64 "ms",
           ti - prev->tun_in_pkts, tib - prev->tun_in_bytes,
           to - prev->tun_out_pkts, tob - prev->tun_out_bytes,
           qt - prev->quic_tx_pkts, delta_qtb,
           qr - prev->quic_rx_pkts, delta_qrb,
           (double)delta_qtb * 8.0 / (seconds * 1000000.0),
           (double)delta_qrb * 8.0 / (seconds * 1000000.0),
           drops, drops - prev->drops, queue_occupancy, queue_capacity,
           atomic_load(&s->queue_peak), full, qerr, hbtx, hbrx,
           heartbeat_ack_age_ms);
    prev->tun_in_pkts = ti; prev->tun_in_bytes = tib;
    prev->tun_out_pkts = to; prev->tun_out_bytes = tob;
    prev->quic_tx_pkts = qt; prev->quic_tx_bytes = qtb;
    prev->quic_rx_pkts = qr; prev->quic_rx_bytes = qrb;
    prev->drops = drops; prev->queue_full = full; prev->queue_errors = qerr;
    prev->hb_tx = hbtx; prev->hb_rx = hbrx; prev->last_report_ms = now;
}

#endif
