#include "picoquic.h"
#include "picoquic_packet_loop.h"
#include "tun.h"
#include "seamlessnet_monitor.h"

#include <arpa/inet.h>
#include <errno.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <poll.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define PACKET_MAX 1000
#define PACKET_QUEUE 64
#define SEAMLESSNET_IDLE_TIMEOUT_MS 300000
#define MIGRATION_TRIGGER "/tmp/seamlessnet-migrate"
#define NETWORK_A_CLIENT_IP "172.20.0.20"
#define NETWORK_B_CLIENT_IP "172.21.0.20"
#define NETWORK_B_SERVER_IP "172.21.0.10"
#define HEALTH_CHECK_INTERVAL_MS 100
#define MIGRATION_RETRY_MS 3000
#define MAX_MIGRATION_ATTEMPTS 3

enum { MIGRATION_MANUAL = 1, MIGRATION_LINK_DOWN = 2,
       MIGRATION_HEARTBEAT_TIMEOUT = 3, MIGRATION_RETRY = 4,
       MIGRATION_EARLY_WARNING = 5 };

typedef struct {
    uint8_t data[PACKET_MAX];
    size_t length;
} tunnel_packet_t;

typedef struct {
    tunnel_packet_t packets[PACKET_QUEUE];
    unsigned head, tail, count;
    pthread_mutex_t mutex;
    picoquic_cnx_t* cnx;  /* Accessed by the Picoquic network thread. */
    int server_port;
    uint16_t udp_source_port_net;
    int tun_fd;
    int debug_packets;
    unsigned heartbeat_interval_ms;
    unsigned early_warning_ms;
    unsigned failover_timeout_ms;

    atomic_int connected;
    atomic_int migrate_requested;
    atomic_int migrate_reason;
    atomic_int migration_validated;
    atomic_int heartbeat_send_requested;
    atomic_int hard_timeout_reported;
    atomic_int app_recovery_pending;
    atomic_uint_fast64_t migration_requested_at_ms;
    atomic_uint_fast64_t migration_validated_at_ms;
    atomic_uint_fast64_t migration_last_good_ms;
    atomic_uint_fast64_t heartbeat_sequence;
    atomic_uint_fast64_t heartbeat_last_ack_sequence;
    atomic_uint_fast64_t heartbeat_last_ack_ms;
    atomic_uint_fast64_t last_authenticated_rx_ms;
    sn_stats_t stats;
} client_ctx_t;

static void client_drop(client_ctx_t* ctx, const char* reason)
{
    uint64_t n = atomic_fetch_add(&ctx->stats.drops, 1) + 1;
    if (n <= 3 || n % 1000 == 0)
        sn_log("CLIENT", "WARN", "drop=%" PRIu64 " reason=%s", n, reason);
}

static int queue_packet(client_ctx_t* ctx, const uint8_t* data, size_t length)
{
    if (length == 0 || length > PACKET_MAX) {
        client_drop(ctx, "invalid/oversized TUN packet");
        return -1;
    }
    pthread_mutex_lock(&ctx->mutex);
    if (ctx->count == PACKET_QUEUE) {
        pthread_mutex_unlock(&ctx->mutex);
        atomic_fetch_add(&ctx->stats.queue_full, 1);
        client_drop(ctx, "TUN queue full");
        return -1;
    }
    tunnel_packet_t* p = &ctx->packets[ctx->tail];
    memcpy(p->data, data, length);
    p->length = length;
    ctx->tail = (ctx->tail + 1) % PACKET_QUEUE;
    ctx->count++;
    sn_stats_peak(&ctx->stats, ctx->count);
    pthread_mutex_unlock(&ctx->mutex);
    return 0;
}

static int dequeue_packet(client_ctx_t* ctx, tunnel_packet_t* output)
{
    pthread_mutex_lock(&ctx->mutex);
    if (!ctx->count) {
        pthread_mutex_unlock(&ctx->mutex);
        return 0;
    }
    *output = ctx->packets[ctx->head];
    ctx->head = (ctx->head + 1) % PACKET_QUEUE;
    ctx->count--;
    pthread_mutex_unlock(&ctx->mutex);
    return 1;
}

static unsigned queue_occupancy(client_ctx_t* ctx)
{
    pthread_mutex_lock(&ctx->mutex);
    unsigned n = ctx->count;
    pthread_mutex_unlock(&ctx->mutex);
    return n;
}

static void log_path(picoquic_cnx_t* cnx, uint64_t path_id,
                     const char* event, client_ctx_t* ctx)
{
    struct sockaddr_storage local = {0}, peer = {0};
    char lip[INET_ADDRSTRLEN] = "?", pip[INET_ADDRSTRLEN] = "?";
    int a = picoquic_get_path_addr(cnx, path_id, 1, &local);
    int b = picoquic_get_path_addr(cnx, path_id, 2, &peer);
    if (a == 0 && b == 0 && local.ss_family == AF_INET && peer.ss_family == AF_INET) {
        const struct sockaddr_in* la = (const struct sockaddr_in*)&local;
        const struct sockaddr_in* pa = (const struct sockaddr_in*)&peer;
        inet_ntop(AF_INET, &la->sin_addr, lip, sizeof(lip));
        inet_ntop(AF_INET, &pa->sin_addr, pip, sizeof(pip));
        sn_log("CLIENT", "PATH", "%s id=%" PRIu64 " local=%s:%u peer=%s:%u",
               event, path_id, lip, (unsigned)ntohs(la->sin_port),
               pip, (unsigned)ntohs(pa->sin_port));
        if (!strcmp(event, "AVAILABLE") &&
            !strcmp(lip, NETWORK_B_CLIENT_IP) && !strcmp(pip, NETWORK_B_SERVER_IP)) {
            /* Path validation is not the same as application recovery. */
            if (!atomic_exchange(&ctx->migration_validated, 1)) {
                uint64_t validated_at = sn_monotonic_ms();
                uint64_t requested_at = atomic_load(&ctx->migration_requested_at_ms);
                uint64_t last_good_at = atomic_load(&ctx->migration_last_good_ms);
                atomic_store(&ctx->migration_validated_at_ms, validated_at);
                atomic_store(&ctx->app_recovery_pending, 1);
                atomic_store(&ctx->heartbeat_last_ack_ms, validated_at);
                sn_log("CLIENT", "MIGRATION",
                       "Network B validated on ORIGINAL QUIC connection start=%" PRIu64
                       " mono_ms=%" PRIu64 " probe_to_validated_ms=%" PRIu64
                       " last_good_to_validated_ms=%" PRIu64,
                       (uint64_t)picoquic_get_cnx_start_time(cnx), validated_at,
                       sn_elapsed_ms(validated_at, requested_at),
                       sn_elapsed_ms(validated_at, last_good_at));
            }
        }
    } else {
        sn_log("CLIENT", "PATH", "%s id=%" PRIu64 " (addresses unavailable)", event, path_id);
    }
}

static int client_callback(picoquic_cnx_t* cnx, uint64_t stream_id,
                           uint8_t* bytes, size_t length,
                           picoquic_call_back_event_t event,
                           void* callback_ctx, void* stream_ctx)
{
    (void)stream_ctx;
    client_ctx_t* ctx = (client_ctx_t*)callback_ctx;
    if (ctx == NULL) return -1;
    switch (event) {
    case picoquic_callback_ready: {
        ctx->cnx = cnx;
        struct sockaddr* addr = NULL;
        picoquic_get_local_addr(cnx, &addr);
        if (addr && addr->sa_family == AF_INET)
            ctx->udp_source_port_net = ((const struct sockaddr_in*)addr)->sin_port;
        uint64_t ready_at = sn_monotonic_ms();
        atomic_store(&ctx->heartbeat_last_ack_ms, ready_at);
        atomic_store(&ctx->last_authenticated_rx_ms, ready_at);
        atomic_store(&ctx->connected, 1);
        sn_log("CLIENT", "CONNECTION", "QUIC ready start=%" PRIu64,
               (uint64_t)picoquic_get_cnx_start_time(cnx));
        break;
    }
    case picoquic_callback_datagram: {
        uint8_t type;
        uint64_t seq;
        if (sn_hb_parse(bytes, length, &type, &seq)) {
            if (type == SN_HB_ACK && seq <= atomic_load(&ctx->heartbeat_sequence) &&
                seq > atomic_load(&ctx->heartbeat_last_ack_sequence)) {
                atomic_store(&ctx->heartbeat_last_ack_sequence, seq);
                uint64_t received_at = sn_monotonic_ms();
                atomic_store(&ctx->heartbeat_last_ack_ms, received_at);
                atomic_store(&ctx->last_authenticated_rx_ms, received_at);
                atomic_fetch_add(&ctx->stats.hb_rx, 1);
                if (ctx->debug_packets)
                    sn_log("CLIENT", "DEBUG", "heartbeat ACK seq=%" PRIu64, seq);
            }
            break; /* Control messages never enter tun0. */
        }
        if (length < 20 || length > PACKET_MAX || (bytes[0] >> 4) != 4) {
            client_drop(ctx, "invalid QUIC payload");
            break;
        }
        atomic_store(&ctx->last_authenticated_rx_ms, sn_monotonic_ms());
        atomic_fetch_add(&ctx->stats.quic_rx_pkts, 1);
        atomic_fetch_add(&ctx->stats.quic_rx_bytes, length);
        ssize_t n = write(ctx->tun_fd, bytes, length);
        if (n < 0 || (size_t)n != length) {
            client_drop(ctx, "TUN write failed");
            if (n < 0) sn_log("CLIENT", "ERROR", "write(tun0): %s", strerror(errno));
        } else {
            atomic_fetch_add(&ctx->stats.tun_out_pkts, 1);
            atomic_fetch_add(&ctx->stats.tun_out_bytes, length);
            if (atomic_exchange(&ctx->app_recovery_pending, 0)) {
                uint64_t app_at = sn_monotonic_ms();
                sn_log("CLIENT", "RECOVERY",
                       "first IP reply after Network B validation mono_ms=%" PRIu64
                       " probe_to_app_reply_ms=%" PRIu64
                       " validation_to_app_reply_ms=%" PRIu64,
                       app_at,
                       sn_elapsed_ms(app_at, atomic_load(&ctx->migration_requested_at_ms)),
                       sn_elapsed_ms(app_at, atomic_load(&ctx->migration_validated_at_ms)));
            }
            if (ctx->debug_packets) sn_log("CLIENT", "DEBUG", "QUIC -> TUN %zuB", length);
        }
        break;
    }
    case picoquic_callback_path_available:
        log_path(cnx, stream_id, "AVAILABLE", ctx); break;
    case picoquic_callback_path_suspended:
        log_path(cnx, stream_id, "SUSPENDED", ctx); break;
    case picoquic_callback_path_deleted:
        sn_log("CLIENT", "PATH", "DELETED id=%" PRIu64, stream_id); break;
    case picoquic_callback_close:
    case picoquic_callback_application_close:
    case picoquic_callback_stateless_reset:
        atomic_store(&ctx->connected, 0);
        sn_log("CLIENT", "CONNECTION", "closed event=%d (no automatic reconnect)", (int)event);
        break;
    default: break;
    }
    return 0;
}

/* Interface detection handles administrative DOWN; heartbeats handle blackholes. */
static int interface_with_ipv4_is_up(const char* ipv4)
{
    struct in_addr wanted;
    struct ifaddrs* interfaces = NULL;
    if (inet_pton(AF_INET, ipv4, &wanted) != 1) return -1;
    if (getifaddrs(&interfaces) != 0) return -1;
    int up = 0;
    for (struct ifaddrs* it = interfaces; it; it = it->ifa_next) {
        if (!it->ifa_addr || it->ifa_addr->sa_family != AF_INET) continue;
        const struct sockaddr_in* a = (const struct sockaddr_in*)it->ifa_addr;
        if (a->sin_addr.s_addr != wanted.s_addr) continue;
        up = !!(it->ifa_flags & IFF_UP) && !!(it->ifa_flags & IFF_RUNNING);
        break;
    }
    freeifaddrs(interfaces);
    return up;
}

/* Called only on Picoquic's network thread. */
static int request_network_b_migration(client_ctx_t* ctx)
{
    if (!atomic_load(&ctx->connected) || !ctx->cnx) {
        sn_log("CLIENT", "ERROR", "migration rejected: QUIC not connected");
        return -1;
    }
    if (atomic_load(&ctx->migration_validated)) return 0;
    uint16_t source_port = ctx->udp_source_port_net;
    struct sockaddr* current_local = NULL;
    picoquic_get_local_addr(ctx->cnx, &current_local);
    if (current_local && current_local->sa_family == AF_INET) {
        uint16_t p = ((const struct sockaddr_in*)current_local)->sin_port;
        if (p) source_port = p;
    }
    if (!source_port) {
        sn_log("CLIENT", "ERROR", "migration rejected: missing UDP source port");
        return -1;
    }
    struct sockaddr_in local = {0}, peer = {0};
    local.sin_family = AF_INET;
    local.sin_port = source_port;
    peer.sin_family = AF_INET;
    peer.sin_port = htons((uint16_t)ctx->server_port);
    if (inet_pton(AF_INET, NETWORK_B_CLIENT_IP, &local.sin_addr) != 1 ||
        inet_pton(AF_INET, NETWORK_B_SERVER_IP, &peer.sin_addr) != 1) {
        sn_log("CLIENT", "ERROR", "invalid Network B address");
        return -1;
    }
    int reason = atomic_load(&ctx->migrate_reason);
    sn_log("CLIENT", "MIGRATION", "probe requested reason=%d %s:%u -> %s:%u",
           reason, NETWORK_B_CLIENT_IP, (unsigned)ntohs(source_port),
           NETWORK_B_SERVER_IP, (unsigned)ctx->server_port);
    int ret = picoquic_probe_new_path(ctx->cnx,
        (const struct sockaddr*)&peer, (const struct sockaddr*)&local,
        picoquic_current_time());
    sn_log("CLIENT", ret == 0 ? "MIGRATION" : "ERROR",
           "probe returned %d (0=accepted, not yet validated)", ret);
    return ret;
}

static int client_loop_callback(picoquic_quic_t* quic,
                                picoquic_packet_loop_cb_enum mode,
                                void* callback_ctx, void* callback_arg)
{
    (void)quic; (void)callback_arg;
    client_ctx_t* ctx = (client_ctx_t*)callback_ctx;
    if (!ctx || mode != picoquic_packet_loop_wake_up) return 0;

    if (atomic_exchange(&ctx->migrate_requested, 0))
        (void)request_network_b_migration(ctx);
    if (!atomic_load(&ctx->connected) || !ctx->cnx) return 0;

    if (atomic_exchange(&ctx->heartbeat_send_requested, 0)) {
        uint64_t seq = atomic_fetch_add(&ctx->heartbeat_sequence, 1) + 1;
        uint8_t ping[SN_HB_SIZE];
        sn_hb_make(ping, SN_HB_PING, seq);
        int ret = picoquic_queue_datagram_frame(ctx->cnx, sizeof(ping), ping);
        if (ret == 0) {
            atomic_fetch_add(&ctx->stats.hb_tx, 1);
            if (ctx->debug_packets) sn_log("CLIENT", "DEBUG", "heartbeat PING seq=%" PRIu64, seq);
        } else {
            atomic_fetch_add(&ctx->stats.queue_errors, 1);
            client_drop(ctx, "heartbeat DATAGRAM queue failed");
        }
    }

    tunnel_packet_t p;
    while (dequeue_packet(ctx, &p)) {
        int ret = picoquic_queue_datagram_frame(ctx->cnx, p.length, p.data);
        if (ret) {
            atomic_fetch_add(&ctx->stats.queue_errors, 1);
            client_drop(ctx, "QUIC DATAGRAM queue failed");
            continue;
        }
        atomic_fetch_add(&ctx->stats.quic_tx_pkts, 1);
        atomic_fetch_add(&ctx->stats.quic_tx_bytes, p.length);
        if (ctx->debug_packets) sn_log("CLIENT", "DEBUG", "TUN -> QUIC %zuB", p.length);
    }
    return 0;
}

static void request_migration(client_ctx_t* ctx,
                              picoquic_network_thread_ctx_t* thread,
                              int reason, unsigned attempt)
{
    uint64_t tick = sn_monotonic_ms();
    uint64_t ack_at = atomic_load(&ctx->heartbeat_last_ack_ms);
    uint64_t rx_at = atomic_load(&ctx->last_authenticated_rx_ms);
    uint64_t last_good_at = ack_at > rx_at ? ack_at : rx_at;
    /* Timestamp is updated on retries; the first attempt is what matters
     * for the normal successful early-failover case. */
    atomic_store(&ctx->migration_requested_at_ms, tick);
    atomic_store(&ctx->migration_last_good_ms, last_good_at);
    atomic_store(&ctx->migrate_reason, reason);
    atomic_store(&ctx->migrate_requested, 1);
    sn_log("CLIENT", "FAILOVER",
           "Network A -> B reason=%d attempt=%u/%u mono_ms=%" PRIu64
           " ack_age_ms=%" PRIu64 " app_rx_age_ms=%" PRIu64,
           reason, attempt, MAX_MIGRATION_ATTEMPTS, tick,
           sn_elapsed_ms(tick, ack_at), sn_elapsed_ms(tick, rx_at));
    picoquic_wake_up_network_thread(thread);
}

int start_picoquic_client(const char* server_ip, int port)
{
    int ret = -1;
    client_ctx_t ctx = {0};
    ctx.tun_fd = -1;
    ctx.server_port = port;
    ctx.debug_packets = sn_env_flag("SEAMLESSNET_DEBUG_PACKETS");
    ctx.heartbeat_interval_ms = sn_env_u32("SEAMLESSNET_HEARTBEAT_INTERVAL_MS", 250, 100, 5000);
    ctx.early_warning_ms = sn_env_u32("SEAMLESSNET_EARLY_WARNING_MS", 750, 300, 10000);
    ctx.failover_timeout_ms = sn_env_u32("SEAMLESSNET_FAILOVER_TIMEOUT_MS", 1500, 750, 30000);
    /* Require at least two heartbeat opportunities before early warning. */
    if (ctx.early_warning_ms < ctx.heartbeat_interval_ms * 2u)
        ctx.early_warning_ms = ctx.heartbeat_interval_ms * 2u;
    if (ctx.failover_timeout_ms < ctx.early_warning_ms + ctx.heartbeat_interval_ms)
        ctx.failover_timeout_ms = ctx.early_warning_ms + ctx.heartbeat_interval_ms;
    pthread_mutex_init(&ctx.mutex, NULL);
    sn_stats_init(&ctx.stats);
    atomic_init(&ctx.connected, 0);
    atomic_init(&ctx.migrate_requested, 0);
    atomic_init(&ctx.migrate_reason, 0);
    atomic_init(&ctx.migration_validated, 0);
    atomic_init(&ctx.heartbeat_send_requested, 0);
    atomic_init(&ctx.hard_timeout_reported, 0);
    atomic_init(&ctx.app_recovery_pending, 0);
    atomic_init(&ctx.migration_requested_at_ms, 0);
    atomic_init(&ctx.migration_validated_at_ms, 0);
    atomic_init(&ctx.migration_last_good_ms, 0);
    atomic_init(&ctx.heartbeat_sequence, 0);
    atomic_init(&ctx.heartbeat_last_ack_sequence, 0);
    atomic_init(&ctx.heartbeat_last_ack_ms, 0);
    atomic_init(&ctx.last_authenticated_rx_ms, 0);

    ctx.tun_fd = tun_create("tun0");
    if (ctx.tun_fd < 0) goto cleanup_mutex;
    if (tun_configure("tun0") != 0) goto cleanup_tun;

    uint64_t now = picoquic_current_time();
    picoquic_quic_t* quic = picoquic_create(
        1, NULL, NULL, NULL, "seamlessnet", client_callback, &ctx,
        NULL, NULL, NULL, now, NULL, NULL, NULL, 0);
    if (!quic) {
        sn_log("CLIENT", "ERROR", "picoquic_create failed");
        goto cleanup_tun;
    }
    picoquic_set_default_idle_timeout(quic, SEAMLESSNET_IDLE_TIMEOUT_MS);
    picoquic_set_null_verifier(quic); /* Development only. */
    picoquic_tp_t tp = *picoquic_get_default_tp(quic);
    tp.max_datagram_frame_size = 65535;
    picoquic_set_default_tp(quic, &tp);

    struct sockaddr_in peer = {0};
    peer.sin_family = AF_INET;
    peer.sin_port = htons((uint16_t)port);
    if (inet_pton(AF_INET, server_ip, &peer.sin_addr) != 1) {
        sn_log("CLIENT", "ERROR", "invalid server address: %s", server_ip);
        goto cleanup_quic;
    }
    picoquic_cnx_t* cnx = picoquic_create_cnx(
        quic, picoquic_null_connection_id, picoquic_null_connection_id,
        (struct sockaddr*)&peer, now, 0, server_ip, "seamlessnet", 1);
    if (!cnx) {
        sn_log("CLIENT", "ERROR", "picoquic_create_cnx failed");
        goto cleanup_quic;
    }
    ctx.cnx = cnx;
    picoquic_set_callback(cnx, client_callback, &ctx);
    picoquic_enable_path_callbacks(cnx, 1);
    ret = picoquic_start_client_cnx(cnx);
    if (ret) {
        sn_log("CLIENT", "ERROR", "QUIC start failed: %d", ret);
        goto cleanup_quic;
    }

    picoquic_packet_loop_param_t param = {0};
    param.local_af = AF_INET;
    picoquic_network_thread_ctx_t* thread = picoquic_start_network_thread(
        quic, &param, client_loop_callback, &ctx, &ret);
    if (!thread) {
        sn_log("CLIENT", "ERROR", "network thread start failed: %d", ret);
        goto cleanup_quic;
    }
    sn_log("CLIENT", "CONNECTION", "connecting Network A to %s:%d", server_ip, port);
    int ready = 0;
    for (int i = 0; i < 300; ++i) {
        if (atomic_load(&ctx.connected)) { ready = 1; break; }
        usleep(100000);
    }
    if (!ready) {
        sn_log("CLIENT", "ERROR", "QUIC handshake timeout");
        ret = -1;
        goto cleanup_thread;
    }
    sn_log("CLIENT", "CONFIG", "TUN MTU=1000 heartbeat=%ums early_warning=%ums hard_timeout=%ums debug_packets=%d",
           ctx.heartbeat_interval_ms, ctx.early_warning_ms,
           ctx.failover_timeout_ms, ctx.debug_packets);
    sn_log("CLIENT", "CONFIG", "manual trigger: touch %s", MIGRATION_TRIGGER);

    uint8_t packet[PACKET_MAX];
    sn_stats_snapshot_t previous = {.last_report_ms = sn_monotonic_ms()};
    uint64_t next_health_check_ms = 0, next_heartbeat_ms = 0;
    uint64_t last_migration_attempt_ms = 0;
    unsigned migration_attempts = 0;
    int b_unavailable_reported = 0, b_failed_reported = 0;

    for (;;) {
        uint64_t tick = sn_monotonic_ms();
        if (tick >= next_heartbeat_ms && atomic_load(&ctx.connected)) {
            next_heartbeat_ms = tick + ctx.heartbeat_interval_ms;
            atomic_store(&ctx.heartbeat_send_requested, 1);
            picoquic_wake_up_network_thread(thread);
        }

        if (tick >= next_health_check_ms) {
            next_health_check_ms = tick + HEALTH_CHECK_INTERVAL_MS;
            if (access(MIGRATION_TRIGGER, F_OK) == 0) {
                unlink(MIGRATION_TRIGGER);
                if (!atomic_load(&ctx.migration_validated) && atomic_load(&ctx.connected)) {
                    /* Manual trigger forces the first attempt even if A is healthy. */
                    if (migration_attempts == 0) {
                        migration_attempts++;
                        last_migration_attempt_ms = tick;
                        request_migration(&ctx, thread, MIGRATION_MANUAL, migration_attempts);
                    } else sn_log("CLIENT", "MIGRATION", "manual trigger ignored; probe already requested");
                }
            }
            if (atomic_load(&ctx.connected) && !atomic_load(&ctx.migration_validated)) {
                int a_up = interface_with_ipv4_is_up(NETWORK_A_CLIENT_IP);
                uint64_t ack_at = atomic_load(&ctx.heartbeat_last_ack_ms);
                uint64_t ack_age = ack_at && tick >= ack_at ? tick - ack_at : 0;
                uint64_t rx_at = atomic_load(&ctx.last_authenticated_rx_ms);
                uint64_t rx_age = rx_at && tick >= rx_at ? tick - rx_at : 0;
                /* Silence is evaluated using both heartbeat ACKs and
                 * authenticated application traffic, so one lost ACK does
                 * not cause a premature switch. */
                int health = sn_path_health_level(tick, ack_at, rx_at,
                                 atomic_load(&ctx.stats.hb_tx),
                                 ctx.early_warning_ms, ctx.failover_timeout_ms);
                if (health == SN_HEALTH_HARD_FAILURE &&
                    !atomic_exchange(&ctx.hard_timeout_reported, 1)) {
                    sn_log("CLIENT", "HEALTH", "Network A hard timeout: ack_age=%" PRIu64
                           "ms app_rx_age=%" PRIu64 "ms mono_ms=%" PRIu64,
                           ack_age, rx_age, tick);
                } else if (health == SN_HEALTH_OK) {
                    atomic_store(&ctx.hard_timeout_reported, 0);
                }
                if (a_up == 0 || health != SN_HEALTH_OK || migration_attempts > 0) {
                    int b_up = interface_with_ipv4_is_up(NETWORK_B_CLIENT_IP);
                    if (b_up == 1) {
                        b_unavailable_reported = 0;
                        if (migration_attempts < MAX_MIGRATION_ATTEMPTS &&
                            (migration_attempts == 0 || tick - last_migration_attempt_ms >= MIGRATION_RETRY_MS)) {
                            int reason = migration_attempts ? MIGRATION_RETRY :
                                         a_up == 0 ? MIGRATION_LINK_DOWN :
                                         health == SN_HEALTH_EARLY_WARNING ? MIGRATION_EARLY_WARNING :
                                         MIGRATION_HEARTBEAT_TIMEOUT;
                            if (reason == MIGRATION_EARLY_WARNING)
                                sn_log("CLIENT", "HEALTH", "Network A DEGRADED: ack_age=%" PRIu64
                                       "ms app_rx_age=%" PRIu64 "ms; switching before hard timeout", ack_age, rx_age);
                            else if (reason == MIGRATION_HEARTBEAT_TIMEOUT)
                                sn_log("CLIENT", "FAILOVER", "silent Network A failure: ACK age=%" PRIu64
                                       "ms app/control RX age=%" PRIu64 "ms", ack_age, rx_age);
                            else if (reason == MIGRATION_LINK_DOWN)
                                sn_log("CLIENT", "FAILOVER", "Network A interface DOWN");
                            migration_attempts++;
                            last_migration_attempt_ms = tick;
                            request_migration(&ctx, thread, reason, migration_attempts);
                        } else if (migration_attempts >= MAX_MIGRATION_ATTEMPTS &&
                                   tick - last_migration_attempt_ms >= MIGRATION_RETRY_MS && !b_failed_reported) {
                            b_failed_reported = 1;
                            sn_log("CLIENT", "ERROR", "Network B not validated after %u probe requests", migration_attempts);
                        }
                    } else if (!b_unavailable_reported) {
                        b_unavailable_reported = 1;
                        sn_log("CLIENT", "ERROR", "Network A unhealthy, but Network B interface unavailable");
                    }
                }
            }
        }

        if (tick - previous.last_report_ms >= 1000) {
            uint64_t ack = atomic_load(&ctx.heartbeat_last_ack_ms);
            uint64_t age = ack && tick >= ack ? tick - ack : 0;
            sn_stats_report("CLIENT", &ctx.stats, &previous,
                            queue_occupancy(&ctx), PACKET_QUEUE, age);
        }

        struct pollfd pfd = {.fd = ctx.tun_fd, .events = POLLIN};
        int nready = poll(&pfd, 1, 100);
        if (nready == 0) continue;
        if (nready < 0) {
            if (errno == EINTR) continue;
            sn_log("CLIENT", "ERROR", "poll(tun0): %s", strerror(errno));
            break;
        }
        if (!(pfd.revents & POLLIN)) {
            sn_log("CLIENT", "ERROR", "unexpected TUN poll event: 0x%x", pfd.revents);
            break;
        }
        ssize_t n = read(ctx.tun_fd, packet, sizeof(packet));
        if (n < 0) {
            if (errno == EINTR) continue;
            sn_log("CLIENT", "ERROR", "read(tun0): %s", strerror(errno));
            break;
        }
        atomic_fetch_add(&ctx.stats.tun_in_pkts, 1);
        atomic_fetch_add(&ctx.stats.tun_in_bytes, (size_t)n);
        if (!atomic_load(&ctx.connected)) {
            client_drop(&ctx, "QUIC disconnected");
            continue;
        }
        if (queue_packet(&ctx, packet, (size_t)n) == 0)
            picoquic_wake_up_network_thread(thread);
    }
    ret = -1;
cleanup_thread:
    picoquic_delete_network_thread(thread);
cleanup_quic:
    picoquic_free(quic);
cleanup_tun:
    close(ctx.tun_fd);
cleanup_mutex:
    pthread_mutex_destroy(&ctx.mutex);
    return ret;
}
