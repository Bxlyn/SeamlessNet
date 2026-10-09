#include "picoquic.h"
#include "picoquic_packet_loop.h"
#include "tun.h"
#include "seamlessnet_monitor.h"

#include <arpa/inet.h>
#include <errno.h>
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

typedef struct {
    uint8_t data[PACKET_MAX];
    size_t length;
} tunnel_packet_t;

typedef struct {
    tunnel_packet_t packets[PACKET_QUEUE];
    unsigned head, tail, count;
    pthread_mutex_t mutex;
    picoquic_cnx_t* cnx; /* Picoquic network thread only. */
    atomic_int connected;
    int tun_fd;
    int debug_packets;
    sn_stats_t stats;
} server_ctx_t;

static void server_drop(server_ctx_t* ctx, const char* reason)
{
    uint64_t n = atomic_fetch_add(&ctx->stats.drops, 1) + 1;
    if (n <= 3 || n % 1000 == 0)
        sn_log("SERVER", "WARN", "drop=%" PRIu64 " reason=%s", n, reason);
}

static int queue_packet(server_ctx_t* ctx, const uint8_t* data, size_t length)
{
    if (!length || length > PACKET_MAX) {
        server_drop(ctx, "invalid/oversized return packet");
        return -1;
    }
    pthread_mutex_lock(&ctx->mutex);
    if (ctx->count == PACKET_QUEUE) {
        pthread_mutex_unlock(&ctx->mutex);
        atomic_fetch_add(&ctx->stats.queue_full, 1);
        server_drop(ctx, "return queue full");
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

static int dequeue_packet(server_ctx_t* ctx, tunnel_packet_t* output)
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

static unsigned queue_occupancy(server_ctx_t* ctx)
{
    pthread_mutex_lock(&ctx->mutex);
    unsigned n = ctx->count;
    pthread_mutex_unlock(&ctx->mutex);
    return n;
}

static void debug_ipv4(server_ctx_t* ctx, const uint8_t* bytes,
                       size_t length, const char* direction)
{
    if (!ctx->debug_packets || length < 20 || (bytes[0] >> 4) != 4) return;
    char src[INET_ADDRSTRLEN], dst[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, bytes + 12, src, sizeof(src));
    inet_ntop(AF_INET, bytes + 16, dst, sizeof(dst));
    sn_log("SERVER", "DEBUG", "%s %s -> %s %zuB proto=%u",
           direction, src, dst, length, (unsigned)bytes[9]);
}

static void log_server_path(picoquic_cnx_t* cnx, uint64_t path_id, const char* event)
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
        sn_log("SERVER", "PATH", "%s id=%" PRIu64 " local=%s:%u peer=%s:%u start=%" PRIu64,
               event, path_id, lip, (unsigned)ntohs(la->sin_port),
               pip, (unsigned)ntohs(pa->sin_port),
               (uint64_t)picoquic_get_cnx_start_time(cnx));
    } else {
        sn_log("SERVER", "PATH", "%s id=%" PRIu64, event, path_id);
    }
}

static int server_callback(picoquic_cnx_t* cnx, uint64_t stream_id,
                           uint8_t* bytes, size_t length,
                           picoquic_call_back_event_t event,
                           void* callback_ctx, void* stream_ctx)
{
    (void)stream_ctx;
    server_ctx_t* ctx = (server_ctx_t*)callback_ctx;
    if (!ctx) return -1;
    switch (event) {
    case picoquic_callback_ready:
        if (ctx->cnx && ctx->cnx != cnx && atomic_load(&ctx->connected)) {
            sn_log("SERVER", "ERROR", "Stage 1 supports only one active QUIC client");
            return -1;
        }
        ctx->cnx = cnx;
        atomic_store(&ctx->connected, 1);
        picoquic_enable_path_callbacks(cnx, 1);
        sn_log("SERVER", "CONNECTION", "QUIC ready start=%" PRIu64,
               (uint64_t)picoquic_get_cnx_start_time(cnx));
        break;

    case picoquic_callback_datagram: {
        uint8_t type;
        uint64_t seq;
        if (sn_hb_parse(bytes, length, &type, &seq)) {
            if (type == SN_HB_PING) {
                atomic_fetch_add(&ctx->stats.hb_rx, 1);
                uint8_t ack[SN_HB_SIZE];
                sn_hb_make(ack, SN_HB_ACK, seq);
                int ret = picoquic_queue_datagram_frame(cnx, sizeof(ack), ack);
                if (!ret) {
                    atomic_fetch_add(&ctx->stats.hb_tx, 1);
                    if (ctx->debug_packets)
                        sn_log("SERVER", "DEBUG", "heartbeat ACK seq=%" PRIu64, seq);
                } else {
                    atomic_fetch_add(&ctx->stats.queue_errors, 1);
                    server_drop(ctx, "heartbeat ACK queue failed");
                }
            }
            break; /* Heartbeats never enter tun0. */
        }
        if (length < 20 || length > PACKET_MAX || (bytes[0] >> 4) != 4) {
            server_drop(ctx, "invalid QUIC payload");
            break;
        }
        atomic_fetch_add(&ctx->stats.quic_rx_pkts, 1);
        atomic_fetch_add(&ctx->stats.quic_rx_bytes, length);
        debug_ipv4(ctx, bytes, length, "QUIC -> TUN");
        ssize_t n = write(ctx->tun_fd, bytes, length);
        if (n < 0 || (size_t)n != length) {
            server_drop(ctx, "TUN write failed");
            if (n < 0) sn_log("SERVER", "ERROR", "write(tun0): %s", strerror(errno));
        } else {
            atomic_fetch_add(&ctx->stats.tun_out_pkts, 1);
            atomic_fetch_add(&ctx->stats.tun_out_bytes, length);
        }
        break;
    }
    case picoquic_callback_path_available:
        log_server_path(cnx, stream_id, "AVAILABLE"); break;
    case picoquic_callback_path_suspended:
        log_server_path(cnx, stream_id, "SUSPENDED"); break;
    case picoquic_callback_path_deleted:
        sn_log("SERVER", "PATH", "DELETED id=%" PRIu64, stream_id); break;
    case picoquic_callback_close:
    case picoquic_callback_application_close:
    case picoquic_callback_stateless_reset:
        if (ctx->cnx == cnx) {
            atomic_store(&ctx->connected, 0);
            ctx->cnx = NULL;
        }
        sn_log("SERVER", "CONNECTION", "closed event=%d", (int)event);
        break;
    default: break;
    }
    return 0;
}

static int server_loop_callback(picoquic_quic_t* quic,
                                picoquic_packet_loop_cb_enum mode,
                                void* callback_ctx, void* callback_arg)
{
    (void)quic; (void)callback_arg;
    server_ctx_t* ctx = (server_ctx_t*)callback_ctx;
    if (!ctx || mode != picoquic_packet_loop_wake_up ||
        !atomic_load(&ctx->connected) || !ctx->cnx) return 0;

    tunnel_packet_t p;
    while (dequeue_packet(ctx, &p)) {
        int ret = picoquic_queue_datagram_frame(ctx->cnx, p.length, p.data);
        if (ret) {
            atomic_fetch_add(&ctx->stats.queue_errors, 1);
            server_drop(ctx, "return DATAGRAM queue failed");
            continue;
        }
        atomic_fetch_add(&ctx->stats.quic_tx_pkts, 1);
        atomic_fetch_add(&ctx->stats.quic_tx_bytes, p.length);
        debug_ipv4(ctx, p.data, p.length, "TUN -> QUIC");
    }
    return 0;
}

int start_picoquic_server(int port, const char* cert_file, const char* key_file)
{
    int ret = -1;
    server_ctx_t ctx = {0};
    ctx.tun_fd = -1;
    ctx.debug_packets = sn_env_flag("SEAMLESSNET_DEBUG_PACKETS");
    pthread_mutex_init(&ctx.mutex, NULL);
    sn_stats_init(&ctx.stats);
    atomic_init(&ctx.connected, 0);

    ctx.tun_fd = tun_create("tun0");
    if (ctx.tun_fd < 0) goto cleanup_mutex;
    if (tun_configure("tun0") != 0) goto cleanup_tun;

    picoquic_quic_t* quic = picoquic_create(
        8, cert_file, key_file, NULL, "seamlessnet", server_callback, &ctx,
        NULL, NULL, NULL, picoquic_current_time(), NULL, NULL, NULL, 0);
    if (!quic) {
        sn_log("SERVER", "ERROR", "picoquic_create failed");
        goto cleanup_tun;
    }
    picoquic_set_default_idle_timeout(quic, SEAMLESSNET_IDLE_TIMEOUT_MS);
    picoquic_enable_path_callbacks_default(quic, 1);
    picoquic_tp_t tp = *picoquic_get_default_tp(quic);
    tp.max_datagram_frame_size = 65535;
    picoquic_set_default_tp(quic, &tp);

    picoquic_packet_loop_param_t param = {0};
    param.local_port = (uint16_t)port;
    param.local_af = AF_INET;
    picoquic_network_thread_ctx_t* thread = picoquic_start_network_thread(
        quic, &param, server_loop_callback, &ctx, &ret);
    if (!thread) {
        sn_log("SERVER", "ERROR", "network thread failed: %d", ret);
        goto cleanup_quic;
    }
    sn_log("SERVER", "CONNECTION", "listening UDP %d on Networks A and B", port);
    sn_log("SERVER", "CONFIG", "TUN MTU=1000 debug_packets=%d", ctx.debug_packets);

    uint8_t packet[PACKET_MAX];
    sn_stats_snapshot_t previous = {.last_report_ms = sn_monotonic_ms()};
    for (;;) {
        uint64_t tick = sn_monotonic_ms();
        if (tick - previous.last_report_ms >= 1000)
            sn_stats_report("SERVER", &ctx.stats, &previous,
                            queue_occupancy(&ctx), PACKET_QUEUE, 0);

        struct pollfd pfd = {.fd = ctx.tun_fd, .events = POLLIN};
        int ready = poll(&pfd, 1, 100);
        if (ready == 0) continue;
        if (ready < 0) {
            if (errno == EINTR) continue;
            sn_log("SERVER", "ERROR", "poll(tun0): %s", strerror(errno));
            break;
        }
        if (!(pfd.revents & POLLIN)) {
            sn_log("SERVER", "ERROR", "unexpected TUN poll event: 0x%x", pfd.revents);
            break;
        }
        ssize_t n = read(ctx.tun_fd, packet, sizeof(packet));
        if (n < 0) {
            if (errno == EINTR) continue;
            sn_log("SERVER", "ERROR", "read(tun0): %s", strerror(errno));
            break;
        }
        atomic_fetch_add(&ctx.stats.tun_in_pkts, 1);
        atomic_fetch_add(&ctx.stats.tun_in_bytes, (size_t)n);
        if (!atomic_load(&ctx.connected)) {
            server_drop(&ctx, "no active QUIC client");
            continue;
        }
        if (queue_packet(&ctx, packet, (size_t)n) == 0)
            picoquic_wake_up_network_thread(thread);
    }
    ret = -1;
    picoquic_delete_network_thread(thread);
cleanup_quic:
    picoquic_free(quic);
cleanup_tun:
    close(ctx.tun_fd);
cleanup_mutex:
    pthread_mutex_destroy(&ctx.mutex);
    return ret;
}
