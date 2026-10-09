#include "picoquic.h"
#include "picoquic_packet_loop.h"
#include "tun.h"

#include <arpa/inet.h>
#include <errno.h>
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
    picoquic_cnx_t* cnx; /* Only used on Picoquic's network thread. */
    atomic_int connected;
    int tun_fd;
} server_ctx_t;

static int queue_packet(server_ctx_t* ctx, const uint8_t* data, size_t length)
{
    if (length == 0 || length > PACKET_MAX) {
        fprintf(stderr, "[SERVER] Invalid/oversized return packet: %zu bytes\n", length);
        return -1;
    }
    pthread_mutex_lock(&ctx->mutex);
    if (ctx->count == PACKET_QUEUE) {
        pthread_mutex_unlock(&ctx->mutex);
        fprintf(stderr, "[SERVER] Return packet queue full\n");
        return -1;
    }
    tunnel_packet_t* p = &ctx->packets[ctx->tail];
    memcpy(p->data, data, length);
    p->length = length;
    ctx->tail = (ctx->tail + 1) % PACKET_QUEUE;
    ctx->count++;
    pthread_mutex_unlock(&ctx->mutex);
    return 0;
}

static int dequeue_packet(server_ctx_t* ctx, tunnel_packet_t* output)
{
    pthread_mutex_lock(&ctx->mutex);
    if (ctx->count == 0) {
        pthread_mutex_unlock(&ctx->mutex);
        return 0;
    }
    *output = ctx->packets[ctx->head];
    ctx->head = (ctx->head + 1) % PACKET_QUEUE;
    ctx->count--;
    pthread_mutex_unlock(&ctx->mutex);
    return 1;
}

static void print_ipv4_packet(const uint8_t* bytes, size_t length, const char* direction)
{
    if (length < 20 || (bytes[0] >> 4) != 4) return;
    char src[INET_ADDRSTRLEN], dst[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, bytes + 12, src, sizeof(src));
    inet_ntop(AF_INET, bytes + 16, dst, sizeof(dst));
    printf("[SERVER] %s: %s -> %s, %zu bytes, protocol=%u\n",
           direction, src, dst, length, bytes[9]);
}

static void log_server_path(picoquic_cnx_t* cnx, uint64_t path_id, const char* event)
{
    struct sockaddr_storage local = {0}, peer = {0};
    char local_ip[INET_ADDRSTRLEN] = "?", peer_ip[INET_ADDRSTRLEN] = "?";
    int a = picoquic_get_path_addr(cnx, path_id, 1, &local);
    int b = picoquic_get_path_addr(cnx, path_id, 2, &peer);
    if (a == 0 && b == 0 && local.ss_family == AF_INET && peer.ss_family == AF_INET) {
        const struct sockaddr_in* sa = (const struct sockaddr_in*)&local;
        const struct sockaddr_in* sb = (const struct sockaddr_in*)&peer;
        inet_ntop(AF_INET, &sa->sin_addr, local_ip, sizeof(local_ip));
        inet_ntop(AF_INET, &sb->sin_addr, peer_ip, sizeof(peer_ip));
        printf("[SERVER] Path %s id=%llu local=%s:%u peer=%s:%u\n",
               event, (unsigned long long)path_id,
               local_ip, (unsigned)ntohs(sa->sin_port),
               peer_ip, (unsigned)ntohs(sb->sin_port));
    } else {
        printf("[SERVER] Path %s id=%llu\n", event, (unsigned long long)path_id);
    }
    printf("[SERVER] Same connection start time=%llu\n",
           (unsigned long long)picoquic_get_cnx_start_time(cnx));
    fflush(stdout);
}

static int server_callback(picoquic_cnx_t* cnx, uint64_t stream_id,
                           uint8_t* bytes, size_t length,
                           picoquic_call_back_event_t event,
                           void* callback_ctx, void* stream_ctx)
{
    (void)stream_ctx;
    server_ctx_t* ctx = (server_ctx_t*)callback_ctx;
    if (ctx == NULL) return -1;

    switch (event) {
    case picoquic_callback_ready:
        if (ctx->cnx != NULL && ctx->cnx != cnx && atomic_load(&ctx->connected)) {
            fprintf(stderr, "[SERVER] Stage 1 only supports one active client\n");
            return -1;
        }
        ctx->cnx = cnx;
        atomic_store(&ctx->connected, 1);
        picoquic_enable_path_callbacks(cnx, 1);
        printf("[SERVER] QUIC connected; start time=%llu\n",
               (unsigned long long)picoquic_get_cnx_start_time(cnx));
        fflush(stdout);
        break;

    case picoquic_callback_datagram: {
        if (length < 20 || length > PACKET_MAX || (bytes[0] >> 4) != 4) {
            fprintf(stderr, "[SERVER] Invalid incoming IP packet: %zu bytes\n", length);
            break;
        }
        print_ipv4_packet(bytes, length, "QUIC -> TUN");
        ssize_t n = write(ctx->tun_fd, bytes, length);
        if (n < 0) perror("[SERVER] write(tun0)");
        else if ((size_t)n != length)
            fprintf(stderr, "[SERVER] Short TUN write: %zd/%zu\n", n, length);
        fflush(stdout);
        break;
    }

    case picoquic_callback_path_available:
        log_server_path(cnx, stream_id, "AVAILABLE");
        break;
    case picoquic_callback_path_suspended:
        log_server_path(cnx, stream_id, "SUSPENDED");
        break;
    case picoquic_callback_path_deleted:
        printf("[SERVER] Path deleted id=%llu\n", (unsigned long long)stream_id);
        fflush(stdout);
        break;

    case picoquic_callback_close:
    case picoquic_callback_application_close:
    case picoquic_callback_stateless_reset:
        if (ctx->cnx == cnx) {
            atomic_store(&ctx->connected, 0);
            ctx->cnx = NULL;
        }
        printf("[SERVER] QUIC connection closed (event=%d)\n", (int)event);
        fflush(stdout);
        break;
    default:
        break;
    }
    return 0;
}

static int server_loop_callback(picoquic_quic_t* quic,
                                picoquic_packet_loop_cb_enum cb_mode,
                                void* callback_ctx, void* callback_arg)
{
    (void)quic;
    (void)callback_arg;
    server_ctx_t* ctx = (server_ctx_t*)callback_ctx;
    if (ctx == NULL) return -1;
    if (cb_mode != picoquic_packet_loop_wake_up ||
        !atomic_load(&ctx->connected) || ctx->cnx == NULL) return 0;

    tunnel_packet_t packet;
    while (dequeue_packet(ctx, &packet)) {
        int ret = picoquic_queue_datagram_frame(ctx->cnx, packet.length, packet.data);
        if (ret != 0) {
            fprintf(stderr, "[SERVER] Return QUIC DATAGRAM queue error: %d\n", ret);
            continue;
        }
        print_ipv4_packet(packet.data, packet.length, "TUN -> QUIC");
    }
    fflush(stdout);
    return 0;
}

int start_picoquic_server(int port, const char* cert_file, const char* key_file)
{
    int ret = -1;
    server_ctx_t ctx = {0};
    ctx.tun_fd = -1;
    pthread_mutex_init(&ctx.mutex, NULL);
    atomic_init(&ctx.connected, 0);

    ctx.tun_fd = tun_create("tun0");
    if (ctx.tun_fd < 0) goto cleanup_mutex;
    if (tun_configure("tun0") != 0) goto cleanup_tun;

    picoquic_quic_t* quic = picoquic_create(
        8, cert_file, key_file, NULL, "seamlessnet", server_callback, &ctx,
        NULL, NULL, NULL, picoquic_current_time(), NULL, NULL, NULL, 0);
    if (quic == NULL) {
        fprintf(stderr, "[SERVER] picoquic_create failed\n");
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
    if (thread == NULL) {
        fprintf(stderr, "[SERVER] Picoquic network thread failed: %d\n", ret);
        goto cleanup_quic;
    }

    printf("[SERVER] Listening UDP %d on both Network A and Network B\n", port);
    printf("[SERVER] TUN 10.10.0.2/24; one client; no automatic reconnect\n");
    fflush(stdout);

    uint8_t packet[PACKET_MAX];
    for (;;) {
        ssize_t n = read(ctx.tun_fd, packet, sizeof(packet));
        if (n < 0) {
            if (errno == EINTR) continue;
            perror("[SERVER] read(tun0)");
            break;
        }
        if (!atomic_load(&ctx.connected)) continue;
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
