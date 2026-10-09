#include "picoquic.h"
#include "picoquic_packet_loop.h"
#include "tun.h"

#include <arpa/inet.h>
#include <errno.h>
#include <poll.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define PACKET_MAX 1000
#define PACKET_QUEUE 64
#define SEAMLESSNET_IDLE_TIMEOUT_MS 300000
#define MIGRATION_TRIGGER "/tmp/seamlessnet-migrate"
#define NETWORK_B_CLIENT_IP "172.21.0.20"
#define NETWORK_B_SERVER_IP "172.21.0.10"

typedef struct {
    uint8_t data[PACKET_MAX];
    size_t length;
} tunnel_packet_t;

typedef struct {
    tunnel_packet_t packets[PACKET_QUEUE];
    unsigned head, tail, count;
    pthread_mutex_t mutex;

    /* Picoquic connection pointer is used only on its network thread
       after the thread starts. */
    picoquic_cnx_t* cnx;
    int server_port;
    int tun_fd;
    atomic_int connected;
    atomic_int migrate_requested;
    atomic_int migration_validated;
} client_ctx_t;

static int queue_packet(client_ctx_t* ctx, const uint8_t* data, size_t length)
{
    if (length == 0 || length > PACKET_MAX) {
        fprintf(stderr, "[CLIENT] Invalid/oversized TUN packet: %zu bytes\n", length);
        return -1;
    }
    pthread_mutex_lock(&ctx->mutex);
    if (ctx->count == PACKET_QUEUE) {
        pthread_mutex_unlock(&ctx->mutex);
        fprintf(stderr, "[CLIENT] Outgoing packet queue full; dropping packet\n");
        return -1;
    }
    tunnel_packet_t* packet = &ctx->packets[ctx->tail];
    memcpy(packet->data, data, length);
    packet->length = length;
    ctx->tail = (ctx->tail + 1) % PACKET_QUEUE;
    ctx->count++;
    pthread_mutex_unlock(&ctx->mutex);
    return 0;
}

static int dequeue_packet(client_ctx_t* ctx, tunnel_packet_t* output)
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

static void log_path(picoquic_cnx_t* cnx, uint64_t path_id, const char* prefix,
                     client_ctx_t* ctx)
{
    struct sockaddr_storage local = {0};
    struct sockaddr_storage peer = {0};
    char local_ip[INET_ADDRSTRLEN] = "?";
    char peer_ip[INET_ADDRSTRLEN] = "?";

    int local_ok = picoquic_get_path_addr(cnx, path_id, 1, &local);
    int peer_ok = picoquic_get_path_addr(cnx, path_id, 2, &peer);
    if (local_ok == 0 && peer_ok == 0 &&
        local.ss_family == AF_INET && peer.ss_family == AF_INET) {
        const struct sockaddr_in* a = (const struct sockaddr_in*)&local;
        const struct sockaddr_in* b = (const struct sockaddr_in*)&peer;
        inet_ntop(AF_INET, &a->sin_addr, local_ip, sizeof(local_ip));
        inet_ntop(AF_INET, &b->sin_addr, peer_ip, sizeof(peer_ip));
        printf("[MIGRATION] %s path=%llu local=%s:%u peer=%s:%u\n",
               prefix, (unsigned long long)path_id,
               local_ip, (unsigned)ntohs(a->sin_port),
               peer_ip, (unsigned)ntohs(b->sin_port));

        if (strcmp(local_ip, NETWORK_B_CLIENT_IP) == 0 &&
            strcmp(peer_ip, NETWORK_B_SERVER_IP) == 0 &&
            strcmp(prefix, "AVAILABLE") == 0) {
            atomic_store(&ctx->migration_validated, 1);
            printf("[MIGRATION] Network B validated on ORIGINAL QUIC connection\n");
        }
    } else {
        printf("[MIGRATION] %s path=%llu (addresses unavailable)\n",
               prefix, (unsigned long long)path_id);
    }
    printf("[MIGRATION] Connection start time: %llu\n",
           (unsigned long long)picoquic_get_cnx_start_time(cnx));
    fflush(stdout);
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
    case picoquic_callback_ready:
        ctx->cnx = cnx;
        atomic_store(&ctx->connected, 1);
        printf("[CLIENT] QUIC connected; start time=%llu\n",
               (unsigned long long)picoquic_get_cnx_start_time(cnx));
        fflush(stdout);
        break;

    case picoquic_callback_datagram: {
        /* The server sends an entire IPv4 packet as one QUIC DATAGRAM. */
        if (length < 20 || length > PACKET_MAX || (bytes[0] >> 4) != 4) {
            fprintf(stderr, "[CLIENT] Ignoring invalid return IP packet (%zu bytes)\n", length);
            break;
        }
        ssize_t n = write(ctx->tun_fd, bytes, length);
        if (n < 0) perror("[CLIENT] write(tun0)");
        else if ((size_t)n != length)
            fprintf(stderr, "[CLIENT] Short TUN write: %zd/%zu\n", n, length);
        else printf("[CLIENT] QUIC -> TUN: %zu bytes\n", length);
        fflush(stdout);
        break;
    }

    case picoquic_callback_path_available:
        log_path(cnx, stream_id, "AVAILABLE", ctx);
        break;
    case picoquic_callback_path_suspended:
        log_path(cnx, stream_id, "SUSPENDED", ctx);
        break;
    case picoquic_callback_path_deleted:
        printf("[MIGRATION] Path deleted: %llu\n", (unsigned long long)stream_id);
        fflush(stdout);
        break;

    case picoquic_callback_close:
    case picoquic_callback_application_close:
    case picoquic_callback_stateless_reset:
        atomic_store(&ctx->connected, 0);
        printf("[CLIENT] QUIC closed (event=%d); NO automatic reconnection\n", (int)event);
        fflush(stdout);
        break;
    default:
        break;
    }
    return 0;
}

/* Only the Picoquic network thread may initiate migration or send datagrams. */
static int request_network_b_migration(client_ctx_t* ctx)
{
    if (!atomic_load(&ctx->connected) || ctx->cnx == NULL) {
        fprintf(stderr, "[MIGRATION] No active connection\n");
        return -1;
    }
    if (atomic_load(&ctx->migration_validated)) {
        printf("[MIGRATION] Network B is already validated\n");
        return 0;
    }

    struct sockaddr* current_local = NULL;
    picoquic_get_local_addr(ctx->cnx, &current_local);
    if (current_local == NULL || current_local->sa_family != AF_INET) {
        fprintf(stderr, "[MIGRATION] Cannot read current local IPv4 address\n");
        return -1;
    }

    struct sockaddr_in new_local = {0};
    struct sockaddr_in new_peer = {0};
    new_local.sin_family = AF_INET;
    /* Retain the established UDP source port across the new path. */
    new_local.sin_port = ((struct sockaddr_in*)current_local)->sin_port;
    new_peer.sin_family = AF_INET;
    new_peer.sin_port = htons((uint16_t)ctx->server_port);

    if (inet_pton(AF_INET, NETWORK_B_CLIENT_IP, &new_local.sin_addr) != 1 ||
        inet_pton(AF_INET, NETWORK_B_SERVER_IP, &new_peer.sin_addr) != 1) {
        fprintf(stderr, "[MIGRATION] Invalid Network B address\n");
        return -1;
    }

    printf("[MIGRATION] Probing %s:%u -> %s:%u\n",
           NETWORK_B_CLIENT_IP, (unsigned)ntohs(new_local.sin_port),
           NETWORK_B_SERVER_IP, (unsigned)ctx->server_port);
    int ret = picoquic_probe_new_path(
        ctx->cnx, (const struct sockaddr*)&new_peer,
        (const struct sockaddr*)&new_local, picoquic_current_time());
    printf("[MIGRATION] Probe request returned %d (0 = accepted, not yet validated)\n", ret);
    fflush(stdout);
    return ret;
}

static int client_loop_callback(picoquic_quic_t* quic,
                                picoquic_packet_loop_cb_enum cb_mode,
                                void* callback_ctx, void* callback_arg)
{
    (void)quic;
    (void)callback_arg;
    client_ctx_t* ctx = (client_ctx_t*)callback_ctx;
    if (ctx == NULL) return -1;
    if (cb_mode != picoquic_packet_loop_wake_up) return 0;

    if (atomic_exchange(&ctx->migrate_requested, 0)) {
        (void)request_network_b_migration(ctx);
    }
    if (!atomic_load(&ctx->connected)) return 0;

    tunnel_packet_t packet;
    while (dequeue_packet(ctx, &packet)) {
        int ret = picoquic_queue_datagram_frame(ctx->cnx, packet.length, packet.data);
        if (ret != 0) {
            fprintf(stderr, "[CLIENT] QUIC DATAGRAM queue error: %d\n", ret);
            /* This is a per-packet failure; do not terminate the network loop. */
            continue;
        }
        printf("[CLIENT] TUN -> QUIC: %zu bytes\n", packet.length);
    }
    fflush(stdout);
    return 0;
}

int start_picoquic_client(const char* server_ip, int port)
{
    int ret = -1;
    client_ctx_t ctx = {0};
    ctx.tun_fd = -1;
    ctx.server_port = port;
    pthread_mutex_init(&ctx.mutex, NULL);
    atomic_init(&ctx.connected, 0);
    atomic_init(&ctx.migrate_requested, 0);
    atomic_init(&ctx.migration_validated, 0);

    ctx.tun_fd = tun_create("tun0");
    if (ctx.tun_fd < 0) goto cleanup_mutex;
    if (tun_configure("tun0") != 0) goto cleanup_tun;

    uint64_t now = picoquic_current_time();
    picoquic_quic_t* quic = picoquic_create(
        1, NULL, NULL, NULL, "seamlessnet", client_callback, &ctx,
        NULL, NULL, NULL, now, NULL, NULL, NULL, 0);
    if (quic == NULL) {
        fprintf(stderr, "[CLIENT] picoquic_create failed\n");
        goto cleanup_tun;
    }
    picoquic_set_default_idle_timeout(quic, SEAMLESSNET_IDLE_TIMEOUT_MS);
    /* Development only: self-signed certificate; not secure for deployment. */
    picoquic_set_null_verifier(quic);
    picoquic_tp_t tp = *picoquic_get_default_tp(quic);
    tp.max_datagram_frame_size = 65535;
    picoquic_set_default_tp(quic, &tp);

    struct sockaddr_in peer = {0};
    peer.sin_family = AF_INET;
    peer.sin_port = htons((uint16_t)port);
    if (inet_pton(AF_INET, server_ip, &peer.sin_addr) != 1) {
        fprintf(stderr, "[CLIENT] Invalid server IPv4 address: %s\n", server_ip);
        goto cleanup_quic;
    }

    picoquic_cnx_t* cnx = picoquic_create_cnx(
        quic, picoquic_null_connection_id, picoquic_null_connection_id,
        (struct sockaddr*)&peer, now, 0, server_ip, "seamlessnet", 1);
    if (cnx == NULL) {
        fprintf(stderr, "[CLIENT] picoquic_create_cnx failed\n");
        goto cleanup_quic;
    }
    ctx.cnx = cnx;
    picoquic_set_callback(cnx, client_callback, &ctx);
    picoquic_enable_path_callbacks(cnx, 1);
    ret = picoquic_start_client_cnx(cnx);
    if (ret != 0) {
        fprintf(stderr, "[CLIENT] Failed to start QUIC connection: %d\n", ret);
        goto cleanup_quic;
    }

    picoquic_packet_loop_param_t param = {0};
    param.local_af = AF_INET;
    picoquic_network_thread_ctx_t* thread = picoquic_start_network_thread(
        quic, &param, client_loop_callback, &ctx, &ret);
    if (thread == NULL) {
        fprintf(stderr, "[CLIENT] Failed to start Picoquic thread: %d\n", ret);
        goto cleanup_quic;
    }

    printf("[CLIENT] Connecting via Network A: %s:%d\n", server_ip, port);
    fflush(stdout);
    int connected = 0;
    for (int i = 0; i < 300; ++i) {
        if (atomic_load(&ctx.connected)) { connected = 1; break; }
        usleep(100000);
    }
    if (!connected) {
        fprintf(stderr, "[CLIENT] QUIC handshake did not finish within 30 seconds\n");
        ret = -1;
        goto cleanup_thread;
    }

    printf("[CLIENT] Tunnel active: tun0=10.10.0.1/24 MTU=1000\n");
    printf("[CLIENT] Migration trigger: touch %s\n", MIGRATION_TRIGGER);
    fflush(stdout);

    uint8_t packet[PACKET_MAX];
    for (;;) {
        /* A file trigger is simple, deterministic, and needs no controller. */
        if (access(MIGRATION_TRIGGER, F_OK) == 0) {
            unlink(MIGRATION_TRIGGER);
            printf("[MIGRATION] Manual trigger detected\n");
            atomic_store(&ctx.migrate_requested, 1);
            picoquic_wake_up_network_thread(thread);
        }

        struct pollfd pfd = {.fd = ctx.tun_fd, .events = POLLIN};
        int ready = poll(&pfd, 1, 200);
        if (ready == 0) continue;
        if (ready < 0) {
            if (errno == EINTR) continue;
            perror("[CLIENT] poll(tun0)");
            break;
        }
        if (!(pfd.revents & POLLIN)) {
            fprintf(stderr, "[CLIENT] Unexpected TUN poll event: 0x%x\n", pfd.revents);
            break;
        }

        ssize_t n = read(ctx.tun_fd, packet, sizeof(packet));
        if (n < 0) {
            if (errno == EINTR) continue;
            perror("[CLIENT] read(tun0)");
            break;
        }
        if (!atomic_load(&ctx.connected)) {
            fprintf(stderr, "[CLIENT] QUIC disconnected; dropping TUN packet\n");
            continue;
        }
        if (queue_packet(&ctx, packet, (size_t)n) == 0) {
            picoquic_wake_up_network_thread(thread);
        }
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
