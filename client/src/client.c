#include "picoquic.h"
#include "picoquic_packet_loop.h"
#include "tun.h"

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <stdatomic.h>


#define PACKET_MAX 1000
#define PACKET_QUEUE 64

/* 5 minutes */
#define SEAMLESSNET_IDLE_TIMEOUT_MS 300000


/* =========================================================
 * Packet queue
 * ========================================================= */

typedef struct
{
    uint8_t data[PACKET_MAX];
    size_t length;

} tunnel_packet_t;


/* =========================================================
 * Client context
 * ========================================================= */

typedef struct
{
    tunnel_packet_t packets[PACKET_QUEUE];

    int head;
    int tail;
    int count;

    pthread_mutex_t mutex;

    picoquic_cnx_t* cnx;

    atomic_int connected;

    /*
     * TUN file descriptor.
     *
     * Used for return traffic:
     *
     * QUIC -> client -> write(tun0) -> Linux
     */
    int tun_fd;

} client_ctx_t;


/* =========================================================
 * Queue packet
 * ========================================================= */

static int queue_packet(
    client_ctx_t* ctx,
    const uint8_t* data,
    size_t length)
{
    if (length > PACKET_MAX)
    {
        fprintf(
            stderr,
            "[CLIENT] Dropping oversized packet: %zu bytes\n",
            length
        );

        return -1;
    }


    pthread_mutex_lock(&ctx->mutex);


    if (ctx->count >= PACKET_QUEUE)
    {
        pthread_mutex_unlock(&ctx->mutex);

        fprintf(
            stderr,
            "[CLIENT] Packet queue full - dropping packet\n"
        );

        return -1;
    }


    tunnel_packet_t* packet =
        &ctx->packets[ctx->tail];


    memcpy(
        packet->data,
        data,
        length
    );


    packet->length = length;


    ctx->tail =
        (ctx->tail + 1) % PACKET_QUEUE;


    ctx->count++;


    pthread_mutex_unlock(&ctx->mutex);


    return 0;
}


/* =========================================================
 * Dequeue packet
 * ========================================================= */

static int dequeue_packet(
    client_ctx_t* ctx,
    tunnel_packet_t* output)
{
    pthread_mutex_lock(&ctx->mutex);


    if (ctx->count == 0)
    {
        pthread_mutex_unlock(&ctx->mutex);

        return 0;
    }


    *output =
        ctx->packets[ctx->head];


    ctx->head =
        (ctx->head + 1) % PACKET_QUEUE;


    ctx->count--;


    pthread_mutex_unlock(&ctx->mutex);


    return 1;
}


/* =========================================================
 * Picoquic client callback
 * ========================================================= */

static int client_callback(
    picoquic_cnx_t* cnx,
    uint64_t stream_id,
    uint8_t* bytes,
    size_t length,
    picoquic_call_back_event_t event,
    void* callback_ctx,
    void* stream_ctx)
{
    (void)stream_id;
    (void)stream_ctx;


    client_ctx_t* ctx =
        (client_ctx_t*)callback_ctx;


    switch (event)
    {
        /* -------------------------------------------------
         * QUIC connection ready
         * ------------------------------------------------- */

        case picoquic_callback_ready:
        {
            printf(
                "[CLIENT] QUIC connection established!\n"
            );


            ctx->cnx = cnx;


            atomic_store(
                &ctx->connected,
                1
            );


            fflush(stdout);

            break;
        }


        /* -------------------------------------------------
         * QUIC DATAGRAM received from server
         *
         * This is return traffic.
         *
         * Server
         *   |
         *   | QUIC DATAGRAM
         *   v
         * Client
         *   |
         *   | write()
         *   v
         * tun0
         *   |
         *   v
         * Linux network stack
         * ------------------------------------------------- */

        case picoquic_callback_datagram:
        {
            printf(
                "[CLIENT] QUIC -> TUN: received %zu bytes\n",
                length
            );


            if (ctx->tun_fd < 0)
            {
                fprintf(
                    stderr,
                    "[CLIENT] Invalid TUN descriptor\n"
                );

                break;
            }


            ssize_t written =
                write(
                    ctx->tun_fd,
                    bytes,
                    length
                );


            if (written < 0)
            {
                perror(
                    "[CLIENT] write(tun0)"
                );
            }
            else if ((size_t)written != length)
            {
                fprintf(
                    stderr,
                    "[CLIENT] Partial TUN write: %zd/%zu\n",
                    written,
                    length
                );
            }
            else
            {
                printf(
                    "[CLIENT] Injected %zu-byte IP packet into tun0\n",
                    length
                );
            }


            fflush(stdout);

            break;
        }


        /* -------------------------------------------------
         * Normal QUIC close
         * ------------------------------------------------- */

        case picoquic_callback_close:
        {
            printf(
                "[CLIENT] QUIC connection closed\n"
            );


            atomic_store(
                &ctx->connected,
                0
            );


            fflush(stdout);

            break;
        }


        /* -------------------------------------------------
         * Application close
         * ------------------------------------------------- */

        case picoquic_callback_application_close:
        {
            printf(
                "[CLIENT] QUIC application close received\n"
            );


            atomic_store(
                &ctx->connected,
                0
            );


            fflush(stdout);

            break;
        }


        /* -------------------------------------------------
         * Stateless reset
         * ------------------------------------------------- */

        case picoquic_callback_stateless_reset:
        {
            printf(
                "[CLIENT] QUIC stateless reset received\n"
            );


            atomic_store(
                &ctx->connected,
                0
            );


            fflush(stdout);

            break;
        }


        default:
            break;
    }


    return 0;
}


/* =========================================================
 * Picoquic network-thread callback
 *
 * The TUN thread does NOT directly call Picoquic send
 * operations.
 *
 * Instead:
 *
 * TUN thread
 *     |
 *     | queue packet
 *     v
 * packet queue
 *     |
 *     | wake Picoquic
 *     v
 * Picoquic network thread
 *     |
 *     | queue QUIC DATAGRAM
 *     v
 * network
 * ========================================================= */

static int client_loop_callback(
    picoquic_quic_t* quic,
    picoquic_packet_loop_cb_enum cb_mode,
    void* callback_ctx,
    void* callback_arg)
{
    (void)quic;
    (void)callback_arg;


    client_ctx_t* ctx =
        (client_ctx_t*)callback_ctx;


    if (ctx == NULL)
    {
        return PICOQUIC_ERROR_UNEXPECTED_ERROR;
    }


    if (cb_mode == picoquic_packet_loop_wake_up)
    {
        /*
         * Do not attempt to send packets when QUIC
         * is disconnected.
         */
        if (!atomic_load(&ctx->connected))
        {
            return 0;
        }


        tunnel_packet_t packet;


        while (dequeue_packet(
            ctx,
            &packet))
        {
            /*
             * One IP packet becomes one QUIC DATAGRAM.
             */
            int ret =
                picoquic_queue_datagram_frame(
                    ctx->cnx,
                    packet.length,
                    packet.data
                );


            if (ret != 0)
            {
                fprintf(
                    stderr,
                    "[CLIENT] Failed to queue QUIC datagram: %d\n",
                    ret
                );

                return ret;
            }


            printf(
                "[CLIENT] TUN -> QUIC: %zu bytes\n",
                packet.length
            );


            fflush(stdout);
        }
    }


    return 0;
}


/* =========================================================
 * Start SeamlessNet client
 * ========================================================= */

int start_picoquic_client(
    const char* server_ip,
    int port)
{
    int ret = 0;


    /* -----------------------------------------------------
     * Initialise client context
     * ----------------------------------------------------- */

    client_ctx_t ctx;


    memset(
        &ctx,
        0,
        sizeof(ctx)
    );


    ctx.tun_fd = -1;


    pthread_mutex_init(
        &ctx.mutex,
        NULL
    );


    atomic_init(
        &ctx.connected,
        0
    );


    /* =====================================================
     * Create TUN interface
     * ===================================================== */

    int tun_fd =
        tun_create("tun0");


    if (tun_fd < 0)
    {
        pthread_mutex_destroy(
            &ctx.mutex
        );

        return -1;
    }


    ctx.tun_fd = tun_fd;


    if (tun_configure("tun0") != 0)
    {
        close(tun_fd);

        pthread_mutex_destroy(
            &ctx.mutex
        );

        return -1;
    }


    /* =====================================================
     * Create Picoquic context
     * ===================================================== */

    uint64_t current_time =
        picoquic_current_time();


    picoquic_quic_t* quic =
        picoquic_create(
            1,
            NULL,
            NULL,
            NULL,
            "seamlessnet",
            client_callback,
            &ctx,
            NULL,
            NULL,
            NULL,
            current_time,
            NULL,
            NULL,
            NULL,
            0
        );


    if (quic == NULL)
    {
        fprintf(
            stderr,
            "[CLIENT] Failed to create QUIC context\n"
        );


        close(tun_fd);


        pthread_mutex_destroy(
            &ctx.mutex
        );


        return -1;
    }


    /* -----------------------------------------------------
     * Prototype idle timeout
     *
     * Default Picoquic idle timeout is about 30 seconds.
     *
     * For the Stage 1 prototype we use 5 minutes.
     * ----------------------------------------------------- */

    picoquic_set_default_idle_timeout(
        quic,
        SEAMLESSNET_IDLE_TIMEOUT_MS
    );


    /*
     * DEVELOPMENT ONLY.
     *
     * Allows our self-signed server certificate.
     */
    picoquic_set_null_verifier(quic);


    /* -----------------------------------------------------
     * Enable QUIC DATAGRAM support
     * ----------------------------------------------------- */

    picoquic_tp_t tp =
        *picoquic_get_default_tp(quic);


    tp.max_datagram_frame_size =
        65535;


    picoquic_set_default_tp(
        quic,
        &tp
    );


    /* =====================================================
     * Configure server address
     * ===================================================== */

    struct sockaddr_in server_address;


    memset(
        &server_address,
        0,
        sizeof(server_address)
    );


    server_address.sin_family =
        AF_INET;


    server_address.sin_port =
        htons(
            (uint16_t)port
        );


    if (inet_pton(
            AF_INET,
            server_ip,
            &server_address.sin_addr) != 1)
    {
        fprintf(
            stderr,
            "[CLIENT] Invalid server IP: %s\n",
            server_ip
        );


        picoquic_free(quic);

        close(tun_fd);

        pthread_mutex_destroy(
            &ctx.mutex
        );


        return -1;
    }


    /* =====================================================
     * Create QUIC connection
     * ===================================================== */

    picoquic_cnx_t* cnx =
        picoquic_create_cnx(
            quic,
            picoquic_null_connection_id,
            picoquic_null_connection_id,
            (struct sockaddr*)&server_address,
            current_time,
            0,
            server_ip,
            "seamlessnet",
            1
        );


    if (cnx == NULL)
    {
        fprintf(
            stderr,
            "[CLIENT] Failed to create QUIC connection\n"
        );


        picoquic_free(quic);

        close(tun_fd);

        pthread_mutex_destroy(
            &ctx.mutex
        );


        return -1;
    }


    ctx.cnx = cnx;


    picoquic_set_callback(
        cnx,
        client_callback,
        &ctx
    );


    /* =====================================================
     * Start client connection
     * ===================================================== */

    ret =
        picoquic_start_client_cnx(
            cnx
        );


    if (ret != 0)
    {
        fprintf(
            stderr,
            "[CLIENT] Failed to start QUIC connection: %d\n",
            ret
        );


        picoquic_free(quic);

        close(tun_fd);

        pthread_mutex_destroy(
            &ctx.mutex
        );


        return ret;
    }


    printf(
        "[CLIENT] Connecting to %s:%d...\n",
        server_ip,
        port
    );


    /* =====================================================
     * Start Picoquic network thread
     * ===================================================== */

    picoquic_packet_loop_param_t param =
        {0};


    param.local_af =
        AF_INET;


    picoquic_network_thread_ctx_t* network_thread =
        picoquic_start_network_thread(
            quic,
            &param,
            client_loop_callback,
            &ctx,
            &ret
        );


    if (network_thread == NULL)
    {
        fprintf(
            stderr,
            "[CLIENT] Failed to start network thread\n"
        );


        picoquic_free(quic);

        close(tun_fd);

        pthread_mutex_destroy(
            &ctx.mutex
        );


        return -1;
    }


    printf(
        "[CLIENT] Waiting for QUIC connection...\n"
    );


    /* -----------------------------------------------------
     * Wait for handshake
     * ----------------------------------------------------- */

    while (!atomic_load(&ctx.connected))
    {
        usleep(10000);
    }


    printf("\n");
    printf("=====================================\n");
    printf("       SeamlessNet Tunnel Active\n");
    printf("=====================================\n");
    printf("TUN:          tun0\n");
    printf("TUN IP:       10.10.0.1/24\n");
    printf("Server:       %s:%d\n", server_ip, port);
    printf("Transport:    QUIC DATAGRAM\n");
    printf("Idle timeout: 300 seconds\n");
    printf("=====================================\n");
    printf("\n");


    printf(
        "[CLIENT] Waiting for TUN packets...\n"
    );


    /* =====================================================
     * TUN capture loop
     * ===================================================== */

    uint8_t packet[PACKET_MAX];


    while (1)
    {
        ssize_t length =
            read(
                tun_fd,
                packet,
                sizeof(packet)
            );


        if (length < 0)
        {
            perror(
                "[TUN] read"
            );

            break;
        }


        printf(
            "[TUN] Captured %zd-byte IP packet\n",
            length
        );


        /*
         * During Stage 1 we deliberately DO NOT
         * reconnect automatically.
         *
         * This makes it obvious if the QUIC
         * connection actually died.
         */
        if (!atomic_load(&ctx.connected))
        {
            fprintf(
                stderr,
                "[CLIENT] QUIC disconnected - dropping TUN packet\n"
            );

            continue;
        }


        if (queue_packet(
                &ctx,
                packet,
                (size_t)length) == 0)
        {
            /*
             * Tell Picoquic's network thread that
             * application data is waiting.
             */
            picoquic_wake_up_network_thread(
                network_thread
            );
        }
    }


    /* =====================================================
     * Cleanup
     * ===================================================== */

    printf(
        "[CLIENT] Shutting down...\n"
    );


    picoquic_delete_network_thread(
        network_thread
    );


    picoquic_free(
        quic
    );


    close(
        tun_fd
    );


    pthread_mutex_destroy(
        &ctx.mutex
    );


    return 0;
}