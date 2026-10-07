#include "picoquic.h"
#include "picoquic_packet_loop.h"
#include "tun.h"

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <pthread.h>
#include <stdatomic.h>

#include <arpa/inet.h>


#define PACKET_MAX 1000
#define PACKET_QUEUE 64

#define SEAMLESSNET_IDLE_TIMEOUT_MS 300000


/* =========================================================
 * Packet structure
 * ========================================================= */

typedef struct
{
    uint8_t data[PACKET_MAX];
    size_t length;

} tunnel_packet_t;


/* =========================================================
 * Server context
 *
 * Stage 1 currently supports one active client.
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

    int tun_fd;

} server_ctx_t;


/* =========================================================
 * Queue outgoing packet
 *
 * These are packets Linux gives us from server tun0 that
 * need to travel back to the client.
 * ========================================================= */

static int queue_packet(
    server_ctx_t* ctx,
    const uint8_t* data,
    size_t length)
{
    if (length > PACKET_MAX)
    {
        fprintf(
            stderr,
            "[SERVER] Dropping oversized return packet: %zu bytes\n",
            length
        );

        return -1;
    }


    pthread_mutex_lock(
        &ctx->mutex
    );


    if (ctx->count >= PACKET_QUEUE)
    {
        pthread_mutex_unlock(
            &ctx->mutex
        );

        fprintf(
            stderr,
            "[SERVER] Return packet queue full - dropping packet\n"
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


    packet->length =
        length;


    ctx->tail =
        (ctx->tail + 1) % PACKET_QUEUE;


    ctx->count++;


    pthread_mutex_unlock(
        &ctx->mutex
    );


    return 0;
}


/* =========================================================
 * Dequeue outgoing packet
 * ========================================================= */

static int dequeue_packet(
    server_ctx_t* ctx,
    tunnel_packet_t* output)
{
    pthread_mutex_lock(
        &ctx->mutex
    );


    if (ctx->count == 0)
    {
        pthread_mutex_unlock(
            &ctx->mutex
        );

        return 0;
    }


    *output =
        ctx->packets[ctx->head];


    ctx->head =
        (ctx->head + 1) % PACKET_QUEUE;


    ctx->count--;


    pthread_mutex_unlock(
        &ctx->mutex
    );


    return 1;
}


/* =========================================================
 * Basic IP packet logging
 * ========================================================= */

static void print_ipv4_packet(
    const uint8_t* packet,
    size_t length,
    const char* direction)
{
    if (length < 20)
    {
        return;
    }


    uint8_t version =
        packet[0] >> 4;


    if (version != 4)
    {
        return;
    }


    char source[
        INET_ADDRSTRLEN
    ];


    char destination[
        INET_ADDRSTRLEN
    ];


    inet_ntop(
        AF_INET,
        packet + 12,
        source,
        sizeof(source)
    );


    inet_ntop(
        AF_INET,
        packet + 16,
        destination,
        sizeof(destination)
    );


    uint8_t protocol =
        packet[9];


    printf(
        "[SERVER] %s | %s -> %s | %zu bytes | protocol=%u",
        direction,
        source,
        destination,
        length,
        protocol
    );


    if (protocol == 1)
    {
        printf(" ICMP");
    }
    else if (protocol == 6)
    {
        printf(" TCP");
    }
    else if (protocol == 17)
    {
        printf(" UDP");
    }


    printf("\n");

    fflush(stdout);
}


/* =========================================================
 * Picoquic connection callback
 * ========================================================= */

static int server_callback(
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


    server_ctx_t* ctx =
        (server_ctx_t*)callback_ctx;


    switch (event)
    {
        /* -------------------------------------------------
         * Client connected
         * ------------------------------------------------- */

        case picoquic_callback_ready:
        {
            printf(
                "[SERVER] QUIC connection established!\n"
            );


            /*
             * Stage 1:
             * only one client connection.
             */
            ctx->cnx =
                cnx;


            atomic_store(
                &ctx->connected,
                1
            );


            fflush(stdout);

            break;
        }


        /* -------------------------------------------------
         * Client -> Server QUIC DATAGRAM
         *
         * The datagram contains one complete IP packet.
         *
         * Inject it into Linux through tun0.
         * ------------------------------------------------- */

        case picoquic_callback_datagram:
        {
            printf(
                "[SERVER] QUIC -> TUN: received %zu bytes\n",
                length
            );


            print_ipv4_packet(
                bytes,
                length,
                "CLIENT -> INTERNET"
            );


            if (ctx->tun_fd < 0)
            {
                fprintf(
                    stderr,
                    "[SERVER] Invalid TUN descriptor\n"
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
                    "[SERVER] write(tun0)"
                );
            }
            else if ((size_t)written != length)
            {
                fprintf(
                    stderr,
                    "[SERVER] Partial TUN write: %zd/%zu\n",
                    written,
                    length
                );
            }
            else
            {
                printf(
                    "[SERVER] Injected %zu-byte packet into server tun0\n",
                    length
                );
            }


            fflush(stdout);

            break;
        }


        /* -------------------------------------------------
         * Connection closed
         * ------------------------------------------------- */

        case picoquic_callback_close:
        {
            printf(
                "[SERVER] QUIC connection closed\n"
            );


            atomic_store(
                &ctx->connected,
                0
            );


            ctx->cnx =
                NULL;


            fflush(stdout);

            break;
        }


        case picoquic_callback_application_close:
        {
            printf(
                "[SERVER] QUIC application close\n"
            );


            atomic_store(
                &ctx->connected,
                0
            );


            ctx->cnx =
                NULL;


            fflush(stdout);

            break;
        }


        case picoquic_callback_stateless_reset:
        {
            printf(
                "[SERVER] QUIC stateless reset\n"
            );


            atomic_store(
                &ctx->connected,
                0
            );


            ctx->cnx =
                NULL;


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
 * When Linux gives us a return packet through server tun0,
 * the main thread puts it in our queue and wakes Picoquic.
 *
 * This callback executes inside Picoquic's network thread,
 * where it is safe to call Picoquic APIs.
 * ========================================================= */

static int server_loop_callback(
    picoquic_quic_t* quic,
    picoquic_packet_loop_cb_enum cb_mode,
    void* callback_ctx,
    void* callback_arg)
{
    (void)quic;
    (void)callback_arg;


    server_ctx_t* ctx =
        (server_ctx_t*)callback_ctx;


    if (ctx == NULL)
    {
        return PICOQUIC_ERROR_UNEXPECTED_ERROR;
    }


    if (cb_mode ==
        picoquic_packet_loop_wake_up)
    {
        if (!atomic_load(
                &ctx->connected))
        {
            return 0;
        }


        if (ctx->cnx == NULL)
        {
            return 0;
        }


        tunnel_packet_t packet;


        while (dequeue_packet(
            ctx,
            &packet))
        {
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
                    "[SERVER] Failed to queue return QUIC datagram: %d\n",
                    ret
                );

                return ret;
            }


            printf(
                "[SERVER] TUN -> QUIC: %zu bytes\n",
                packet.length
            );


            fflush(stdout);
        }
    }


    return 0;
}


/* =========================================================
 * Start server
 * ========================================================= */

int start_picoquic_server(
    int port,
    const char* cert_file,
    const char* key_file)
{
    int ret = 0;


    server_ctx_t ctx;


    memset(
        &ctx,
        0,
        sizeof(ctx)
    );


    ctx.tun_fd =
        -1;


    pthread_mutex_init(
        &ctx.mutex,
        NULL
    );


    atomic_init(
        &ctx.connected,
        0
    );


    /* =====================================================
     * Create server TUN
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


    ctx.tun_fd =
        tun_fd;


    if (tun_configure(
            "tun0") != 0)
    {
        close(
            tun_fd
        );


        pthread_mutex_destroy(
            &ctx.mutex
        );


        return -1;
    }


    /* =====================================================
     * Create QUIC context
     * ===================================================== */

    uint64_t current_time =
        picoquic_current_time();


    picoquic_quic_t* quic =
        picoquic_create(
            8,
            cert_file,
            key_file,
            NULL,
            "seamlessnet",
            server_callback,
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
            "[SERVER] Failed to create QUIC context\n"
        );


        close(
            tun_fd
        );


        pthread_mutex_destroy(
            &ctx.mutex
        );


        return -1;
    }


    /* =====================================================
     * Five-minute prototype idle timeout
     * ===================================================== */

    picoquic_set_default_idle_timeout(
        quic,
        SEAMLESSNET_IDLE_TIMEOUT_MS
    );


    /* =====================================================
     * Enable QUIC DATAGRAM
     * ===================================================== */

    picoquic_tp_t tp =
        *picoquic_get_default_tp(
            quic
        );


    tp.max_datagram_frame_size =
        65535;


    picoquic_set_default_tp(
        quic,
        &tp
    );


    /* =====================================================
     * Start QUIC network thread
     *
     * Unlike our previous server, the packet loop must now
     * run in the background because the main thread needs
     * to read return packets from tun0.
     *
     * Picoquic explicitly supports this threaded pattern:
     * applications can wake the network thread and safely
     * call Picoquic APIs from the wake-up callback.
     * ===================================================== */

    picoquic_packet_loop_param_t param =
        {0};


    param.local_port =
        (uint16_t)port;


    param.local_af =
        AF_INET;


    printf(
        "[SERVER] Starting QUIC listener on UDP %d...\n",
        port
    );


    picoquic_network_thread_ctx_t* network_thread =
        picoquic_start_network_thread(
            quic,
            &param,
            server_loop_callback,
            &ctx,
            &ret
        );


    if (network_thread == NULL)
    {
        fprintf(
            stderr,
            "[SERVER] Failed to start network thread: %d\n",
            ret
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


        return -1;
    }


    printf("\n");
    printf("=====================================\n");
    printf("    SeamlessNet Forwarding Server\n");
    printf("=====================================\n");
    printf("QUIC UDP port: %d\n", port);
    printf("TUN:           tun0\n");
    printf("TUN IP:        10.10.0.2/24\n");
    printf("Transport:     QUIC DATAGRAM\n");
    printf("=====================================\n");
    printf("\n");


    printf(
        "[SERVER] Waiting for client connection...\n"
    );


    /* =====================================================
     * Read return packets from Linux
     *
     * Internet
     *    |
     *   eth0
     *    |
     * Linux routing / reverse NAT
     *    |
     *   tun0
     *    |
     * read()
     *    |
     * SeamlessNet
     * ===================================================== */

    uint8_t packet[
        PACKET_MAX
    ];


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
                "[SERVER TUN] read"
            );

            break;
        }


        printf(
            "[SERVER TUN] Captured return packet: %zd bytes\n",
            length
        );


        print_ipv4_packet(
            packet,
            (size_t)length,
            "INTERNET -> CLIENT"
        );


        if (!atomic_load(
                &ctx.connected))
        {
            fprintf(
                stderr,
                "[SERVER] No connected client - dropping return packet\n"
            );

            continue;
        }


        if (queue_packet(
                &ctx,
                packet,
                (size_t)length) == 0)
        {
            picoquic_wake_up_network_thread(
                network_thread
            );
        }
    }


    /* =====================================================
     * Cleanup
     * ===================================================== */

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