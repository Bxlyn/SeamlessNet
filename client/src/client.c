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


#define PACKET_MAX      1000
#define PACKET_QUEUE    64
#define SEAMLESSNET_IDLE_TIMEOUT_MS 300000


typedef struct
{
    uint8_t data[PACKET_MAX];
    size_t length;

} tunnel_packet_t;


typedef struct
{
    tunnel_packet_t packets[PACKET_QUEUE];

    int head;
    int tail;
    int count;

    pthread_mutex_t mutex;

    picoquic_cnx_t* cnx;

    atomic_int connected;

} client_ctx_t;


/* ---------------------------------------------------------
 * Queue helpers
 * --------------------------------------------------------- */

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

static void print_close_reason(
    picoquic_cnx_t* cnx)
{
    uint64_t local_reason = 0;
    uint64_t remote_reason = 0;
    uint64_t local_app_reason = 0;
    uint64_t remote_app_reason = 0;

    picoquic_get_close_reasons(
        cnx,
        &local_reason,
        &remote_reason,
        &local_app_reason,
        &remote_app_reason
    );

    printf(
        "[QUIC] Connection closed\n"
        "       local transport:  %llu\n"
        "       remote transport: %llu\n"
        "       local app:        %llu\n"
        "       remote app:       %llu\n",
        (unsigned long long)local_reason,
        (unsigned long long)remote_reason,
        (unsigned long long)local_app_reason,
        (unsigned long long)remote_app_reason
    );
}

/* ---------------------------------------------------------
 * Picoquic application callback
 * --------------------------------------------------------- */

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
    (void)bytes;
    (void)length;
    (void)stream_ctx;

    client_ctx_t* ctx =
        (client_ctx_t*)callback_ctx;

    switch (event)
    {
    case picoquic_callback_ready:

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


    case picoquic_callback_close:

        atomic_store(
            &ctx->connected,
            0
        );

        print_close_reason(cnx);

        break;


    case picoquic_callback_application_close:

        printf(
            "[CLIENT] Application closed connection\n"
        );

        atomic_store(
            &ctx->connected,
            0
        );

        break;


    case picoquic_callback_stateless_reset:

        printf(
            "[CLIENT] QUIC stateless reset\n"
        );

        atomic_store(
            &ctx->connected,
            0
        );

        break;


    default:
        break;
    }

    return 0;
}


/* ---------------------------------------------------------
 * Picoquic network-thread callback
 *
 * IMPORTANT:
 *
 * TUN thread only places packets in our queue.
 *
 * Picoquic operations happen here in Picoquic's own thread.
 * --------------------------------------------------------- */

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
        if (!atomic_load(&ctx->connected))
        {
            return 0;
        }

        tunnel_packet_t packet;

        while (dequeue_packet(ctx, &packet))
        {
            /*
             * One TUN IP packet becomes one QUIC DATAGRAM.
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
        }
    }

    return 0;
}


/* ---------------------------------------------------------
 * Start SeamlessNet client
 * --------------------------------------------------------- */

int start_picoquic_client(
    const char* server_ip,
    int port)
{
    int ret = 0;

    client_ctx_t ctx;

    memset(
        &ctx,
        0,
        sizeof(ctx)
    );

    pthread_mutex_init(
        &ctx.mutex,
        NULL
    );

    atomic_init(
        &ctx.connected,
        0
    );


    /* -----------------------------------------------------
     * Create TUN
     * ----------------------------------------------------- */

    int tun_fd =
        tun_create("tun0");

    if (tun_fd < 0)
    {
        return -1;
    }


    if (tun_configure("tun0") != 0)
    {
        close(tun_fd);
        return -1;
    }


    /* -----------------------------------------------------
     * Create Picoquic
     * ----------------------------------------------------- */

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

        return -1;
    }

    /*
    * Prototype: keep an idle tunnel alive for 5 minutes.
    */
    picoquic_set_default_idle_timeout(
        quic,
        SEAMLESSNET_IDLE_TIMEOUT_MS
    );

    /*
     * Development certificate configuration.
     */
    picoquic_set_null_verifier(quic);


    /*
     * Enable QUIC DATAGRAM support.
     */
    picoquic_tp_t tp =
        *picoquic_get_default_tp(quic);

    tp.max_datagram_frame_size = 65535;

    picoquic_set_default_tp(
        quic,
        &tp
    );


    /* -----------------------------------------------------
     * Server address
     * ----------------------------------------------------- */

    struct sockaddr_in server_address;

    memset(
        &server_address,
        0,
        sizeof(server_address)
    );

    server_address.sin_family =
        AF_INET;

    server_address.sin_port =
        htons((uint16_t)port);


    if (inet_pton(
            AF_INET,
            server_ip,
            &server_address.sin_addr) != 1)
    {
        fprintf(
            stderr,
            "[CLIENT] Invalid server IP\n"
        );

        picoquic_free(quic);
        close(tun_fd);

        return -1;
    }


    /* -----------------------------------------------------
     * Create QUIC connection
     * ----------------------------------------------------- */

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

        return -1;
    }


    ctx.cnx = cnx;


    picoquic_set_callback(
        cnx,
        client_callback,
        &ctx
    );


    ret =
        picoquic_start_client_cnx(cnx);


    if (ret != 0)
    {
        fprintf(
            stderr,
            "[CLIENT] Failed to start QUIC connection: %d\n",
            ret
        );

        picoquic_free(quic);
        close(tun_fd);

        return ret;
    }


    printf(
        "[CLIENT] Connecting to %s:%d...\n",
        server_ip,
        port
    );


    /* -----------------------------------------------------
     * Start Picoquic network thread
     * ----------------------------------------------------- */

    picoquic_packet_loop_param_t param = {0};

    param.local_af = AF_INET;


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

        return -1;
    }


    printf(
        "[CLIENT] Waiting for QUIC connection...\n"
    );


    while (!atomic_load(&ctx.connected))
    {
        usleep(10000);
    }


    printf("\n");
    printf("=============================\n");
    printf(" SeamlessNet tunnel active\n");
    printf("=============================\n");
    printf("TUN:       tun0\n");
    printf("TUN IP:    10.10.0.1/24\n");
    printf("Server:    %s:%d\n", server_ip, port);
    printf("Transport: QUIC DATAGRAM\n");
    printf("=============================\n\n");

    printf(
        "[CLIENT] Waiting for TUN packets...\n"
    );


    /* -----------------------------------------------------
     * TUN capture loop
     * ----------------------------------------------------- */

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
            perror("[TUN] read");
            break;
        }


        printf(
            "[TUN] Captured %zd byte IP packet\n",
            length
        );


        if (queue_packet(
                &ctx,
                packet,
                (size_t)length) == 0)
        {
            /*
             * Wake Picoquic.
             *
             * Picoquic's thread will then pull the packet
             * from our queue and queue the QUIC DATAGRAM.
             */
            picoquic_wake_up_network_thread(
                network_thread
            );
        }
    }


    picoquic_delete_network_thread(
        network_thread
    );

    picoquic_free(quic);

    close(tun_fd);

    pthread_mutex_destroy(
        &ctx.mutex
    );

    return 0;
}