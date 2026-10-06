#include "picoquic.h"
#include "picoquic_packet_loop.h"

#include <stdio.h>
#include <stdint.h>

static int server_callback(
    picoquic_cnx_t* cnx,
    uint64_t stream_id,
    uint8_t* bytes,
    size_t length,
    picoquic_call_back_event_t event,
    void* callback_ctx,
    void* stream_ctx)
{
    (void)cnx;
    (void)callback_ctx;
    (void)stream_ctx;

    switch (event)
    {
    case picoquic_callback_ready:
        printf("[SERVER] QUIC connection established!\n");
        fflush(stdout);
        break;

    case picoquic_callback_stream_data:
        printf("[SERVER] Received on stream %llu: ",
               (unsigned long long)stream_id);

        fwrite(bytes, 1, length, stdout);
        printf("\n");
        fflush(stdout);
        break;

    case picoquic_callback_stream_fin:
        if (length > 0)
        {
            printf("[SERVER] Received on stream %llu: ",
                (unsigned long long)stream_id);

            fwrite(bytes, 1, length, stdout);
            printf("\n");
        }

        printf("[SERVER] Stream %llu finished\n",
            (unsigned long long)stream_id);

        fflush(stdout);
        break;

    case picoquic_callback_close:
        printf("[SERVER] Connection closed\n");
        fflush(stdout);
        break;

    case picoquic_callback_application_close:
        printf("[SERVER] Application closed connection\n");
        fflush(stdout);
        break;

    case picoquic_callback_stateless_reset:
        printf("[SERVER] Stateless reset\n");
        fflush(stdout);
        break;

    default:
        break;
    }

    return 0;
}


int start_picoquic_server(
    int port,
    const char* cert_file,
    const char* key_file)
{
    uint64_t current_time = picoquic_current_time();

    printf("[SERVER] Creating QUIC context...\n");

    picoquic_quic_t* quic = picoquic_create(
        8,
        cert_file,
        key_file,
        NULL,
        "seamlessnet",
        server_callback,
        NULL,
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
        fprintf(stderr, "[SERVER] Failed to create QUIC context\n");
        return -1;
    }

    printf("[SERVER] Listening on UDP port %d...\n", port);
    fflush(stdout);

    int ret = picoquic_packet_loop(
        quic,
        port,
        AF_INET,
        0,
        0,
        0,
        NULL,
        NULL
    );

    printf("[SERVER] Packet loop stopped: %d\n", ret);

    picoquic_free(quic);

    return ret;
}