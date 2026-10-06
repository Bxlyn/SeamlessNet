#include "picoquic.h"
#include "picoquic_packet_loop.h"

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <arpa/inet.h>


typedef struct
{
    int message_sent;
} client_ctx_t;


static int client_callback(
    picoquic_cnx_t* cnx,
    uint64_t stream_id,
    uint8_t* bytes,
    size_t length,
    picoquic_call_back_event_t event,
    void* callback_ctx,
    void* stream_ctx)
{
    (void)stream_ctx;

    client_ctx_t* ctx = (client_ctx_t*)callback_ctx;

    switch (event)
    {
    case picoquic_callback_ready:
        printf("[CLIENT] QUIC connection established!\n");
        fflush(stdout);

        /*
         * Tell Picoquic that stream 0 has data waiting
         * to be sent.
         */
        if (!ctx->message_sent)
        {
            printf("[CLIENT] Activating stream 0...\n");

            picoquic_mark_active_stream(
                cnx,
                0,
                1,
                NULL
            );
        }

        break;


    case picoquic_callback_prepare_to_send:
    {
        if (!ctx->message_sent)
        {
            const char* message = "Hello from SeamlessNet!";
            size_t message_length = strlen(message);

            uint8_t* buffer =
                picoquic_provide_stream_data_buffer(
                    bytes,
                    message_length,
                    1,
                    0
                );

            if (buffer != NULL)
            {
                memcpy(buffer, message, message_length);

                ctx->message_sent = 1;

                printf(
                    "[CLIENT] Sent: %s\n",
                    message
                );

                fflush(stdout);
            }
        }

        break;
    }


    case picoquic_callback_stream_data:

        printf("[CLIENT] Received: ");

        fwrite(bytes, 1, length, stdout);

        printf("\n");

        fflush(stdout);

        break;


    case picoquic_callback_close:

        printf("[CLIENT] Connection closed\n");

        fflush(stdout);

        break;


    case picoquic_callback_application_close:

        printf("[CLIENT] Application closed connection\n");

        fflush(stdout);

        break;


    case picoquic_callback_stateless_reset:

        printf("[CLIENT] Stateless reset\n");

        fflush(stdout);

        break;


    default:
        break;
    }

    return 0;
}


int start_picoquic_client(
    const char* server_ip,
    int port)
{
    uint64_t current_time =
        picoquic_current_time();

    client_ctx_t client_ctx = {0};

    printf("[CLIENT] Creating QUIC context...\n");

    picoquic_quic_t* quic =
        picoquic_create(
            1,
            NULL,
            NULL,
            NULL,
            "seamlessnet",
            client_callback,
            &client_ctx,
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

        return -1;
    }

    /*
     * Development only.
     *
     * Accept our self-signed server certificate.
     */
    picoquic_set_null_verifier(quic);


    struct sockaddr_in server_address;

    memset(
        &server_address,
        0,
        sizeof(server_address)
    );

    server_address.sin_family = AF_INET;

    server_address.sin_port =
        htons((uint16_t)port);


    if (inet_pton(
            AF_INET,
            server_ip,
            &server_address.sin_addr) != 1)
    {
        fprintf(
            stderr,
            "[CLIENT] Invalid IP: %s\n",
            server_ip
        );

        picoquic_free(quic);

        return -1;
    }


    printf(
        "[CLIENT] Connecting to %s:%d...\n",
        server_ip,
        port
    );


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
            "[CLIENT] Failed to create connection\n"
        );

        picoquic_free(quic);

        return -1;
    }


    picoquic_set_callback(
        cnx,
        client_callback,
        &client_ctx
    );


    int ret =
        picoquic_start_client_cnx(cnx);


    if (ret != 0)
    {
        fprintf(
            stderr,
            "[CLIENT] Could not start connection: %d\n",
            ret
        );

        picoquic_free(quic);

        return ret;
    }


    /*
     * Start UDP/QUIC packet processing.
     */
    ret = picoquic_packet_loop(
        quic,
        0,
        AF_INET,
        0,
        0,
        0,
        NULL,
        NULL
    );


    picoquic_free(quic);

    return ret;
}