#include "picoquic.h"

#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>

static int client_callback(
    picoquic_cnx_t* cnx,
    uint64_t stream_id,
    uint8_t* bytes,
    size_t length,
    picoquic_call_back_event_t event,
    void* callback_ctx,
    void* stream_ctx)
{
    (void)cnx;
    (void)stream_id;
    (void)callback_ctx;
    (void)stream_ctx;

    switch (event) {

    case picoquic_callback_ready:
        printf("[CLIENT] QUIC connection established\n");
        fflush(stdout);
        break;

    case picoquic_callback_stream_data:
        printf("[CLIENT] Received %zu bytes: ", length);

        fwrite(bytes, 1, length, stdout);
        printf("\n");

        fflush(stdout);
        break;

    case picoquic_callback_close:
        printf("[CLIENT] Connection closed\n");
        fflush(stdout);
        break;

    default:
        break;
    }

    return 0;
}

int start_picoquic_client(const char* server_name, int port)
{
    uint64_t current_time = picoquic_current_time();

    picoquic_quic_t* quic = picoquic_create(
        1,
        NULL,
        NULL,
        NULL,
        "seamlessnet",
        client_callback,
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

    if (quic == NULL) {
        fprintf(stderr, "[CLIENT] Failed to create QUIC context\n");
        return -1;
    }

    struct sockaddr_in server_address;
    memset(&server_address, 0, sizeof(server_address));

    server_address.sin_family = AF_INET;
    server_address.sin_port = htons((uint16_t)port);

    if (inet_pton(AF_INET, server_name,
                  &server_address.sin_addr) != 1) {
        fprintf(stderr, "[CLIENT] Invalid server address: %s\n",
                server_name);
        picoquic_free(quic);
        return -1;
    }

    picoquic_cnx_t* cnx = picoquic_create_cnx(
        quic,
        picoquic_null_connection_id,
        picoquic_null_connection_id,
        (struct sockaddr*)&server_address,
        current_time,
        0,
        server_name,
        "seamlessnet",
        1
    );

    if (cnx == NULL) {
        fprintf(stderr, "[CLIENT] Failed to create connection\n");
        picoquic_free(quic);
        return -1;
    }

    picoquic_set_callback(cnx, client_callback, NULL);

    int ret = picoquic_start_client_cnx(cnx);

    if (ret != 0) {
        fprintf(stderr,
                "[CLIENT] Failed to start connection: %d\n",
                ret);

        picoquic_free(quic);
        return ret;
    }

    printf("[CLIENT] Client started. Connecting to %s:%d...\n",
           server_name, port);
    fflush(stdout);

    /*
     * For the first test, we'll keep the client alive.
     */
    while (1) {
        sleep(1);
    }

    picoquic_free(quic);

    return 0;
}