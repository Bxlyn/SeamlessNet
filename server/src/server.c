#include "picoquic.h"
#include "picoquic_packet_loop.h"

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <arpa/inet.h>

#define SEAMLESSNET_IDLE_TIMEOUT_MS 300000

static void print_ipv4_packet(
    const uint8_t* packet,
    size_t length)
{
    if (length < 20)
    {
        printf(
            "[SERVER] Packet too short for IPv4\n"
        );

        return;
    }


    uint8_t version =
        packet[0] >> 4;


    if (version != 4)
    {
        printf(
            "[SERVER] Non-IPv4 packet, version=%u\n",
            version
        );

        return;
    }


    char source[INET_ADDRSTRLEN];
    char destination[INET_ADDRSTRLEN];


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


    printf("\n");
    printf("---------------------------------\n");
    printf("[SERVER] Recovered IP packet\n");
    printf("Length:      %zu bytes\n", length);
    printf("Source:      %s\n", source);
    printf("Destination: %s\n", destination);
    printf("Protocol:    %u", protocol);


    if (protocol == 1)
    {
        printf(" (ICMP)");
    }
    else if (protocol == 6)
    {
        printf(" (TCP)");
    }
    else if (protocol == 17)
    {
        printf(" (UDP)");
    }


    printf("\n");
    printf("---------------------------------\n");

    fflush(stdout);
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
    (void)stream_id;
    (void)callback_ctx;
    (void)stream_ctx;


    switch (event)
    {
    case picoquic_callback_ready:

        printf(
            "[SERVER] QUIC connection established!\n"
        );

        fflush(stdout);

        break;


    case picoquic_callback_datagram:

        printf(
            "[SERVER] QUIC DATAGRAM received: %zu bytes\n",
            length
        );

        print_ipv4_packet(
            bytes,
            length
        );

        break;


    case picoquic_callback_close:

        print_close_reason(cnx);

        break;


    case picoquic_callback_application_close:

        printf(
            "[SERVER] Application closed connection\n"
        );

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
        fprintf(
            stderr,
            "[SERVER] Failed to create QUIC context\n"
        );

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
     * Tell the client that this server supports
     * QUIC DATAGRAM.
     */
    picoquic_tp_t tp =
        *picoquic_get_default_tp(quic);

    tp.max_datagram_frame_size = 65535;

    picoquic_set_default_tp(
        quic,
        &tp
    );


    printf(
        "[SERVER] Listening on UDP port %d...\n",
        port
    );


    int ret =
        picoquic_packet_loop(
            quic,
            port,
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