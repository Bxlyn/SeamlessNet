#include "picoquic.h"
#include "picoquic_packet_loop.h"

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <arpa/inet.h>


#define MAX_TUN_PACKET 2000

/* 5 minutes */
#define SEAMLESSNET_IDLE_TIMEOUT_MS 300000


/* =========================================================
 * Internet checksum
 *
 * Used for:
 *
 * - IPv4 header checksum
 * - ICMP checksum
 * ========================================================= */

static uint16_t internet_checksum(
    const uint8_t* data,
    size_t length)
{
    uint32_t sum = 0;


    while (length >= 2)
    {
        uint16_t word =
            ((uint16_t)data[0] << 8) |
            ((uint16_t)data[1]);


        sum += word;


        data += 2;

        length -= 2;
    }


    /*
     * Handle odd byte.
     */
    if (length == 1)
    {
        sum +=
            ((uint16_t)data[0] << 8);
    }


    /*
     * Fold carry bits.
     */
    while (sum >> 16)
    {
        sum =
            (sum & 0xffff) +
            (sum >> 16);
    }


    return
        (uint16_t)(~sum);
}


/* =========================================================
 * Store 16-bit checksum in network byte order
 * ========================================================= */

static void store_checksum(
    uint8_t* field,
    uint16_t checksum)
{
    field[0] =
        (uint8_t)(
            checksum >> 8
        );


    field[1] =
        (uint8_t)(
            checksum & 0xff
        );
}


/* =========================================================
 * Print IPv4 packet information
 * ========================================================= */

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


/* =========================================================
 * Build ICMP Echo Reply
 *
 * Input:
 *
 *     10.10.0.1 -> 10.10.0.2
 *     ICMP Echo Request
 *
 * Output:
 *
 *     10.10.0.2 -> 10.10.0.1
 *     ICMP Echo Reply
 *
 * Return:
 *
 *      0 = reply generated
 *      1 = valid packet but not Echo Request
 *     -1 = invalid packet
 * ========================================================= */

static int build_icmp_echo_reply(
    const uint8_t* packet,
    size_t packet_length,
    uint8_t* reply,
    size_t* reply_length)
{
    /* -----------------------------------------------------
     * Validate minimum IPv4 header
     * ----------------------------------------------------- */

    if (packet_length < 20)
    {
        return -1;
    }


    uint8_t version =
        packet[0] >> 4;


    if (version != 4)
    {
        return -1;
    }


    /* -----------------------------------------------------
     * IPv4 header length
     *
     * IHL is measured in 32-bit words.
     * ----------------------------------------------------- */

    size_t ip_header_length =
        (packet[0] & 0x0f) * 4;


    if (ip_header_length < 20 ||
        ip_header_length > packet_length)
    {
        return -1;
    }


    /* -----------------------------------------------------
     * IPv4 total packet length
     * ----------------------------------------------------- */

    size_t total_length =
        ((size_t)packet[2] << 8) |
        packet[3];


    if (total_length < ip_header_length ||
        total_length > packet_length ||
        total_length > MAX_TUN_PACKET)
    {
        return -1;
    }


    /* -----------------------------------------------------
     * IPv4 protocol 1 = ICMP
     * ----------------------------------------------------- */

    if (packet[9] != 1)
    {
        return 1;
    }


    /*
     * ICMP header requires at least 8 bytes.
     */
    if (total_length <
        ip_header_length + 8)
    {
        return -1;
    }


    size_t icmp_offset =
        ip_header_length;


    /* -----------------------------------------------------
     * ICMP type:
     *
     * 8 = Echo Request
     * 0 = Echo Reply
     * ----------------------------------------------------- */

    if (packet[icmp_offset] != 8)
    {
        return 1;
    }


    /* -----------------------------------------------------
     * Copy original packet
     * ----------------------------------------------------- */

    memcpy(
        reply,
        packet,
        total_length
    );


    /* -----------------------------------------------------
     * Swap source/destination IPv4 addresses
     * ----------------------------------------------------- */

    uint8_t temp_address[4];


    memcpy(
        temp_address,
        reply + 12,
        4
    );


    memcpy(
        reply + 12,
        reply + 16,
        4
    );


    memcpy(
        reply + 16,
        temp_address,
        4
    );


    /* -----------------------------------------------------
     * Set TTL
     * ----------------------------------------------------- */

    reply[8] = 64;


    /* -----------------------------------------------------
     * Echo Request -> Echo Reply
     * ----------------------------------------------------- */

    reply[icmp_offset] = 0;


    /* =====================================================
     * Recalculate ICMP checksum
     * ===================================================== */

    reply[icmp_offset + 2] = 0;

    reply[icmp_offset + 3] = 0;


    uint16_t icmp_checksum =
        internet_checksum(
            reply + icmp_offset,
            total_length - icmp_offset
        );


    store_checksum(
        reply + icmp_offset + 2,
        icmp_checksum
    );


    /* =====================================================
     * Recalculate IPv4 header checksum
     * ===================================================== */

    reply[10] = 0;

    reply[11] = 0;


    uint16_t ip_checksum =
        internet_checksum(
            reply,
            ip_header_length
        );


    store_checksum(
        reply + 10,
        ip_checksum
    );


    *reply_length =
        total_length;


    return 0;
}


/* =========================================================
 * Picoquic server callback
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
    (void)callback_ctx;
    (void)stream_ctx;


    switch (event)
    {
        /* -------------------------------------------------
         * Connection established
         * ------------------------------------------------- */

        case picoquic_callback_ready:
        {
            printf(
                "[SERVER] QUIC connection established!\n"
            );


            fflush(stdout);

            break;
        }


        /* -------------------------------------------------
         * Receive IP packet from client
         * ------------------------------------------------- */

        case picoquic_callback_datagram:
        {
            printf(
                "[SERVER] QUIC DATAGRAM received: %zu bytes\n",
                length
            );


            /*
             * Display the recovered original IP packet.
             */
            print_ipv4_packet(
                bytes,
                length
            );


            /* ---------------------------------------------
             * Try to generate an ICMP Echo Reply.
             * --------------------------------------------- */

            uint8_t reply[
                MAX_TUN_PACKET
            ];


            size_t reply_length =
                0;


            int result =
                build_icmp_echo_reply(
                    bytes,
                    length,
                    reply,
                    &reply_length
                );


            if (result == 0)
            {
                printf(
                    "[SERVER] ICMP Echo Request detected\n"
                );


                printf(
                    "[SERVER] Building Echo Reply: %zu bytes\n",
                    reply_length
                );


                /*
                 * Send reconstructed IP packet back
                 * through the same QUIC connection.
                 */
                int ret =
                    picoquic_queue_datagram_frame(
                        cnx,
                        reply_length,
                        reply
                    );


                if (ret != 0)
                {
                    fprintf(
                        stderr,
                        "[SERVER] Failed to queue return datagram: %d\n",
                        ret
                    );
                }
                else
                {
                    printf(
                        "[SERVER] QUIC -> CLIENT: %zu bytes\n",
                        reply_length
                    );
                }
            }
            else if (result == 1)
            {
                printf(
                    "[SERVER] Packet is not an ICMP Echo Request - ignoring\n"
                );
            }
            else
            {
                printf(
                    "[SERVER] Invalid IP packet\n"
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


            fflush(stdout);

            break;
        }


        /* -------------------------------------------------
         * Application close
         * ------------------------------------------------- */

        case picoquic_callback_application_close:
        {
            printf(
                "[SERVER] QUIC application close received\n"
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
                "[SERVER] QUIC stateless reset received\n"
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
 * Start SeamlessNet server
 * ========================================================= */

int start_picoquic_server(
    int port,
    const char* cert_file,
    const char* key_file)
{
    uint64_t current_time =
        picoquic_current_time();


    printf(
        "[SERVER] Creating QUIC context...\n"
    );


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


    /* =====================================================
     * Stage 1 prototype idle timeout
     *
     * Keep inactive tunnels alive for five minutes.
     * ===================================================== */

    picoquic_set_default_idle_timeout(
        quic,
        SEAMLESSNET_IDLE_TIMEOUT_MS
    );


    /* =====================================================
     * Enable QUIC DATAGRAM support
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
     * Start server
     * ===================================================== */

    printf(
        "[SERVER] Listening on UDP port %d...\n",
        port
    );


    printf(
        "[SERVER] Idle timeout: %d seconds\n",
        SEAMLESSNET_IDLE_TIMEOUT_MS / 1000
    );


    fflush(stdout);


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


    printf(
        "[SERVER] Packet loop stopped: %d\n",
        ret
    );


    picoquic_free(
        quic
    );


    return ret;
}