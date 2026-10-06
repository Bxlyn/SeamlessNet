#include <stdio.h>

int start_picoquic_client(
    const char* server_ip,
    int port);

int main(void)
{
    printf("=============================\n");
    printf(" SeamlessNet QUIC Client\n");
    printf("=============================\n");

    return start_picoquic_client(
        "172.20.0.10",
        4433
    );
}