#include <stdio.h>

int start_picoquic_server(
    int port,
    const char* cert_file,
    const char* key_file);

int main(void)
{
    printf("=============================\n");
    printf(" SeamlessNet QUIC Server\n");
    printf("=============================\n");

    return start_picoquic_server(
        4433,
        "/usr/local/SeamlessNet/certs/cert.pem",
        "/usr/local/SeamlessNet/certs/key.pem"
    );
}