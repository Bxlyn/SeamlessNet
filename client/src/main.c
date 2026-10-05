#include <stdio.h>

int start_picoquic_client(const char* server_name, int port);

int main(void)
{
    printf("Starting SeamlessNet client...\n");

    return start_picoquic_client(
        "172.20.0.10",
        4433
    );
}