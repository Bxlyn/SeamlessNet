#include "tun.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <fcntl.h>
#include <unistd.h>

#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <linux/if.h>
#include <linux/if_tun.h>


int tun_create(const char* device_name)
{
    struct ifreq ifr;
    int fd;

    fd = open("/dev/net/tun", O_RDWR);

    if (fd < 0)
    {
        perror("[SERVER TUN] Failed to open /dev/net/tun");
        return -1;
    }

    memset(&ifr, 0, sizeof(ifr));

    ifr.ifr_flags =
        IFF_TUN | IFF_NO_PI;

    strncpy(
        ifr.ifr_name,
        device_name,
        IFNAMSIZ - 1
    );

    if (ioctl(
            fd,
            TUNSETIFF,
            &ifr) < 0)
    {
        perror("[SERVER TUN] TUNSETIFF failed");

        close(fd);

        return -1;
    }

    printf(
        "[SERVER TUN] Created interface: %s\n",
        ifr.ifr_name
    );

    return fd;
}


int tun_configure(const char* device_name)
{
    char command[256];

    /*
     * Server side of our virtual tunnel network:
     *
     * Client: 10.10.0.1
     * Server: 10.10.0.2
     */

    snprintf(
        command,
        sizeof(command),
        "ip addr replace 10.10.0.2/24 dev %s",
        device_name
    );

    if (system(command) != 0)
    {
        fprintf(
            stderr,
            "[SERVER TUN] Failed to assign address\n"
        );

        return -1;
    }


    snprintf(
        command,
        sizeof(command),
        "ip link set dev %s mtu %d",
        device_name,
        SERVER_TUN_MTU
    );

    if (system(command) != 0)
    {
        fprintf(
            stderr,
            "[SERVER TUN] Failed to set MTU\n"
        );

        return -1;
    }


    snprintf(
        command,
        sizeof(command),
        "ip link set dev %s up",
        device_name
    );

    if (system(command) != 0)
    {
        fprintf(
            stderr,
            "[SERVER TUN] Failed to bring interface up\n"
        );

        return -1;
    }


    printf(
        "[SERVER TUN] %s configured as 10.10.0.2/24, MTU=%d\n",
        device_name,
        SERVER_TUN_MTU
    );


    return 0;
}