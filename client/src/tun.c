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
        perror("[TUN] Failed to open /dev/net/tun");
        return -1;
    }

    memset(&ifr, 0, sizeof(ifr));

    /*
     * IFF_TUN:
     * Give us layer-3 IP packets.
     *
     * IFF_NO_PI:
     * Do not prepend Linux's extra 4-byte packet-info header.
     */
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;

    strncpy(
        ifr.ifr_name,
        device_name,
        IFNAMSIZ - 1
    );

    if (ioctl(fd, TUNSETIFF, &ifr) < 0)
    {
        perror("[TUN] TUNSETIFF failed");
        close(fd);
        return -1;
    }

    printf(
        "[TUN] Created interface: %s\n",
        ifr.ifr_name
    );

    return fd;
}

int tun_configure(const char* device_name)
{
    char command[256];

    /*
     * Give SeamlessNet's virtual client interface an address.
     */
    snprintf(
        command,
        sizeof(command),
        "ip addr replace 10.10.0.1/24 dev %s",
        device_name
    );

    if (system(command) != 0)
    {
        fprintf(
            stderr,
            "[TUN] Failed to assign IP address\n"
        );

        return -1;
    }

    /*
     * Keep packets comfortably below QUIC datagram limits
     * during this prototype stage.
     */
    snprintf(
        command,
        sizeof(command),
        "ip link set dev %s mtu %d",
        device_name,
        TUN_MTU
    );

    if (system(command) != 0)
    {
        fprintf(
            stderr,
            "[TUN] Failed to set MTU\n"
        );

        return -1;
    }

    /*
     * Bring the interface online.
     */
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
            "[TUN] Failed to bring interface up\n"
        );

        return -1;
    }

    printf(
        "[TUN] %s configured as 10.10.0.1/24, MTU=%d\n",
        device_name,
        TUN_MTU
    );

    return 0;
}