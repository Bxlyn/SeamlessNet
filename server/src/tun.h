#ifndef SEAMLESSNET_SERVER_TUN_H
#define SEAMLESSNET_SERVER_TUN_H

#define SERVER_TUN_MTU 1000

int tun_create(const char* device_name);
int tun_configure(const char* device_name);

#endif