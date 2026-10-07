#ifndef SEAMLESSNET_TUN_H
#define SEAMLESSNET_TUN_H

#define TUN_MTU 1000

int tun_create(const char* device_name);
int tun_configure(const char* device_name);

#endif