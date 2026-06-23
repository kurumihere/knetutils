#ifndef KNETUTILS_NET_H
#define KNETUTILS_NET_H

#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>

typedef struct net_socket net_socket_t;

bool net_get_iface_mac(const char *iface, uint8_t *mac);
bool net_get_iface_ip(const char *iface, uint32_t *ip);
int net_get_iface_index(const char *iface);

net_socket_t *net_open_raw_socket(const char *iface, uint16_t protocol);
net_socket_t *net_open_icmp_socket(void);
void net_close_raw_socket(net_socket_t *sock);

ssize_t net_send_packet(net_socket_t *sock, const void *buf, size_t len,
                        const uint8_t *dst_mac);
ssize_t net_send_icmp_packet(net_socket_t *sock, const void *buf, size_t len,
                             uint32_t dst_ip);

ssize_t net_recv_packet(net_socket_t *sock, void *buf, size_t len);
ssize_t net_recv_icmp_packet(net_socket_t *sock, void *buf, size_t len,
                             uint32_t *src_ip);

int net_get_fd(net_socket_t *sock);

bool net_resolve_ipv4(const char *hostname, uint32_t *ip);
bool net_parse_mac(const char *mac_str, uint8_t *mac);
bool net_get_default_gateway(const char *iface, uint32_t *gateway_ip);

#endif
