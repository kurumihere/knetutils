#ifndef KNETUTILS_NET_H
#define KNETUTILS_NET_H

#include <stdbool.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/types.h>

typedef struct net_socket net_socket_t;

bool net_get_iface_mac(const char *iface, uint8_t *mac);
bool net_get_iface_ip(const char *iface, uint32_t *ip);
int net_get_iface_index(const char *iface);

net_socket_t *net_open_raw_socket(const char *iface, uint16_t protocol);
void net_close_raw_socket(net_socket_t *sock);

ssize_t net_send_packet(net_socket_t *sock, const void *buf, size_t len,
                        const uint8_t *dst_mac);

ssize_t net_recv_packet(net_socket_t *sock, void *buf, size_t len);

int net_get_fd(net_socket_t *sock);

bool net_resolve_host(const char *hostname, int family,
                      struct sockaddr_storage *ss, socklen_t *ss_len);
bool net_resolve_ipv4(const char *hostname, uint32_t *ip);
bool net_parse_mac(const char *mac_str, uint8_t *mac);
bool net_get_default_gateway(const char *iface, uint32_t *gateway_ip);

net_socket_t *net_open_icmp_socket(int family);
ssize_t net_send_icmp_packet(net_socket_t *sock, const void *buf, size_t len,
                             const struct sockaddr *dest, socklen_t dest_len);
ssize_t net_recv_icmp_packet(net_socket_t *sock, void *buf, size_t len,
                             struct sockaddr_storage *src, socklen_t *src_len);

#endif
