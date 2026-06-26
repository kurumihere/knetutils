/***************************************************************************
 * net.h -- Header definitions for network abstractions                    *
 *                                                                         *
 ***********************IMPORTANT KNETUTILS LICENSE TERMS******************* *
 *                                                                         *
 * knetutils is (C) 2026 kurumihere                                        *
 *                                                                         *
 * Redistribution and use in source and binary forms, with or without      *
 * modification, are permitted provided that the following conditions are  *
 * met:                                                                    *
 *                                                                         *
 * 1. Redistributions of source code must retain the above copyright       *
 *    notice, this list of conditions and the following disclaimer.        *
 *                                                                         *
 * 2. Redistributions in binary form must reproduce the above copyright    *
 *    notice, this list of conditions and the following disclaimer in the  *
 *    documentation and/or other materials provided with the distribution. *
 *                                                                         *
 * 3. Neither the name of the copyright holder nor the names of its        *
 *    contributors may be used to endorse or promote products derived from *
 *    this software without specific prior written permission.             *
 *                                                                         *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS     *
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT       *
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A *
 * PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT      *
 * HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,  *
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT        *
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,   *
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY   *
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT     *
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE   *
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.    *
 *                                                                         *
 ***************************************************************************/

#ifndef KNETUTILS_NET_H
#define KNETUTILS_NET_H

#include <stdbool.h>
#include <sys/socket.h>
#include <sys/types.h>

typedef struct net_socket net_socket_t;

bool net_get_iface_mac(const char *iface, u_char *mac);
bool net_get_iface_ip(const char *iface, u_int *ip);
int net_get_iface_index(const char *iface);

net_socket_t *net_open_raw_socket(const char *iface, u_short protocol);
void net_close_raw_socket(net_socket_t *sock);
bool net_set_promiscuous(net_socket_t *sock);

ssize_t net_send_packet(net_socket_t *sock, const void *buf, size_t len,
                        const u_char *dst_mac);

ssize_t net_recv_packet(net_socket_t *sock, void *buf, size_t len);

int net_get_fd(net_socket_t *sock);

bool net_resolve_host(const char *hostname, int family,
                      struct sockaddr_storage *ss, socklen_t *ss_len);
bool net_resolve_ipv4(const char *hostname, u_int *ip);
bool net_parse_mac(const char *mac_str, u_char *mac);
bool net_get_default_gateway(const char *iface, u_int *gateway_ip);

net_socket_t *net_open_icmp_socket(int family);
bool net_is_dgram(net_socket_t *sock);
ssize_t net_send_icmp_packet(net_socket_t *sock, const void *buf, size_t len,
                             const struct sockaddr *dest, socklen_t dest_len);
ssize_t net_recv_icmp_packet(net_socket_t *sock, void *buf, size_t len,
                             struct sockaddr_storage *src, socklen_t *src_len);

ssize_t net_send_ip_raw(net_socket_t *sock, const void *buf, size_t len,
                        const struct sockaddr *dest, socklen_t dest_len);
ssize_t net_recv_ip_raw(net_socket_t *sock, void *buf, size_t len,
                        struct sockaddr_storage *src, socklen_t *src_len);

net_socket_t *net_open_ip_raw_socket(int family, int protocol);
bool
net_get_source_ip_for(const struct sockaddr_storage *dst, socklen_t dst_len,
                      struct sockaddr_storage *src, socklen_t *src_len);
u_short net_checksum(const void *b, int len);

#endif
