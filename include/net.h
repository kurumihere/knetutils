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

/*
 *		N E T _ S O C K E T
 *
 * Opaque structure representing an abstracted cross-platform network socket.
 */
typedef struct net_socket net_socket_t;

/*
 *		N E T _ G E T _ I F A C E _ M A C
 *
 * Retrieve the MAC address of the specified network interface.
 */
bool net_get_iface_mac(const char *iface, u_char *mac);

/*
 *		N E T _ G E T _ I F A C E _ I P
 *
 * Retrieve the IPv4 address of the specified network interface.
 */
bool net_get_iface_ip(const char *iface, u_int *ip);

/*
 *		N E T _ G E T _ I F A C E _ I N D E X
 *
 * Retrieve the interface index (ifindex) for a given interface name.
 */
int net_get_iface_index(const char *iface);

/*
 *		N E T _ O P E N _ R A W _ S O C K E T
 *
 * Open a raw socket on a specific interface for the given protocol.
 */
net_socket_t *net_open_raw_socket(const char *iface, u_short protocol);

/*
 *		N E T _ C L O S E _ R A W _ S O C K E T
 *
 * Close and release resources associated with an open raw socket.
 */
void net_close_raw_socket(net_socket_t *sock);

/*
 *		N E T _ S E T _ P R O M I S C U O U S
 *
 * Enable promiscuous mode on the network interface bound to the socket.
 */
bool net_set_promiscuous(net_socket_t *sock);

/*
 *		N E T _ S E N D _ P A C K E T
 *
 * Transmit a raw Ethernet packet through the specified socket to a destination
 * MAC.
 */
ssize_t net_send_packet(net_socket_t *sock, const void *buf, size_t len,
                        const u_char *dst_mac);

/*
 *		N E T _ R E C V _ P A C K E T
 *
 * Receive a raw Ethernet packet from the network socket into a buffer.
 */
ssize_t net_recv_packet(net_socket_t *sock, void *buf, size_t len);

/*
 *		N E T _ G E T _ F D
 *
 * Get the underlying operating system file descriptor for the socket.
 */
int net_get_fd(net_socket_t *sock);

/*
 *		N E T _ R E S O L V E _ H O S T
 *
 * Resolve a hostname into a network address for the specified address family.
 */
bool net_resolve_host(const char *hostname, int family,
                      struct sockaddr_storage *ss, socklen_t *ss_len);

/*
 *		N E T _ R E S O L V E _ I P V 4
 *
 * Resolve a hostname specifically into an IPv4 address.
 */
bool net_resolve_ipv4(const char *hostname, u_int *ip);

/*
 *		N E T _ P A R S E _ M A C
 *
 * Parse a standard string representation of a MAC address into a byte array.
 */
bool net_parse_mac(const char *mac_str, u_char *mac);

/*
 *		N E T _ G E T _ D E F A U L T _ G A T E W A Y
 *
 * Retrieve the default gateway IP address for a given network interface.
 */
bool net_get_default_gateway(const char *iface, u_int *gateway_ip);

/*
 *		N E T _ O P E N _ I C M P _ S O C K E T
 *
 * Open a socket for sending and receiving ICMP messages.
 */
net_socket_t *net_open_icmp_socket(int family);

/*
 *		N E T _ I S _ D G R A M
 *
 * Check if the network socket is an unprivileged datagram socket.
 */
bool net_is_dgram(net_socket_t *sock);

/*
 *		N E T _ S E N D _ I C M P _ P A C K E T
 *
 * Send an ICMP packet to a destination address using the specified socket.
 */
ssize_t net_send_icmp_packet(net_socket_t *sock, const void *buf, size_t len,
                             const struct sockaddr *dest, socklen_t dest_len);

/*
 *		N E T _ R E C V _ I C M P _ P A C K E T
 *
 * Receive an ICMP packet from the socket and record the source address.
 */
ssize_t net_recv_icmp_packet(net_socket_t *sock, void *buf, size_t len,
                             struct sockaddr_storage *src, socklen_t *src_len);

/*
 *		N E T _ S E N D _ I P _ R A W
 *
 * Send a raw IP packet via the socket to a specific destination.
 */
ssize_t net_send_ip_raw(net_socket_t *sock, const void *buf, size_t len,
                        const struct sockaddr *dest, socklen_t dest_len);

/*
 *		N E T _ R E C V _ I P _ R A W
 *
 * Receive a raw IP packet from the socket along with its source address.
 */
ssize_t net_recv_ip_raw(net_socket_t *sock, void *buf, size_t len,
                        struct sockaddr_storage *src, socklen_t *src_len);

/*
 *		N E T _ O P E N _ I P _ R A W _ S O C K E T
 *
 * Open a raw socket operating at the IP layer for a specific protocol.
 */
net_socket_t *net_open_ip_raw_socket(int family, int protocol);

/*
 *		N E T _ G E T _ S O U R C E _ I P _ F O R
 *
 * Determine the best local source IP address to use to reach a destination.
 */
bool
net_get_source_ip_for(const struct sockaddr_storage *dst, socklen_t dst_len,
                      struct sockaddr_storage *src, socklen_t *src_len);

/*
 *		N E T _ C H E C K S U M
 *
 * Calculate the Internet checksum for a given block of data.
 */
u_short net_checksum(const void *b, int len);

#endif
