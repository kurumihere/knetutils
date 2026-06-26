/***************************************************************************
 * net.c -- Cross-platform network abstractions and raw sockets            *
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

#include "net.h"
#include "utils.h"
#include <arpa/inet.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#define MAX_BPF_DEVS 256
#define MAX_LINE_LEN 256
#define MAX_IFACE_LEN 128
#define BPF_PATH_MAX 32
#define MAC_OCTETS 6
#define DNS_PORT 53
#define CHECKSUM_SHIFT 16
#define CHECKSUM_MASK 0xFFFF

#ifdef __linux__
#include <linux/if_packet.h>
#include <net/ethernet.h>

struct net_socket {
        int fd;
        int ifindex;
        bool is_dgram;
};

#else

#include <net/bpf.h>
#include <net/ethernet.h>
#include <net/if_dl.h>
#include <net/route.h>
#include <sys/param.h>
#include <sys/sysctl.h>

struct net_socket {
        int fd;
        bool is_dgram;
        u_char *bpf_buf;
        size_t bpf_buf_len;
        size_t bpf_pos;
        size_t bpf_filled;
};

#endif

#ifndef ETH_ALEN
#ifdef ETHER_ADDR_LEN
#define ETH_ALEN ETHER_ADDR_LEN
#else
#define ETH_ALEN 6
#endif
#endif

/*
 *		N E T _ G E T _ I F A C E _ M A C
 *
 * Fetch the MAC address for a given network interface.
 * On Linux, this uses a dummy DGRAM socket to issue the SIOCGIFHWADDR ioctl.
 * On BSD/macOS, it traverses the getifaddrs() linked list looking for an
 * AF_LINK entry.
 */
bool
net_get_iface_mac(const char *iface, u_char *mac)
{
#ifdef __linux__
        int sock;
        struct ifreq ifr;
        bool ret = false;

        sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (sock < 0) {
                return false;
        }

        memset(&ifr, 0, sizeof(ifr));
        strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);

        if (ioctl(sock, SIOCGIFHWADDR, &ifr) < 0) {
                goto out;
        }

        memcpy(mac, ifr.ifr_hwaddr.sa_data, ETH_ALEN);
        ret = true;

out:
        close(sock);
        return ret;
#else
        struct ifaddrs *ifap, *ifa;
        bool found = false;

        if (getifaddrs(&ifap) != 0) {
                return false;
        }

        for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
                if (ifa->ifa_addr && ifa->ifa_addr->sa_family == AF_LINK &&
                    strcmp(ifa->ifa_name, iface) == 0) {
                        struct sockaddr_dl *sdl;

                        sdl = (struct sockaddr_dl *)ifa->ifa_addr;
                        memcpy(mac, LLADDR(sdl), ETH_ALEN);
                        found = true;
                        break;
                }
        }

        freeifaddrs(ifap);
        return found;
#endif
}

/*
 *		N E T _ G E T _ I F A C E _ I P
 *
 * Fetch the IPv4 address for a given network interface.
 */
bool
net_get_iface_ip(const char *iface, u_int *ip)
{
        struct ifaddrs *ifap, *ifa;
        bool found = false;

        if (getifaddrs(&ifap) != 0) {
                return false;
        }

        for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
                if (ifa->ifa_addr && ifa->ifa_addr->sa_family == AF_INET &&
                    strcmp(ifa->ifa_name, iface) == 0) {
                        struct sockaddr_in *sin;

                        sin = (struct sockaddr_in *)ifa->ifa_addr;
                        *ip = sin->sin_addr.s_addr;
                        found = true;
                        break;
                }
        }

        freeifaddrs(ifap);
        return found;
}

/*
 *		N E T _ G E T _ I F A C E _ I N D E X
 *
 * Translate an interface name into its system index.
 */
int
net_get_iface_index(const char *iface)
{
        return if_nametoindex(iface);
}

/*
 *		N E T _ O P E N _ R A W _ S O C K E T
 *
 * Open a raw packet socket for link-layer (L2) injection.
 * Linux: Binds an AF_PACKET socket to the specific interface index.
 * BSD/macOS: Iterates through /dev/bpf* devices to find an available Berkeley
 * Packet Filter, then binds it using BIOCSETIF and enables immediate mode.
 */
net_socket_t *
net_open_raw_socket(const char *iface, u_short protocol)
{
#ifdef __linux__
        int fd;
        int ifindex;
        struct sockaddr_ll sll;
        net_socket_t *sock;

        /* Open AF_PACKET socket for L2 frame injection.  */
        fd = socket(AF_PACKET, SOCK_RAW, htons(protocol));
        if (fd < 0) {
                return NULL;
        }

        ifindex = net_get_iface_index(iface);
        if (ifindex == 0) {
                goto err_close;
        }

        memset(&sll, 0, sizeof(sll));
        sll.sll_family = AF_PACKET;
        sll.sll_ifindex = ifindex;
        sll.sll_protocol = htons(protocol);

        if (bind(fd, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
                goto err_close;
        }

        sock = calloc(1, sizeof(net_socket_t));
        if (!sock) {
                log_err("net_open_raw_socket: memory allocation failed");
                goto err_close;
        }

        sock->fd = fd;
        sock->ifindex = ifindex;
        sock->is_dgram = false;

        return sock;

err_close:
        close(fd);
        return NULL;
#else
        int fd = -1;
        char bpf_path[BPF_PATH_MAX];
        int i;
        struct ifreq ifr;
        int opt = 1;
        u_int blen = 0;
        net_socket_t *sock;

        (void)protocol;

        for (i = 0; i < MAX_BPF_DEVS; i++) {
                snprintf(bpf_path, sizeof(bpf_path), "/dev/bpf%d", i);
                fd = open(bpf_path, O_RDWR);
                if (fd >= 0) {
                        break;
                }
        }

        if (fd < 0) {
                return NULL;
        }

        memset(&ifr, 0, sizeof(ifr));
        strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);
        if (ioctl(fd, BIOCSETIF, &ifr) < 0) {
                goto err_close;
        }

        ioctl(fd, BIOCIMMEDIATE, &opt);

        if (ioctl(fd, BIOCGBLEN, &blen) < 0) {
                goto err_close;
        }

        sock = calloc(1, sizeof(net_socket_t));
        if (!sock) {
                log_err("net_open_raw_socket: memory allocation failed");
                goto err_close;
        }

        sock->fd = fd;
        sock->is_dgram = false;
        sock->bpf_buf_len = blen;
        sock->bpf_buf = calloc(1, blen);
        sock->bpf_pos = 0;
        sock->bpf_filled = 0;

        if (!sock->bpf_buf) {
                log_err("net_open_raw_socket: memory allocation failed for "
                        "bpf_buf");
                goto err_free;
        }

        return sock;

err_free:
        free(sock);
err_close:
        close(fd);
        return NULL;
#endif
}

/*
 *		N E T _ O P E N _ I C M P _ S O C K E T
 *
 * Open an ICMP socket. It tries a raw socket first, and falls back
 * to an unprivileged datagram ICMP socket if permissions fail.
 */
net_socket_t *
net_open_icmp_socket(int family)
{
        int proto;
        bool is_dgram;
        int fd;
        net_socket_t *sock;

        proto = (family == AF_INET6) ? IPPROTO_ICMPV6 : IPPROTO_ICMP;
        is_dgram = false;

        fd = socket(family, SOCK_RAW, proto);

        if (fd < 0) {
                fd = socket(family, SOCK_DGRAM, proto);
                if (fd < 0) {
                        return NULL;
                }
                is_dgram = true;
        }

        sock = calloc(1, sizeof(net_socket_t));
        if (!sock) {
                log_err("net_open_icmp_socket: memory allocation failed");
                goto err_close;
        }

        sock->fd = fd;
        sock->is_dgram = is_dgram;
#ifndef __linux__
        sock->bpf_buf = NULL;
        sock->bpf_buf_len = 0;
#endif
        return sock;

err_close:
        close(fd);
        return NULL;
}

/*
 *		N E T _ I S _ D G R A M
 *
 * Check if the socket is a datagram socket rather than raw.
 */
bool
net_is_dgram(net_socket_t *sock)
{
        if (!sock) {
                return false;
        }
        return sock->is_dgram;
}

/*
 *		N E T _ C L O S E _ R A W _ S O C K E T
 *
 * Close the network socket and free any associated buffers.
 */
void
net_close_raw_socket(net_socket_t *sock)
{
        if (!sock) {
                return;
        }

        close(sock->fd);
#ifndef __linux__
        free(sock->bpf_buf);
#endif
        free(sock);
}

/*
 *		N E T _ S E T _ P R O M I S C U O U S
 *
 * Enable promiscuous mode on the raw socket to receive all traffic.
 */
bool
net_set_promiscuous(net_socket_t *sock)
{
#ifdef __linux__
        struct packet_mreq mr;

        memset(&mr, 0, sizeof(mr));
        mr.mr_ifindex = sock->ifindex;
        mr.mr_type = PACKET_MR_PROMISC;

        if (setsockopt(sock->fd, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mr,
                       sizeof(mr)) < 0) {
                return false;
        }
        return true;
#else
        if (ioctl(sock->fd, BIOCPROMISC, NULL) < 0) {
                return false;
        }
        return true;
#endif
}

/*
 *		N E T _ S E N D _ P A C K E T
 *
 * Send a raw Ethernet frame over the network socket.
 */
ssize_t
net_send_packet(net_socket_t *sock, const void *buf, size_t len,
                const u_char *dst_mac)
{
#ifdef __linux__
        struct sockaddr_ll sll;

        memset(&sll, 0, sizeof(sll));
        sll.sll_family = AF_PACKET;
        sll.sll_ifindex = sock->ifindex;
        /* Set hardware address length to 6 bytes for Ethernet.  */
        sll.sll_halen = ETH_ALEN;

        if (dst_mac) {
                memcpy(sll.sll_addr, dst_mac, ETH_ALEN);
        }

        return sendto(sock->fd, buf, len, 0, (struct sockaddr *)&sll,
                      sizeof(sll));
#else
        (void)dst_mac;

        return write(sock->fd, buf, len);
#endif
}

/*
 *		N E T _ R E C V _ P A C K E T
 *
 * Receive a raw Ethernet frame from the socket.
 */
ssize_t
net_recv_packet(net_socket_t *sock, void *buf, size_t len)
{
#ifdef __linux__
        return recvfrom(sock->fd, buf, len, 0, NULL, NULL);
#else
        struct bpf_hdr *hdr;
        size_t packet_len;

        if (sock->bpf_pos >= sock->bpf_filled) {
                ssize_t n = read(sock->fd, sock->bpf_buf, sock->bpf_buf_len);
                if (n <= 0) {
                        return n;
                }
                sock->bpf_filled = n;
                sock->bpf_pos = 0;
        }

        hdr = (struct bpf_hdr *)(sock->bpf_buf + sock->bpf_pos);
        packet_len = hdr->bh_caplen;
        if (packet_len > len) {
                packet_len = len;
        }

        memcpy(buf, sock->bpf_buf + sock->bpf_pos + hdr->bh_hdrlen, packet_len);

        sock->bpf_pos += BPF_WORDALIGN(hdr->bh_hdrlen + hdr->bh_caplen);

        return packet_len;
#endif
}

/*
 *		N E T _ S E N D _ I C M P _ P A C K E T
 *
 * Transmit an ICMP payload using the specified socket.
 */
ssize_t
net_send_icmp_packet(net_socket_t *sock, const void *buf, size_t len,
                     const struct sockaddr *dest, socklen_t dest_len)
{
        return sendto(sock->fd, buf, len, 0, dest, dest_len);
}

/*
 *		N E T _ R E C V _ I C M P _ P A C K E T
 *
 * Receive an ICMP payload, retrieving the source address.
 */
ssize_t
net_recv_icmp_packet(net_socket_t *sock, void *buf, size_t len,
                     struct sockaddr_storage *src, socklen_t *src_len)
{
        return recvfrom(sock->fd, buf, len, 0, (struct sockaddr *)src, src_len);
}

/*
 *		N E T _ G E T _ F D
 *
 * Expose the underlying file descriptor for select/poll mechanisms.
 */
int
net_get_fd(net_socket_t *sock)
{
        if (!sock) {
                return -1;
        }
        return sock->fd;
}

/*
 *		N E T _ R E S O L V E _ H O S T
 *
 * Resolve a hostname or IP string to a sockaddr structure.
 */
bool
net_resolve_host(const char *hostname, int family, struct sockaddr_storage *ss,
                 socklen_t *ss_len)
{
        struct addrinfo hints, *res;

        memset(&hints, 0, sizeof(hints));
        hints.ai_family = family;

        if (getaddrinfo(hostname, NULL, &hints, &res) != 0) {
                return false;
        }

        memcpy(ss, res->ai_addr, res->ai_addrlen);
        *ss_len = res->ai_addrlen;

        freeaddrinfo(res);
        return true;
}

/*
 *		N E T _ R E S O L V E _ I P V 4
 *
 * Convenience function to resolve a hostname strictly to an IPv4 integer.
 */
bool
net_resolve_ipv4(const char *hostname, u_int *ip)
{
        struct addrinfo hints, *res;
        struct sockaddr_in *ipv4;

        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_INET;

        if (getaddrinfo(hostname, NULL, &hints, &res) != 0) {
                return false;
        }

        ipv4 = (struct sockaddr_in *)res->ai_addr;
        *ip = ipv4->sin_addr.s_addr;

        freeaddrinfo(res);
        return true;
}

/*
 *		N E T _ P A R S E _ M A C
 *
 * Convert a colon-separated MAC string into a byte array.
 */
bool
net_parse_mac(const char *mac_str, u_char *mac)
{
        u_int values[MAC_OCTETS];
        int i;

        if (sscanf(mac_str, "%x:%x:%x:%x:%x:%x", &values[0], &values[1],
                   &values[2], &values[3], &values[4],
                   &values[5]) == MAC_OCTETS) {
                for (i = 0; i < MAC_OCTETS; ++i) {
                        mac[i] = (u_char)values[i];
                }
                return true;
        }

        return false;
}

/*
 *		N E T _ G E T _ D E F A U L T _ G A T E W A Y
 *
 * Extract the default gateway IP for a specific interface.
 * Linux parses /proc/net/route, while BSD queries the routing sysctl.
 */
bool
net_get_default_gateway(const char *iface, u_int *gateway_ip)
{
#ifdef __linux__
        FILE *fp;
        char line[MAX_LINE_LEN];
        char name[MAX_IFACE_LEN];
        u_long dst, gw;
        bool ret = false;

        fp = fopen("/proc/net/route", "r");
        if (!fp) {
                return false;
        }

        if (!fgets(line, sizeof(line), fp)) {
                goto out;
        }

        while (fgets(line, sizeof(line), fp)) {
                if (sscanf(line, "%127s %lx %lx", name, &dst, &gw) != 3) {
                        continue;
                }

                /* Check if destination is default route (0) and matches iface
                 */
                if (dst == 0 && strcmp(name, iface) == 0) {
                        *gateway_ip = (u_int)gw;
                        ret = true;
                        goto out;
                }
        }

out:
        fclose(fp);
        return ret;
#else
        int mib[6] = {CTL_NET, PF_ROUTE, 0, AF_INET, NET_RT_FLAGS, RTF_GATEWAY};
        size_t len;
        char *buf;
        char *next;
        char *lim;
        bool ret = false;

        if (sysctl(mib, 6, NULL, &len, NULL, 0) < 0) {
                return false;
        }

        buf = calloc(1, len);
        if (!buf) {
                log_err("net_get_default_gateway: memory allocation failed");
                return false;
        }

        if (sysctl(mib, 6, buf, &len, NULL, 0) < 0) {
                goto out;
        }

        next = buf;
        lim = buf + len;

        while (next < lim) {
                struct rt_msghdr *rtm;
                struct sockaddr *sa;
                struct sockaddr_in *gw = NULL;
                struct sockaddr_in *dst = NULL;
                int i;

                rtm = (struct rt_msghdr *)next;
                next += rtm->rtm_msglen;
                sa = (struct sockaddr *)(rtm + 1);

#ifndef ROUNDUP
#define ROUNDUP(a)                                                             \
        ((a) > 0 ? (1 + (((a) - 1) | (sizeof(long) - 1))) : sizeof(long))
#endif
#ifndef SA_SIZE
#define SA_SIZE(sa) ROUNDUP((sa)->sa_len)
#endif
                for (i = 0; i < RTAX_MAX; i++) {
                        if (!(rtm->rtm_addrs & (1 << i))) {
                                continue;
                        }
                        if (i == RTAX_GATEWAY) {
                                gw = (struct sockaddr_in *)sa;
                        }
                        if (i == RTAX_DST) {
                                dst = (struct sockaddr_in *)sa;
                        }
                        sa = (struct sockaddr *)((char *)sa + SA_SIZE(sa));
                }

                if (dst && dst->sin_addr.s_addr == 0 && gw &&
                    rtm->rtm_index == if_nametoindex(iface)) {
                        *gateway_ip = gw->sin_addr.s_addr;
                        ret = true;
                        goto out;
                }
        }

out:
        free(buf);
        return ret;
#endif
}

/*
 *		N E T _ O P E N _ I P _ R A W _ S O C K E T
 *
 * Open an L3 raw IP socket.
 */
net_socket_t *
net_open_ip_raw_socket(int family, int protocol)
{
        int fd;
        net_socket_t *sock;

        fd = socket(family, SOCK_RAW, protocol);
        if (fd < 0) {
                return NULL;
        }

        sock = calloc(1, sizeof(net_socket_t));
        if (!sock) {
                log_err("net_open_ip_raw_socket: memory allocation failed");
                goto err_close;
        }

        sock->fd = fd;
        sock->is_dgram = false;
#ifndef __linux__
        sock->bpf_buf = NULL;
        sock->bpf_buf_len = 0;
#endif
        return sock;

err_close:
        close(fd);
        return NULL;
}

/*
 *		N E T _ S E N D _ I P _ R A W
 *
 * Transmit an IP packet payload.
 */
ssize_t
net_send_ip_raw(net_socket_t *sock, const void *buf, size_t len,
                const struct sockaddr *dest, socklen_t dest_len)
{
        return sendto(sock->fd, buf, len, 0, dest, dest_len);
}

/*
 *		N E T _ R E C V _ I P _ R A W
 *
 * Receive an IP packet payload.
 */
ssize_t
net_recv_ip_raw(net_socket_t *sock, void *buf, size_t len,
                struct sockaddr_storage *src, socklen_t *src_len)
{
        return recvfrom(sock->fd, buf, len, 0, (struct sockaddr *)src, src_len);
}

/*
 *		N E T _ G E T _ S O U R C E _ I P _ F O R
 *
 * Determine the local source IP address that will be used to reach a
 * destination.
 */
bool
net_get_source_ip_for(const struct sockaddr_storage *dst, socklen_t dst_len,
                      struct sockaddr_storage *src, socklen_t *src_len)
{
        int sock;
        struct sockaddr_storage dst_copy;
        bool ret = false;

        sock = socket(dst->ss_family, SOCK_DGRAM, 0);
        if (sock < 0) {
                return false;
        }

        memcpy(&dst_copy, dst, dst_len);
        if (dst_copy.ss_family == AF_INET) {
                struct sockaddr_in *sin = (struct sockaddr_in *)&dst_copy;
                if (sin->sin_port == 0) {
                        sin->sin_port = htons(DNS_PORT);
                }
        } else if (dst_copy.ss_family == AF_INET6) {
                struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&dst_copy;
                if (sin6->sin6_port == 0) {
                        sin6->sin6_port = htons(DNS_PORT);
                }
        }

        /* Perform UDP connect to route target and determine source IP.  */
        if (connect(sock, (const struct sockaddr *)&dst_copy, dst_len) < 0) {
                goto out;
        }

        if (getsockname(sock, (struct sockaddr *)src, src_len) < 0) {
                goto out;
        }

        ret = true;

out:
        close(sock);
        return ret;
}

/*
 *		N E T _ C H E C K S U M
 *
 * Calculate the standard 16-bit one's complement Internet checksum.
 */
u_short
net_checksum(const void *b, int len)
{
        const u_short *buf = b;
        u_int sum = 0;
        u_short result;

        for (sum = 0; len > 1; len -= 2) {
                sum += *buf++;
        }

        if (len == 1) {
                sum += *(const u_char *)buf;
        }

        sum = (sum >> CHECKSUM_SHIFT) + (sum & CHECKSUM_MASK);
        sum += (sum >> CHECKSUM_SHIFT);

        result = ~sum;

        return result;
}
