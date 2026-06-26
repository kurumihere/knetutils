#include "net.h"
#include "utils.h"
#include <arpa/inet.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

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
        uint8_t *bpf_buf;
        size_t bpf_buf_len;
        size_t bpf_pos;
        size_t bpf_filled;
};

#endif

bool
net_get_iface_mac(const char *iface, uint8_t *mac)
{
#ifdef __linux__
        int sock;
        struct ifreq ifr;

        sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (sock < 0)
                return false;

        memset(&ifr, 0, sizeof(ifr));
        strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);
        if (ioctl(sock, SIOCGIFHWADDR, &ifr) < 0) {
                close(sock);
                return false;
        }
        memcpy(mac, ifr.ifr_hwaddr.sa_data, ETH_ALEN);
        close(sock);
        return true;
#else
        struct ifaddrs *ifap, *ifa;
        bool found = false;

        if (getifaddrs(&ifap) != 0)
                return false;

        for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
                if (ifa->ifa_addr && ifa->ifa_addr->sa_family == AF_LINK &&
                    strcmp(ifa->ifa_name, iface) == 0) {
                        struct sockaddr_dl *sdl =
                            (struct sockaddr_dl *)ifa->ifa_addr;
                        memcpy(mac, LLADDR(sdl), ETH_ALEN);
                        found = true;
                        break;
                }
        }
        freeifaddrs(ifap);
        return found;
#endif
}

bool
net_get_iface_ip(const char *iface, uint32_t *ip)
{
        struct ifaddrs *ifap, *ifa;
        bool found = false;

        if (getifaddrs(&ifap) != 0)
                return false;

        for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
                if (ifa->ifa_addr && ifa->ifa_addr->sa_family == AF_INET &&
                    strcmp(ifa->ifa_name, iface) == 0) {
                        struct sockaddr_in *sin =
                            (struct sockaddr_in *)ifa->ifa_addr;
                        *ip = sin->sin_addr.s_addr;
                        found = true;
                        break;
                }
        }
        freeifaddrs(ifap);
        return found;
}

int
net_get_iface_index(const char *iface)
{
        return if_nametoindex(iface);
}

net_socket_t *
net_open_raw_socket(const char *iface, uint16_t protocol)
{
#ifdef __linux__
        int fd = socket(AF_PACKET, SOCK_RAW, htons(protocol));
        if (fd < 0)
                return NULL;

        int ifindex = net_get_iface_index(iface);
        if (ifindex == 0) {
                close(fd);
                return NULL;
        }

        struct sockaddr_ll sll;
        memset(&sll, 0, sizeof(sll));
        sll.sll_family = AF_PACKET;
        sll.sll_ifindex = ifindex;
        sll.sll_protocol = htons(protocol);

        if (bind(fd, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
                close(fd);
                return NULL;
        }

        net_socket_t *sock = calloc(1, sizeof(net_socket_t));
        if (!sock) {
                log_err("net_open_raw_socket: memory allocation failed");
                close(fd);
                return NULL;
        }
        sock->fd = fd;
        sock->ifindex = ifindex;
        sock->is_dgram = false;
        return sock;
#else
        (void)protocol;
        int fd = -1;
        char bpf_path[32];
        for (int i = 0; i < 256; i++) {
                snprintf(bpf_path, sizeof(bpf_path), "/dev/bpf%d", i);
                fd = open(bpf_path, O_RDWR);
                if (fd >= 0)
                        break;
        }
        if (fd < 0)
                return NULL;

        struct ifreq ifr;
        memset(&ifr, 0, sizeof(ifr));
        strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);
        if (ioctl(fd, BIOCSETIF, &ifr) < 0) {
                close(fd);
                return NULL;
        }

        int opt = 1;
        ioctl(fd, BIOCIMMEDIATE, &opt);

        unsigned int blen = 0;
        if (ioctl(fd, BIOCGBLEN, &blen) < 0) {
                close(fd);
                return NULL;
        }

        net_socket_t *sock = calloc(1, sizeof(net_socket_t));
        if (!sock) {
                log_err("net_open_raw_socket: memory allocation failed");
                close(fd);
                return NULL;
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
                close(fd);
                free(sock);
                return NULL;
        }

        return sock;
#endif
}

net_socket_t *
net_open_icmp_socket(int family)
{
        int proto = (family == AF_INET6) ? IPPROTO_ICMPV6 : IPPROTO_ICMP;
        bool is_dgram = false;
        int fd = socket(family, SOCK_RAW, proto);
        if (fd < 0) {
                fd = socket(family, SOCK_DGRAM, proto);
                if (fd < 0) {
                        return NULL;
                }
                is_dgram = true;
        }
        net_socket_t *sock = calloc(1, sizeof(net_socket_t));
        if (!sock) {
                log_err("net_open_icmp_socket: memory allocation failed");
                close(fd);
                return NULL;
        }
        sock->fd = fd;
        sock->is_dgram = is_dgram;
#ifndef __linux__
        sock->bpf_buf = NULL;
        sock->bpf_buf_len = 0;
#endif
        return sock;
}

bool
net_is_dgram(net_socket_t *sock)
{
        return sock ? sock->is_dgram : false;
}

void
net_close_raw_socket(net_socket_t *sock)
{
        if (!sock)
                return;
        close(sock->fd);
#ifndef __linux__
        free(sock->bpf_buf);
#endif
        free(sock);
}

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

ssize_t
net_send_packet(net_socket_t *sock, const void *buf, size_t len,
                const uint8_t *dst_mac)
{
#ifdef __linux__
        struct sockaddr_ll sll;
        memset(&sll, 0, sizeof(sll));
        sll.sll_family = AF_PACKET;
        sll.sll_ifindex = sock->ifindex;
        sll.sll_halen = 6;
        if (dst_mac) {
                memcpy(sll.sll_addr, dst_mac, 6);
        }
        return sendto(sock->fd, buf, len, 0, (struct sockaddr *)&sll,
                      sizeof(sll));
#else
        (void)dst_mac;
        return write(sock->fd, buf, len);
#endif
}

ssize_t
net_recv_packet(net_socket_t *sock, void *buf, size_t len)
{
#ifdef __linux__
        return recvfrom(sock->fd, buf, len, 0, NULL, NULL);
#else
        if (sock->bpf_pos >= sock->bpf_filled) {
                ssize_t n = read(sock->fd, sock->bpf_buf, sock->bpf_buf_len);
                if (n <= 0)
                        return n;
                sock->bpf_filled = n;
                sock->bpf_pos = 0;
        }

        struct bpf_hdr *hdr = (struct bpf_hdr *)(sock->bpf_buf + sock->bpf_pos);
        size_t packet_len = hdr->bh_caplen;
        if (packet_len > len)
                packet_len = len;

        memcpy(buf, sock->bpf_buf + sock->bpf_pos + hdr->bh_hdrlen, packet_len);
        sock->bpf_pos += BPF_WORDALIGN(hdr->bh_hdrlen + hdr->bh_caplen);

        return packet_len;
#endif
}

ssize_t
net_send_icmp_packet(net_socket_t *sock, const void *buf, size_t len,
                     const struct sockaddr *dest, socklen_t dest_len)
{
        return sendto(sock->fd, buf, len, 0, dest, dest_len);
}

ssize_t
net_recv_icmp_packet(net_socket_t *sock, void *buf, size_t len,
                     struct sockaddr_storage *src, socklen_t *src_len)
{
        return recvfrom(sock->fd, buf, len, 0, (struct sockaddr *)src, src_len);
}

int
net_get_fd(net_socket_t *sock)
{
        return sock ? sock->fd : -1;
}

#include <netdb.h>

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

bool
net_resolve_ipv4(const char *hostname, uint32_t *ip)
{
        struct addrinfo hints, *res;
        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_INET;

        if (getaddrinfo(hostname, NULL, &hints, &res) != 0) {
                return false;
        }

        struct sockaddr_in *ipv4 = (struct sockaddr_in *)res->ai_addr;
        *ip = ipv4->sin_addr.s_addr;
        freeaddrinfo(res);
        return true;
}

bool
net_parse_mac(const char *mac_str, uint8_t *mac)
{
        unsigned int values[6];
        if (sscanf(mac_str, "%x:%x:%x:%x:%x:%x", &values[0], &values[1],
                   &values[2], &values[3], &values[4], &values[5]) == 6) {
                for (int i = 0; i < 6; ++i)
                        mac[i] = (uint8_t)values[i];
                return true;
        }
        return false;
}

bool
net_get_default_gateway(const char *iface, uint32_t *gateway_ip)
{
#ifdef __linux__
        FILE *fp = fopen("/proc/net/route", "r");
        if (!fp)
                return false;
        char line[256];
        char name[128];
        unsigned long dst, gw;
        if (!fgets(line, sizeof(line), fp)) {
                fclose(fp);
                return false;
        }
        while (fgets(line, sizeof(line), fp)) {
                if (sscanf(line, "%127s %lx %lx", name, &dst, &gw) != 3)
                        continue;
                if (dst == 0 && strcmp(name, iface) == 0) {
                        *gateway_ip = (uint32_t)gw;
                        fclose(fp);
                        return true;
                }
        }
        fclose(fp);
        return false;
#else
        int mib[6] = {CTL_NET, PF_ROUTE, 0, AF_INET, NET_RT_FLAGS, RTF_GATEWAY};
        size_t len;
        if (sysctl(mib, 6, NULL, &len, NULL, 0) < 0)
                return false;
        char *buf = calloc(1, len);
        if (!buf) {
                log_err("net_get_default_gateway: memory allocation failed");
                return false;
        }
        if (sysctl(mib, 6, buf, &len, NULL, 0) < 0) {
                free(buf);
                return false;
        }
        char *next = buf;
        char *lim = buf + len;
        while (next < lim) {
                struct rt_msghdr *rtm = (struct rt_msghdr *)next;
                next += rtm->rtm_msglen;
                struct sockaddr *sa = (struct sockaddr *)(rtm + 1);
                struct sockaddr_in *gw = NULL;
                struct sockaddr_in *dst = NULL;
#ifndef ROUNDUP
#define ROUNDUP(a)                                                             \
        ((a) > 0 ? (1 + (((a) - 1) | (sizeof(long) - 1))) : sizeof(long))
#endif
#ifndef SA_SIZE
#define SA_SIZE(sa) ROUNDUP((sa)->sa_len)
#endif
                for (int i = 0; i < RTAX_MAX; i++) {
                        if (!(rtm->rtm_addrs & (1 << i)))
                                continue;
                        if (i == RTAX_GATEWAY)
                                gw = (struct sockaddr_in *)sa;
                        if (i == RTAX_DST)
                                dst = (struct sockaddr_in *)sa;
                        sa = (struct sockaddr *)((char *)sa + SA_SIZE(sa));
                }
                if (dst && dst->sin_addr.s_addr == 0 && gw &&
                    rtm->rtm_index == if_nametoindex(iface)) {
                        *gateway_ip = gw->sin_addr.s_addr;
                        free(buf);
                        return true;
                }
        }
        free(buf);
        return false;
#endif
}

net_socket_t *
net_open_ip_raw_socket(int family, int protocol)
{
        int fd = socket(family, SOCK_RAW, protocol);
        if (fd < 0) {
                return NULL;
        }
        net_socket_t *sock = calloc(1, sizeof(net_socket_t));
        if (!sock) {
                log_err("net_open_ip_raw_socket: memory allocation failed");
                close(fd);
                return NULL;
        }
        sock->fd = fd;
        sock->is_dgram = false;
#ifndef __linux__
        sock->bpf_buf = NULL;
        sock->bpf_buf_len = 0;
#endif
        return sock;
}

ssize_t
net_send_ip_raw(net_socket_t *sock, const void *buf, size_t len,
                const struct sockaddr *dest, socklen_t dest_len)
{
        return sendto(sock->fd, buf, len, 0, dest, dest_len);
}

ssize_t
net_recv_ip_raw(net_socket_t *sock, void *buf, size_t len,
                struct sockaddr_storage *src, socklen_t *src_len)
{
        return recvfrom(sock->fd, buf, len, 0, (struct sockaddr *)src, src_len);
}

bool
net_get_source_ip_for(const struct sockaddr_storage *dst, socklen_t dst_len,
                      struct sockaddr_storage *src, socklen_t *src_len)
{
        int sock = socket(dst->ss_family, SOCK_DGRAM, 0);
        if (sock < 0)
                return false;

        struct sockaddr_storage dst_copy;
        memcpy(&dst_copy, dst, dst_len);
        if (dst_copy.ss_family == AF_INET) {
                struct sockaddr_in *sin = (struct sockaddr_in *)&dst_copy;
                if (sin->sin_port == 0)
                        sin->sin_port = htons(53);
        } else if (dst_copy.ss_family == AF_INET6) {
                struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&dst_copy;
                if (sin6->sin6_port == 0)
                        sin6->sin6_port = htons(53);
        }

        if (connect(sock, (const struct sockaddr *)&dst_copy, dst_len) < 0) {
                close(sock);
                return false;
        }

        if (getsockname(sock, (struct sockaddr *)src, src_len) < 0) {
                close(sock);
                return false;
        }
        close(sock);
        return true;
}

uint16_t
net_checksum(const void *b, int len)
{
        const uint16_t *buf = b;
        unsigned int sum = 0;
        uint16_t result;
        for (sum = 0; len > 1; len -= 2)
                sum += *buf++;
        if (len == 1)
                sum += *(const uint8_t *)buf;
        sum = (sum >> 16) + (sum & 0xFFFF);
        sum += (sum >> 16);
        result = ~sum;
        return result;
}
