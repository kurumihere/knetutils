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
        int sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (sock < 0)
                return false;
        struct ifreq ifr;
        memset(&ifr, 0, sizeof(ifr));
        strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);
        if (ioctl(sock, SIOCGIFHWADDR, &ifr) < 0) {
                close(sock);
                return false;
        }
        memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
        close(sock);
        return true;
#else
        struct ifaddrs *ifap, *ifa;
        if (getifaddrs(&ifap) != 0)
                return false;
        bool found = false;
        for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
                if (ifa->ifa_addr && ifa->ifa_addr->sa_family == AF_LINK &&
                    strcmp(ifa->ifa_name, iface) == 0) {
                        struct sockaddr_dl *sdl =
                            (struct sockaddr_dl *)ifa->ifa_addr;
                        memcpy(mac, LLADDR(sdl), 6);
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
        if (getifaddrs(&ifap) != 0)
                return false;
        bool found = false;
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

        net_socket_t *sock = malloc(sizeof(net_socket_t));
        if (!sock) {
                close(fd);
                return NULL;
        }
        sock->fd = fd;
        sock->ifindex = ifindex;
        return sock;
#else
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

        net_socket_t *sock = malloc(sizeof(net_socket_t));
        if (!sock) {
                close(fd);
                return NULL;
        }
        sock->fd = fd;
        sock->bpf_buf_len = blen;
        sock->bpf_buf = malloc(blen);
        sock->bpf_pos = 0;
        sock->bpf_filled = 0;

        if (!sock->bpf_buf) {
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
        int fd = socket(family, SOCK_RAW, proto);
        if (fd < 0)
                return NULL;
        net_socket_t *sock = malloc(sizeof(net_socket_t));
        if (!sock) {
                close(fd);
                return NULL;
        }
        sock->fd = fd;
#ifndef __linux__
        sock->bpf_buf = NULL;
        sock->bpf_buf_len = 0;
#endif
        return sock;
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
        char *buf = malloc(len);
        if (!buf)
                return false;
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
#define KNET_SA_SIZE(sa)                                                       \
        ((sa)->sa_len > 0 ? (1 + (((sa)->sa_len - 1) | (sizeof(long) - 1)))    \
                          : sizeof(long))
                for (int i = 0; i < RTAX_MAX; i++) {
                        if (rtm->rtm_addrs & (1 << i)) {
                                if (i == RTAX_GATEWAY)
                                        gw = (struct sockaddr_in *)sa;
                                if (i == RTAX_DST)
                                        dst = (struct sockaddr_in *)sa;
                                sa = (struct sockaddr *)((char *)sa +
                                                         KNET_SA_SIZE(sa));
                        }
                }
#undef KNET_SA_SIZE
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
