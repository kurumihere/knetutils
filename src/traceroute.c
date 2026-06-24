#include "traceroute.h"
#include "net.h"
#include "utils.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/icmp6.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static volatile bool keep_running = true;

static void
handle_sigint(int sig)
{
        (void)sig;
        keep_running = false;
}

static uint16_t
icmp_checksum(const void *b, int len)
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

static bool
is_our_probe_v4(const uint8_t *buf, ssize_t len, uint16_t expected_id,
                uint16_t expected_seq)
{
        if (len < (ssize_t)sizeof(struct ip))
                return false;

        struct ip *ip_hdr = (struct ip *)buf;
        int hlen = ip_hdr->ip_hl << 2;

        if (len < (ssize_t)(hlen + sizeof(struct icmp)))
                return false;

        struct icmp *icp = (struct icmp *)(buf + hlen);

        if (icp->icmp_type == ICMP_ECHOREPLY) {
                return icp->icmp_id == expected_id &&
                       icp->icmp_seq == expected_seq;
        }

        if (icp->icmp_type == ICMP_TIMXCEED || icp->icmp_type == ICMP_UNREACH) {
                if (len < (ssize_t)(hlen + 8 + sizeof(struct ip)))
                        return false;

                struct ip *inner_ip = (struct ip *)icp->icmp_data;
                int inner_hlen = inner_ip->ip_hl << 2;

                if (len < (ssize_t)(hlen + 8 + inner_hlen + 8))
                        return false;

                struct icmp *inner_icp =
                    (struct icmp *)((uint8_t *)inner_ip + inner_hlen);
                return inner_icp->icmp_id == expected_id &&
                       inner_icp->icmp_seq == expected_seq;
        }

        return false;
}

static bool
is_our_probe_v6(const uint8_t *buf, ssize_t len, uint16_t expected_id,
                uint16_t expected_seq)
{
        if (len < (ssize_t)sizeof(struct icmp6_hdr))
                return false;

        struct icmp6_hdr *icp = (struct icmp6_hdr *)buf;

        if (icp->icmp6_type == ICMP6_ECHO_REPLY) {
                return icp->icmp6_id == expected_id &&
                       icp->icmp6_seq == expected_seq;
        }

        if (icp->icmp6_type == ICMP6_TIME_EXCEEDED ||
            icp->icmp6_type == ICMP6_DST_UNREACH) {
                if (len < (ssize_t)(sizeof(struct icmp6_hdr) +
                                    sizeof(struct ip6_hdr) + 8))
                        return false;

                struct ip6_hdr *inner_ip = (struct ip6_hdr *)(icp + 1);
                struct icmp6_hdr *inner_icp =
                    (struct icmp6_hdr *)((uint8_t *)inner_ip +
                                         sizeof(struct ip6_hdr));

                return inner_icp->icmp6_id == expected_id &&
                       inner_icp->icmp6_seq == expected_seq;
        }

        return false;
}

int
traceroute_run(const traceroute_config_t *config)
{
        signal(SIGINT, handle_sigint);

        net_socket_t *sock = net_open_icmp_socket(config->family);
        if (!sock) {
                die("Failed to open ICMP socket. Are you root?");
        }

        if (config->bind_iface) {
                struct sockaddr_storage bind_addr;
                memset(&bind_addr, 0, sizeof(bind_addr));
                if (inet_pton(AF_INET, config->bind_iface,
                              &((struct sockaddr_in *)&bind_addr)->sin_addr) ==
                    1) {
                        bind_addr.ss_family = AF_INET;
                        if (bind(net_get_fd(sock),
                                 (struct sockaddr *)&bind_addr,
                                 sizeof(struct sockaddr_in)) < 0) {
                                die("Failed to bind to IP %s",
                                    config->bind_iface);
                        }
                } else if (inet_pton(AF_INET6, config->bind_iface,
                                     &((struct sockaddr_in6 *)&bind_addr)
                                          ->sin6_addr) == 1) {
                        bind_addr.ss_family = AF_INET6;
                        if (bind(net_get_fd(sock),
                                 (struct sockaddr *)&bind_addr,
                                 sizeof(struct sockaddr_in6)) < 0) {
                                die("Failed to bind to IP %s",
                                    config->bind_iface);
                        }
                } else {
                        if (setsockopt(net_get_fd(sock), SOL_SOCKET,
                                       SO_BINDTODEVICE, config->bind_iface,
                                       strlen(config->bind_iface)) < 0) {
                                die("Failed to bind to interface %s",
                                    config->bind_iface);
                        }
                }
        }

        if (setgid(getgid()) != 0) {
                log_warn("Failed to drop group privileges");
        }
        if (setuid(getuid()) != 0) {
                log_warn("Failed to drop user privileges");
        }

        char target_str[INET6_ADDRSTRLEN];
        getnameinfo((struct sockaddr *)&config->target_addr,
                    config->target_addr_len, target_str, sizeof(target_str),
                    NULL, 0, NI_NUMERICHOST);

        printf("traceroute to %s, %u hops max\n", target_str, config->max_ttl);

        uint16_t pid = getpid() & 0xFFFF;
        uint16_t seq = 1;
        bool target_reached = false;

        struct pollfd pfd;
        pfd.fd = net_get_fd(sock);
        pfd.events = POLLIN;

        size_t header_size = (config->family == AF_INET6)
                                 ? sizeof(struct icmp6_hdr)
                                 : sizeof(struct icmp);

        uint8_t *packet = calloc(1, header_size);
        if (!packet)
                die("Memory allocation failed");

        for (uint8_t ttl = config->first_ttl;
             ttl <= config->max_ttl && keep_running && !target_reached; ttl++) {

                int level =
                    (config->family == AF_INET6) ? IPPROTO_IPV6 : IPPROTO_IP;
                int optname =
                    (config->family == AF_INET6) ? IPV6_UNICAST_HOPS : IP_TTL;
                int ttl_val = ttl;
                if (setsockopt(net_get_fd(sock), level, optname, &ttl_val,
                               sizeof(ttl_val)) < 0) {
                        die("Failed to set TTL");
                }

                printf("%2u  ", ttl);
                fflush(stdout);

                struct sockaddr_storage last_hop_addr;
                memset(&last_hop_addr, 0, sizeof(last_hop_addr));

                for (uint8_t probe = 0; probe < config->queries && keep_running;
                     probe++) {

                        if (config->family == AF_INET) {
                                struct icmp *icp = (struct icmp *)packet;
                                icp->icmp_type = ICMP_ECHO;
                                icp->icmp_code = 0;
                                icp->icmp_id = htons(pid);
                                icp->icmp_seq = htons(seq);
                                icp->icmp_cksum = 0;
                                icp->icmp_cksum =
                                    icmp_checksum(packet, header_size);
                        } else {
                                struct icmp6_hdr *icp =
                                    (struct icmp6_hdr *)packet;
                                icp->icmp6_type = ICMP6_ECHO_REQUEST;
                                icp->icmp6_code = 0;
                                icp->icmp6_id = htons(pid);
                                icp->icmp6_seq = htons(seq);
                                icp->icmp6_cksum = 0;
                        }

                        uint64_t send_time = get_time_ns();

                        if (net_send_icmp_packet(
                                sock, packet, header_size,
                                (struct sockaddr *)&config->target_addr,
                                config->target_addr_len) < 0) {
                                printf("* ");
                                fflush(stdout);
                                seq++;
                                continue;
                        }

                        uint64_t wait_until = send_time + config->timeout_ns;
                        bool got_reply = false;

                        while (get_time_ns() < wait_until && keep_running) {
                                int64_t timeout_ns = wait_until - get_time_ns();
                                if (timeout_ns <= 0)
                                        break;

                                int timeout_ms = timeout_ns / 1000000;
                                int ret = poll(&pfd, 1,
                                               timeout_ms > 0 ? timeout_ms : 1);
                                if (ret <= 0 || !(pfd.revents & POLLIN))
                                        continue;

                                uint8_t recv_buf[4096];
                                struct sockaddr_storage src_addr;
                                socklen_t src_addr_len = sizeof(src_addr);
                                ssize_t n = net_recv_icmp_packet(
                                    sock, recv_buf, sizeof(recv_buf), &src_addr,
                                    &src_addr_len);

                                if (n <= 0)
                                        continue;

                                bool is_mine = false;
                                bool is_target = false;

                                if (config->family == AF_INET) {
                                        is_mine = is_our_probe_v4(recv_buf, n,
                                                                  htons(pid),
                                                                  htons(seq));

                                        struct ip *ip_hdr =
                                            (struct ip *)recv_buf;
                                        int hlen = ip_hdr->ip_hl << 2;
                                        if (is_mine &&
                                            n >= (ssize_t)(hlen +
                                                           sizeof(
                                                               struct icmp))) {
                                                struct icmp *icp =
                                                    (struct icmp *)(recv_buf +
                                                                    hlen);
                                                if (icp->icmp_type ==
                                                    ICMP_ECHOREPLY) {
                                                        is_target = true;
                                                }
                                        }
                                } else {
                                        is_mine = is_our_probe_v6(recv_buf, n,
                                                                  htons(pid),
                                                                  htons(seq));
                                        if (is_mine &&
                                            n >= (ssize_t)sizeof(
                                                     struct icmp6_hdr)) {
                                                struct icmp6_hdr *icp =
                                                    (struct icmp6_hdr *)
                                                        recv_buf;
                                                if (icp->icmp6_type ==
                                                    ICMP6_ECHO_REPLY) {
                                                        is_target = true;
                                                }
                                        }
                                }

                                if (!is_mine)
                                        continue;

                                uint64_t recv_time = get_time_ns();
                                uint64_t rtt =
                                    time_diff_ns(send_time, recv_time);

                                if (memcmp(&last_hop_addr, &src_addr,
                                           sizeof(last_hop_addr)) != 0) {
                                        char host_str[NI_MAXHOST];
                                        char ip_str[INET6_ADDRSTRLEN];

                                        getnameinfo(
                                            (struct sockaddr *)&src_addr,
                                            src_addr_len, ip_str,
                                            sizeof(ip_str), NULL, 0,
                                            NI_NUMERICHOST);

                                        if (config->resolve_hostnames &&
                                            getnameinfo(
                                                (struct sockaddr *)&src_addr,
                                                src_addr_len, host_str,
                                                sizeof(host_str), NULL, 0,
                                                NI_NAMEREQD) == 0) {
                                                printf("%s (%s)  ", host_str,
                                                       ip_str);
                                        } else {
                                                printf("%s  ", ip_str);
                                        }

                                        memcpy(&last_hop_addr, &src_addr,
                                               sizeof(last_hop_addr));
                                }

                                char time_buf[64];
                                format_time(rtt, "ms", time_buf,
                                            sizeof(time_buf));
                                printf("%s  ", time_buf);
                                fflush(stdout);

                                got_reply = true;
                                if (is_target) {
                                        target_reached = true;
                                }
                                break;
                        }

                        if (!got_reply) {
                                printf("* ");
                                fflush(stdout);
                        }

                        seq++;
                }
                printf("\n");
        }

        free(packet);
        net_close_raw_socket(sock);
        return 0;
}
