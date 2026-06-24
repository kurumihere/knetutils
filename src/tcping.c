#include "tcping.h"
#include "net.h"
#include "utils.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifndef TH_SYN
#define TH_SYN 0x02
#endif
#ifndef TH_RST
#define TH_RST 0x04
#endif
#ifndef TH_ACK
#define TH_ACK 0x10
#endif

static volatile bool keep_running = true;

static void
handle_sigint(int sig)
{
        (void)sig;
        keep_running = false;
}

static uint16_t
tcp_checksum(const void *b, int len)
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

struct ipv4_pseudo_header {
        uint32_t src_addr;
        uint32_t dst_addr;
        uint8_t zero;
        uint8_t protocol;
        uint16_t tcp_length;
} __attribute__((packed));

struct ipv6_pseudo_header {
        struct in6_addr src_addr;
        struct in6_addr dst_addr;
        uint32_t tcp_length;
        uint8_t zero[3];
        uint8_t next_header;
} __attribute__((packed));

int
tcping_run(const tcping_config_t *config)
{
        signal(SIGINT, handle_sigint);

        net_socket_t *sock =
            net_open_ip_raw_socket(config->family, IPPROTO_TCP);
        if (!sock) {
                die("Failed to open raw TCP socket. Are you root?");
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

        struct sockaddr_storage src_addr;
        socklen_t src_addr_len = sizeof(src_addr);
        if (!net_get_source_ip_for(&config->target_addr,
                                   config->target_addr_len, &src_addr,
                                   &src_addr_len)) {
                die("Failed to determine source IP for target");
        }

        uint16_t sport = 1024 + (getpid() % 64000);
        uint32_t seq = 1000;

        if (!config->quiet) {
                printf("TCPING %s:%u\n", target_str, config->port);
        }

        uint32_t sent = 0;
        uint32_t received = 0;

        struct pollfd pfd;
        pfd.fd = net_get_fd(sock);
        pfd.events = POLLIN;

        while (keep_running) {
                if (config->count > 0 && sent >= config->count) {
                        break;
                }

                struct tcphdr tcph;
                memset(&tcph, 0, sizeof(tcph));
                tcph.th_sport = htons(sport);
                tcph.th_dport = htons(config->port);
                tcph.th_seq = htonl(seq);
                tcph.th_ack = 0;
                tcph.th_off = 5;
                tcph.th_flags = TH_SYN;
                tcph.th_win = htons(64240);
                tcph.th_sum = 0;
                tcph.th_urp = 0;

                uint8_t csum_buf[1024];
                size_t csum_len = 0;

                if (config->family == AF_INET) {
                        struct ipv4_pseudo_header psh;
                        psh.src_addr =
                            ((struct sockaddr_in *)&src_addr)->sin_addr.s_addr;
                        psh.dst_addr =
                            ((struct sockaddr_in *)&config->target_addr)
                                ->sin_addr.s_addr;
                        psh.zero = 0;
                        psh.protocol = IPPROTO_TCP;
                        psh.tcp_length = htons(sizeof(struct tcphdr));

                        memcpy(csum_buf, &psh, sizeof(psh));
                        csum_len += sizeof(psh);
                } else {
                        struct ipv6_pseudo_header psh;
                        psh.src_addr =
                            ((struct sockaddr_in6 *)&src_addr)->sin6_addr;
                        psh.dst_addr =
                            ((struct sockaddr_in6 *)&config->target_addr)
                                ->sin6_addr;
                        psh.tcp_length = htonl(sizeof(struct tcphdr));
                        memset(psh.zero, 0, 3);
                        psh.next_header = IPPROTO_TCP;

                        memcpy(csum_buf, &psh, sizeof(psh));
                        csum_len += sizeof(psh);
                }

                memcpy(csum_buf + csum_len, &tcph, sizeof(tcph));
                csum_len += sizeof(tcph);

                tcph.th_sum = tcp_checksum(csum_buf, csum_len);

                uint64_t send_time = get_time_ns();

                if (net_send_ip_raw(sock, &tcph, sizeof(tcph),
                                    (struct sockaddr *)&config->target_addr,
                                    config->target_addr_len) < 0) {
                        log_err("Failed to send TCP SYN packet");
                }
                sent++;

                uint64_t wait_until = send_time + config->timeout_ns;
                bool replied = false;

                while (get_time_ns() < wait_until && keep_running) {
                        int64_t timeout_ns = wait_until - get_time_ns();
                        if (timeout_ns <= 0)
                                break;
                        int timeout_ms = timeout_ns / 1000000;

                        int ret =
                            poll(&pfd, 1, timeout_ms > 0 ? timeout_ms : 1);
                        if (ret <= 0 || !(pfd.revents & POLLIN))
                                continue;

                        uint8_t recv_buf[4096];
                        struct sockaddr_storage from_addr;
                        socklen_t from_addr_len = sizeof(from_addr);
                        ssize_t n =
                            net_recv_ip_raw(sock, recv_buf, sizeof(recv_buf),
                                            &from_addr, &from_addr_len);
                        if (n <= 0)
                                continue;

                        int hlen = 0;
                        if (config->family == AF_INET) {
                                struct ip *ip_hdr = (struct ip *)recv_buf;
                                hlen = ip_hdr->ip_hl << 2;
                        }

                        if (n < (ssize_t)(hlen + sizeof(struct tcphdr)))
                                continue;

                        struct tcphdr *r_tcph =
                            (struct tcphdr *)(recv_buf + hlen);

                        if (r_tcph->th_dport != htons(sport) ||
                            r_tcph->th_sport != htons(config->port)) {
                                continue;
                        }

                        uint64_t recv_time = get_time_ns();
                        uint64_t rtt = time_diff_ns(send_time, recv_time);

                        if (!config->quiet) {
                                char time_buf[64];
                                format_time(rtt, "ms", time_buf,
                                            sizeof(time_buf));

                                if ((r_tcph->th_flags & TH_SYN) &&
                                    (r_tcph->th_flags & TH_ACK)) {
                                        printf("Reply from %s:%u (SYN-ACK) "
                                               "time=%s\n",
                                               target_str, config->port,
                                               time_buf);
                                        received++;
                                        replied = true;
                                        break;
                                } else if (r_tcph->th_flags & TH_RST) {
                                        printf(
                                            "Reply from %s:%u (RST) time=%s\n",
                                            target_str, config->port, time_buf);
                                        received++;
                                        replied = true;
                                        break;
                                }
                        } else {
                                if ((r_tcph->th_flags & TH_SYN) &&
                                    (r_tcph->th_flags & TH_ACK)) {
                                        received++;
                                        replied = true;
                                        break;
                                } else if (r_tcph->th_flags & TH_RST) {
                                        received++;
                                        replied = true;
                                        break;
                                }
                        }
                }

                if (!replied && !config->quiet) {
                        printf("Timeout waiting for reply from %s:%u\n",
                               target_str, config->port);
                }

                seq++;

                if (keep_running &&
                    (config->count == 0 || sent < config->count)) {
                        uint64_t current = get_time_ns();
                        uint64_t next_send_time =
                            send_time + config->interval_ns;
                        if (current < next_send_time) {
                                usleep((next_send_time - current) / 1000);
                        }
                }
        }

        net_close_raw_socket(sock);

        if (!config->quiet) {
                printf("\n--- %s:%u tcping statistics ---\n", target_str,
                       config->port);
                printf("%u packets transmitted, %u packets received, %d%% "
                       "packet loss\n",
                       sent, received,
                       sent == 0 ? 0 : ((sent - received) * 100) / sent);
        }

        return (received > 0) ? 0 : 1;
}
