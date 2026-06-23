#include "ping.h"
#include "net.h"
#include "utils.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/ip.h>
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

int
ping_run(const ping_config_t *config)
{
        signal(SIGINT, handle_sigint);

        net_socket_t *sock = net_open_icmp_socket();
        if (!sock) {
                die("Failed to open ICMP socket. Are you root?");
        }

        if (config->ttl > 0) {
                int ttl = config->ttl;
                setsockopt(net_get_fd(sock), IPPROTO_IP, IP_TTL, &ttl,
                           sizeof(ttl));
        }

        struct in_addr target_in = {.s_addr = config->target_ip};
        char target_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &target_in, target_str, sizeof(target_str));

        uint32_t total_len = sizeof(struct icmp) + config->payload_size;

        if (!config->quiet) {
                printf("PING %s: %u data bytes\n", target_str,
                       config->payload_size);
        }

        uint16_t pid = getpid() & 0xFFFF;
        uint32_t sent = 0;
        uint32_t received = 0;
        uint16_t seq = 1;

        uint64_t rtt_min = 0, rtt_max = 0, rtt_sum = 0;

        struct pollfd pfd;
        pfd.fd = net_get_fd(sock);
        pfd.events = POLLIN;

        uint64_t next_send = get_time_ns();

        while (keep_running) {
                if (config->count > 0 && sent >= config->count) {
                        break;
                }

                uint8_t *packet = calloc(1, total_len);
                if (!packet)
                        die("Memory allocation failed");

                struct icmp *icp = (struct icmp *)packet;
                icp->icmp_type = ICMP_ECHO;
                icp->icmp_code = 0;
                icp->icmp_id = htons(pid);
                icp->icmp_seq = htons(seq);

                if (config->payload_size >= 8) {
                        uint64_t *timestamp =
                            (uint64_t *)(packet + sizeof(struct icmp));
                        *timestamp = get_time_ns();
                }

                icp->icmp_cksum = icmp_checksum(packet, total_len);

                if (net_send_icmp_packet(sock, packet, total_len,
                                         config->target_ip) < 0) {
                        log_err("Failed to send ICMP packet: %s",
                                strerror(errno));
                } else {
                        sent++;
                }
                free(packet);

                next_send += config->interval_ns;
                uint64_t expire = get_time_ns() + config->timeout_ns;
                bool replied = false;

                while (get_time_ns() < expire && keep_running) {
                        int64_t timeout_ns = expire - get_time_ns();
                        if (timeout_ns <= 0)
                                break;
                        int timeout_ms = timeout_ns / 1000000;

                        int ret =
                            poll(&pfd, 1, timeout_ms > 0 ? timeout_ms : 1);
                        if (ret < 0) {
                                break;
                        }

                        if (ret > 0 && (pfd.revents & POLLIN)) {
                                uint8_t recv_buf[4096];
                                uint32_t src_ip;
                                ssize_t n = net_recv_icmp_packet(
                                    sock, recv_buf, sizeof(recv_buf), &src_ip);
                                if (n <= 0)
                                        continue;

                                struct ip *ip_hdr = (struct ip *)recv_buf;
                                int hlen = ip_hdr->ip_hl << 2;

                                if (n < (ssize_t)(hlen + 8))
                                        continue;

                                struct icmp *r_icp =
                                    (struct icmp *)(recv_buf + hlen);
                                if (r_icp->icmp_type == ICMP_ECHOREPLY &&
                                    r_icp->icmp_id == htons(pid) &&
                                    r_icp->icmp_seq == htons(seq)) {
                                        uint64_t recv_time = get_time_ns();
                                        uint64_t rtt = 0;

                                        if (config->payload_size >= 8 &&
                                            n >= (ssize_t)(hlen +
                                                           sizeof(struct icmp) +
                                                           8)) {
                                                uint64_t *orig_timestamp =
                                                    (uint64_t
                                                         *)(recv_buf + hlen +
                                                            sizeof(
                                                                struct icmp));
                                                rtt =
                                                    recv_time - *orig_timestamp;
                                        }

                                        if (received == 0) {
                                                rtt_min = rtt_max = rtt;
                                        } else {
                                                if (rtt < rtt_min)
                                                        rtt_min = rtt;
                                                if (rtt > rtt_max)
                                                        rtt_max = rtt;
                                        }
                                        rtt_sum += rtt;

                                        struct in_addr src_in = {.s_addr =
                                                                     src_ip};
                                        char src_str[INET_ADDRSTRLEN];
                                        inet_ntop(AF_INET, &src_in, src_str,
                                                  sizeof(src_str));

                                        if (!config->quiet) {
                                                char time_buf[64] = "N/A";
                                                if (config->payload_size >= 8) {
                                                        format_time(
                                                            rtt,
                                                            config->time_unit,
                                                            time_buf,
                                                            sizeof(time_buf));
                                                }
                                                printf("%zd bytes from %s: "
                                                       "icmp_seq=%u ttl=%d "
                                                       "time=%s\n",
                                                       n - hlen, src_str,
                                                       ntohs(r_icp->icmp_seq),
                                                       ip_hdr->ip_ttl,
                                                       time_buf);
                                        }

                                        received++;
                                        replied = true;
                                        break;
                                }
                        }
                }

                if (!keep_running)
                        break;

                if (!replied && !config->quiet) {
                        printf("Timeout waiting for reply\n");
                }

                seq++;

                if (keep_running && sent < config->count) {
                        uint64_t now = get_time_ns();
                        if (now < next_send) {
                                usleep((next_send - now) / 1000);
                        }
                }
        }

        net_close_raw_socket(sock);

        printf("\n--- %s ping statistics ---\n", target_str);
        printf(
            "%u packets transmitted, %u packets received, %d%% packet loss\n",
            sent, received, sent == 0 ? 0 : ((sent - received) * 100) / sent);

        if (received > 0 && config->payload_size >= 8) {
                char min_buf[64], avg_buf[64], max_buf[64];
                format_time(rtt_min, config->time_unit, min_buf,
                            sizeof(min_buf));
                format_time(rtt_sum / received, config->time_unit, avg_buf,
                            sizeof(avg_buf));
                format_time(rtt_max, config->time_unit, max_buf,
                            sizeof(max_buf));
                printf("rtt min/avg/max = %s/%s/%s\n", min_buf, avg_buf,
                       max_buf);
        }

        return (received > 0) ? 0 : 1;
}
