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

        struct in_addr target_in = {.s_addr = config->target_ip};
        char target_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &target_in, target_str, sizeof(target_str));

        if (!config->quiet) {
                printf("PING %s: 64 data bytes\n", target_str);
        }

        uint16_t pid = getpid() & 0xFFFF;
        uint32_t sent = 0;
        uint32_t received = 0;
        uint16_t seq = 1;

        struct pollfd pfd;
        pfd.fd = net_get_fd(sock);
        pfd.events = POLLIN;

        while (keep_running) {
                if (config->count > 0 && sent >= config->count) {
                        break;
                }

                uint8_t packet[64];
                memset(packet, 0, sizeof(packet));
                struct icmp *icp = (struct icmp *)packet;
                icp->icmp_type = ICMP_ECHO;
                icp->icmp_code = 0;
                icp->icmp_id = htons(pid);
                icp->icmp_seq = htons(seq);

                uint64_t *timestamp = (uint64_t *)(packet + 8);
                *timestamp = get_time_ns();

                icp->icmp_cksum = icmp_checksum(packet, sizeof(packet));

                if (net_send_icmp_packet(sock, packet, sizeof(packet),
                                         config->target_ip) < 0) {
                        log_err("Failed to send ICMP packet: %s",
                                strerror(errno));
                } else {
                        sent++;
                }

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
                                        uint64_t *orig_timestamp =
                                            (uint64_t *)(recv_buf + hlen + 8);
                                        uint64_t rtt =
                                            recv_time - *orig_timestamp;

                                        struct in_addr src_in = {.s_addr =
                                                                     src_ip};
                                        char src_str[INET_ADDRSTRLEN];
                                        inet_ntop(AF_INET, &src_in, src_str,
                                                  sizeof(src_str));

                                        if (!config->quiet) {
                                                char time_buf[64];
                                                printf("%zd bytes from %s: "
                                                       "icmp_seq=%u ttl=%d "
                                                       "time=%s\n",
                                                       n - hlen, src_str,
                                                       ntohs(r_icp->icmp_seq),
                                                       ip_hdr->ip_ttl,
                                                       format_time(
                                                           rtt,
                                                           config->time_unit,
                                                           time_buf,
                                                           sizeof(time_buf)));
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

                if (keep_running && sent < config->count) {
                        usleep(config->interval_ns / 1000);
                }
        }

        net_close_raw_socket(sock);

        printf("\n--- %s ping statistics ---\n", target_str);
        printf(
            "%u packets transmitted, %u packets received, %d%% packet loss\n",
            sent, received, sent == 0 ? 0 : ((sent - received) * 100) / sent);

        return (received > 0) ? 0 : 1;
}
