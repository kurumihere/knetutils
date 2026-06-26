/***************************************************************************
 * ping.c -- ICMP ping utility logic                                       *
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

#include "ping.h"
#include "net.h"
#include "utils.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/icmp6.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <unistd.h>

static volatile sig_atomic_t keep_running = 1;

static void
handle_sigint(int sig)
{
        (void)sig;
        keep_running = 0;
}

typedef struct {
        u_short pid;
        u_short seq;
        u_int sent;
        u_int received;
        u_int64_t start_time;

        u_int64_t rtt_min;
        u_int64_t rtt_max;
        u_int64_t rtt_sum;
        u_int64_t rtt_sum_us;
        u_int64_t rtt_sum_squares_us;
        u_int64_t rtt_last;

        int icmp_req_type;
        int icmp_rep_type;

        net_socket_t *sock;
        bool is_dgram;

        u_char *packet;
        size_t header_size;
        u_int total_len;

        char target_str[INET6_ADDRSTRLEN];
} ping_state_t;

static u_int64_t
integer_sqrt(u_int64_t n)
{
        u_int64_t root = 0;
        u_int64_t bit = 1ULL << 62;

        while (bit > n)
                bit >>= 2;

        while (bit != 0) {
                if (n >= root + bit) {
                        n -= root + bit;
                        root = (root >> 1) + bit;
                } else {
                        root >>= 1;
                }
                bit >>= 2;
        }
        return root;
}

static void
update_ping_stats(ping_state_t *st, u_int64_t rtt)
{
        u_int64_t rtt_us;

        if (st->rtt_min == 0 || rtt < st->rtt_min)
                st->rtt_min = rtt;
        if (rtt > st->rtt_max)
                st->rtt_max = rtt;
        st->rtt_sum += rtt;
        rtt_us = rtt / 1000;
        st->rtt_sum_us += rtt_us;
        st->rtt_sum_squares_us += rtt_us * rtt_us;
        st->rtt_last = rtt;
}

static void
print_ping_reply(const ping_config_t *config, u_int64_t rtt, ssize_t n,
                 int hlen, const char *src_str, u_short r_seq, int ttl)
{
        char time_buf[64] = "N/A";

        if (config->quiet)
                return;

        if (config->cisco_style) {
                printf("!");
                fflush(stdout);
                return;
        }
        if (config->payload_size >= 8) {
                format_time(rtt, config->time_unit, time_buf, sizeof(time_buf));
        }

        if (ttl >= 0) {
                printf("%zd bytes from %s: icmp_seq=%u ttl=%d time=%s\n",
                       n - hlen, src_str, ntohs(r_seq), ttl, time_buf);
        } else {
                printf("%zd bytes from %s: icmp_seq=%u time=%s\n", n - hlen,
                       src_str, ntohs(r_seq), time_buf);
        }
}

/*
 *		S E N D _ P I N G _ R E Q U E S T
 *
 * Construct and transmit an ICMP Echo Request packet.
 * For IPv4, the packet ID and Sequence are packed into the ICMP header, and the
 * payload optionally contains a high-resolution 64-bit timestamp. A software
 * checksum is computed. For IPv6, the ICMPv6 header is used and the kernel
 * computes the checksum automatically.
 */
static void
send_ping_request(const ping_config_t *config, ping_state_t *st)
{
        if (config->family == AF_INET) {
                struct icmp *icp = (struct icmp *)st->packet;
                u_int64_t *ts;

                icp->icmp_type = st->icmp_req_type;
                icp->icmp_code = 0;
                icp->icmp_id = htons(st->pid);
                icp->icmp_seq = htons(st->seq);
                if (config->payload_size >= 8) {
                        ts = (u_int64_t *)(st->packet + st->header_size);
                        *ts = get_time_ns();
                }
                icp->icmp_cksum = 0;
                icp->icmp_cksum = net_checksum(st->packet, st->total_len);
        } else {
                struct icmp6_hdr *icp = (struct icmp6_hdr *)st->packet;
                u_int64_t *ts;

                icp->icmp6_type = st->icmp_req_type;
                icp->icmp6_code = 0;
                icp->icmp6_id = htons(st->pid);
                icp->icmp6_seq = htons(st->seq);
                if (config->payload_size >= 8) {
                        ts = (u_int64_t *)(st->packet + st->header_size);
                        *ts = get_time_ns();
                }
                icp->icmp6_cksum = 0;
        }

        if (config->flood && !config->quiet) {
                printf(".");
                fflush(stdout);
        }

        if (net_send_icmp_packet(st->sock, st->packet, st->total_len,
                                 (struct sockaddr *)&config->target_addr,
                                 config->target_addr_len) < 0) {
                log_err("Failed to send ICMP packet");
        }
        st->sent++;
}

/*
 *		R E C V _ P I N G _ R E P L Y
 *
 * Listen for and process incoming ICMP Echo Reply packets.
 * Uses poll() with a calculated timeout to wait for incoming data. Upon
 * receiving a packet, we inspect the IP header (for IPv4) to locate the inner
 * ICMP message, verify the ICMP Type, ID, and Sequence numbers, and calculate
 * the Round Trip Time (RTT).
 */
static bool
recv_ping_reply(const ping_config_t *config, ping_state_t *st,
                u_int64_t wait_until, u_int64_t send_time)
{
        struct pollfd pfd;
        pfd.fd = net_get_fd(st->sock);
        pfd.events = POLLIN;

        while (get_time_ns() < wait_until && keep_running) {
                int64_t timeout_ns;
                int timeout_ms;
                int ret;
                __attribute__((aligned(8))) u_char recv_buf[4096];
                struct sockaddr_storage src_addr;
                socklen_t src_addr_len = sizeof(src_addr);
                ssize_t n;
                int hlen = 0;
                int ttl = -1;
                u_short r_id, r_seq;
                int r_type;
                u_int64_t recv_time;
                u_int64_t rtt = 0;
                char src_str[INET6_ADDRSTRLEN];

                timeout_ns = wait_until - get_time_ns();
                if (timeout_ns <= 0)
                        break;

                timeout_ms = timeout_ns / NS_PER_MS;
                ret = poll(&pfd, 1, timeout_ms > 0 ? timeout_ms : 1);
                if (ret < 0)
                        break;
                if (ret <= 0 || !(pfd.revents & POLLIN))
                        continue;

                /* Receive an incoming ICMP packet from the raw socket.  */
                n = net_recv_icmp_packet(st->sock, recv_buf, sizeof(recv_buf),
                                         &src_addr, &src_addr_len);
                if (n <= 0)
                        continue;

                /* IPv4 raw sockets return the IP header; parse length and TTL.
                 */
                if (config->family == AF_INET && !st->is_dgram) {
                        struct ip *ip_hdr = (struct ip *)recv_buf;
                        hlen = ip_hdr->ip_hl << 2;
                        ttl = ip_hdr->ip_ttl;
                }

                if (n < (ssize_t)(hlen + st->header_size))
                        continue;

                /* Extract ICMP header fields depending on address family.  */
                if (config->family == AF_INET) {
                        struct icmp *r_icp = (struct icmp *)(recv_buf + hlen);
                        r_type = r_icp->icmp_type;
                        r_id = r_icp->icmp_id;
                        r_seq = r_icp->icmp_seq;
                } else {
                        struct icmp6_hdr *r_icp =
                            (struct icmp6_hdr *)(recv_buf + hlen);
                        r_type = r_icp->icmp6_type;
                        r_id = r_icp->icmp6_id;
                        r_seq = r_icp->icmp6_seq;
                }

                /* Check if this is the reply to our request.  */
                if (r_type != st->icmp_rep_type ||
                    (!st->is_dgram && r_id != htons(st->pid)))
                        continue;

                if (!config->flood && r_seq != htons(st->seq))
                        continue;

                recv_time = get_time_ns();
                if (recv_time >= send_time)
                        rtt = time_diff_ns(send_time, recv_time);

                update_ping_stats(st, rtt);
                st->received++;

                if (config->flood && !config->quiet) {
                        printf("\b \b");
                        fflush(stdout);
                }

                if (config->audible) {
                        printf("\a");
                        fflush(stdout);
                }

                getnameinfo((struct sockaddr *)&src_addr, src_addr_len, src_str,
                            sizeof(src_str), NULL, 0, NI_NUMERICHOST);

                print_ping_reply(config, rtt, n, hlen, src_str, r_seq, ttl);
                return true;
        }
        return false;
}

static void
print_statistics(const ping_config_t *config, const ping_state_t *st)
{
        if (config->quiet)
                return;

        if (config->cisco_style) {
                printf("\nSuccess rate is %u percent (%u/%u)",
                       st->sent == 0 ? 0 : ((st->received * 100) / st->sent),
                       st->received, st->sent);
                if (st->received > 0 && config->payload_size >= 8) {
                        char min_buf[64], avg_buf[64], max_buf[64];
                        format_time(st->rtt_min, config->time_unit, min_buf,
                                    sizeof(min_buf));
                        format_time(st->rtt_sum / st->received,
                                    config->time_unit, avg_buf,
                                    sizeof(avg_buf));
                        format_time(st->rtt_max, config->time_unit, max_buf,
                                    sizeof(max_buf));
                        printf(", round-trip min/avg/max = %s/%s/%s", min_buf,
                               avg_buf, max_buf);
                }
                printf("\n");
                return;
        }

        printf("\n--- %s ping statistics ---\n", st->target_str);
        printf(
            "%u packets transmitted, %u packets received, %d%% packet loss\n",
            st->sent, st->received,
            st->sent == 0 ? 0 : ((st->sent - st->received) * 100) / st->sent);

        if (st->received > 0 && config->payload_size >= 8) {
                char min_buf[64], avg_buf[64], max_buf[64], mdev_buf[64];
                u_int64_t avg_us, variance_us, mdev_ns;

                format_time(st->rtt_min, config->time_unit, min_buf,
                            sizeof(min_buf));
                format_time(st->rtt_sum / st->received, config->time_unit,
                            avg_buf, sizeof(avg_buf));
                format_time(st->rtt_max, config->time_unit, max_buf,
                            sizeof(max_buf));
                avg_us = st->rtt_sum_us / st->received;
                variance_us =
                    (st->rtt_sum_squares_us / st->received) - (avg_us * avg_us);
                mdev_ns = integer_sqrt(variance_us) * 1000;
                format_time(mdev_ns, config->time_unit, mdev_buf,
                            sizeof(mdev_buf));
                printf("rtt min/avg/max/mdev = %s/%s/%s/%s\n", min_buf, avg_buf,
                       max_buf, mdev_buf);
        }
}

static void
init_ping_state(const ping_config_t *config, ping_state_t *st)
{
        memset(st, 0, sizeof(*st));
        st->pid = getpid() & 0xFFFF;
        st->seq = 1;
        st->start_time = get_time_ns();
        st->icmp_req_type =
            (config->family == AF_INET6) ? ICMP6_ECHO_REQUEST : ICMP_ECHO;
        st->icmp_rep_type =
            (config->family == AF_INET6) ? ICMP6_ECHO_REPLY : ICMP_ECHOREPLY;
        st->header_size = (config->family == AF_INET6)
                              ? sizeof(struct icmp6_hdr)
                              : sizeof(struct icmp);
        st->total_len = st->header_size + config->payload_size;

        getnameinfo((struct sockaddr *)&config->target_addr,
                    config->target_addr_len, st->target_str,
                    sizeof(st->target_str), NULL, 0, NI_NUMERICHOST);

        st->packet = calloc(1, st->total_len);
        if (!st->packet)
                die("Memory allocation failed for packet");

        if (config->pattern_len > 0) {
                u_char *payload = st->packet + st->header_size;
                size_t i;
                for (i = 0; i < config->payload_size; i++) {
                        payload[i] = config->pattern[i % config->pattern_len];
                }
        }
}

static void
setup_socket_options(const ping_config_t *config, net_socket_t *sock)
{
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

        if (config->ttl > 0) {
                int ttl = config->ttl;
                int level =
                    (config->family == AF_INET6) ? IPPROTO_IPV6 : IPPROTO_IP;
                int optname =
                    (config->family == AF_INET6) ? IPV6_UNICAST_HOPS : IP_TTL;
                setsockopt(net_get_fd(sock), level, optname, &ttl, sizeof(ttl));
        }

        if (config->has_tos) {
                int tos = config->tos;
                int level =
                    (config->family == AF_INET6) ? IPPROTO_IPV6 : IPPROTO_IP;
                int optname =
                    (config->family == AF_INET6) ? IPV6_TCLASS : IP_TOS;
                setsockopt(net_get_fd(sock), level, optname, &tos, sizeof(tos));
        }
}

int
ping_run(const ping_config_t *config)
{
        struct sigaction sa;
        net_socket_t *sock;
        ping_state_t st;

        memset(&sa, 0, sizeof(sa));
        sa.sa_handler = handle_sigint;
        sigaction(SIGINT, &sa, NULL);
        sigaction(SIGTERM, &sa, NULL);
        sigaction(SIGQUIT, &sa, NULL);

        sock = net_open_icmp_socket(config->family);
        if (!sock) {
                die("Failed to open ICMP socket. Are you root?");
        }

        setup_socket_options(config, sock);

        if (setgid(getgid()) != 0) {
                log_warn("Failed to drop group privileges");
        }
        if (setuid(getuid()) != 0) {
                log_warn("Failed to drop user privileges");
        }

        init_ping_state(config, &st);
        st.sock = sock;
        st.is_dgram = net_is_dgram(sock);

        if (!config->quiet) {
                if (config->cisco_style) {
                        printf("Sending %u, %u-byte ICMP Echos to %s, timeout "
                               "is %u seconds:\n",
                               config->count, config->payload_size,
                               st.target_str,
                               (unsigned int)(config->timeout_ns / NS_PER_S));
                } else {
                        printf("PING %s: %u data bytes\n", st.target_str,
                               config->payload_size);
                        if (config->pattern_len > 0) {
                                size_t i;
                                printf("PATTERN: 0x");
                                for (i = 0; i < config->pattern_len; i++) {
                                        printf("%02x", config->pattern[i]);
                                }
                                printf("\n");
                        }
                }
        }

        while (keep_running) {
                u_int64_t now;
                u_int64_t send_time;
                u_int64_t wait_until;
                bool replied;

                now = get_time_ns();
                if (config->deadline_ns > 0 &&
                    now - st.start_time >= config->deadline_ns) {
                        break;
                }

                if (config->count > 0 && st.sent >= config->count) {
                        break;
                }

                send_ping_request(config, &st);
                send_time = get_time_ns();

                wait_until = config->flood ? send_time + config->interval_ns
                                           : send_time + config->timeout_ns;
                if (config->deadline_ns > 0) {
                        u_int64_t deadline_end =
                            st.start_time + config->deadline_ns;
                        if (wait_until > deadline_end) {
                                wait_until = deadline_end;
                        }
                }

                replied = recv_ping_reply(config, &st, wait_until, send_time);

                if (!keep_running)
                        break;

                if (config->flood && config->count > 0 &&
                    st.received >= config->count)
                        break;

                if (!replied && !config->quiet && !config->flood) {
                        if (config->cisco_style) {
                                printf(".");
                                fflush(stdout);
                        } else {
                                printf("Timeout waiting for reply\n");
                        }
                }

                st.seq++;

                if (keep_running &&
                    (config->count == 0 || st.sent < config->count)) {
                        u_int64_t current = get_time_ns();
                        u_int64_t next_send_time =
                            send_time + config->interval_ns;

                        if (config->adaptive) {
                                u_int64_t adaptive_interval =
                                    st.rtt_last > 0 ? st.rtt_last
                                                    : config->interval_ns;
                                if (adaptive_interval < 2 * NS_PER_MS) {
                                        adaptive_interval = 2 * NS_PER_MS;
                                }
                                next_send_time = send_time + adaptive_interval;
                        }

                        if (!config->flood && current < next_send_time) {
                                usleep((next_send_time - current) / 1000);
                        }
                }
        }

        print_statistics(config, &st);

        net_close_raw_socket(sock);
        free(st.packet);

        return (st.received > 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
