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

static void
print_ping_reply(const ping_config_t *config, uint64_t rtt, ssize_t n, int hlen,
                 const char *src_str, uint16_t r_seq, int ttl)
{
        if (config->quiet)
                return;

        if (config->cisco_style) {
                printf("!");
                fflush(stdout);
                return;
        }

        char time_buf[64] = "N/A";
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

static uint64_t
integer_sqrt(uint64_t n)
{
        uint64_t root = 0;
        uint64_t bit = 1ULL << 62;

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

static volatile bool keep_running = true;

static void
handle_sigint(int sig)
{
        (void)sig;
        keep_running = false;
}

int
ping_run(const ping_config_t *config)
{
        struct sigaction sa;
        memset(&sa, 0, sizeof(sa));
        sa.sa_handler = handle_sigint;
        sigaction(SIGINT, &sa, NULL);
        sigaction(SIGTERM, &sa, NULL);
        sigaction(SIGQUIT, &sa, NULL);

        net_socket_t *sock = net_open_icmp_socket(config->family);
        if (!sock) {
                die("Failed to open ICMP socket. Are you root?");
        }
        bool is_dgram = net_is_dgram(sock);

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

        size_t header_size = (config->family == AF_INET6)
                                 ? sizeof(struct icmp6_hdr)
                                 : sizeof(struct icmp);
        uint32_t total_len = header_size + config->payload_size;

        if (!config->quiet) {
                if (config->cisco_style) {
                        printf(
                            "Sending %u, %u-byte ICMP Echos to %s, timeout is "
                            "%u seconds:\n",
                            config->count, config->payload_size, target_str,
                            (unsigned int)(config->timeout_ns / 1000000000ULL));
                } else {
                        printf("PING %s: %u data bytes\n", target_str,
                               config->payload_size);
                        if (config->pattern_len > 0) {
                                printf("PATTERN: 0x");
                                for (size_t i = 0; i < config->pattern_len;
                                     i++) {
                                        printf("%02x", config->pattern[i]);
                                }
                                printf("\n");
                        }
                }
        }

        uint16_t pid = getpid() & 0xFFFF;
        uint32_t sent = 0;
        uint32_t received = 0;
        uint16_t seq = 1;

        uint64_t rtt_min = 0, rtt_max = 0, rtt_sum = 0;
        uint64_t rtt_sum_us = 0, rtt_sum_squares_us = 0;

        struct pollfd pfd;
        pfd.fd = net_get_fd(sock);
        pfd.events = POLLIN;

        int icmp_type_req =
            (config->family == AF_INET6) ? ICMP6_ECHO_REQUEST : ICMP_ECHO;
        int icmp_type_rep =
            (config->family == AF_INET6) ? ICMP6_ECHO_REPLY : ICMP_ECHOREPLY;

        uint8_t *packet = calloc(1, total_len);
        if (!packet)
                die("Memory allocation failed");

        if (config->pattern_len > 0) {
                uint8_t *payload = packet + header_size;
                for (size_t i = 0; i < config->payload_size; i++) {
                        payload[i] = config->pattern[i % config->pattern_len];
                }
        }

        uint64_t ping_start_time = get_time_ns();

        while (keep_running) {
                uint64_t loop_now = get_time_ns();
                if (config->deadline_ns > 0 &&
                    loop_now - ping_start_time >= config->deadline_ns) {
                        break;
                }

                if (config->count > 0 && sent >= config->count) {
                        break;
                }

                if (config->family == AF_INET) {
                        struct icmp *icp = (struct icmp *)packet;
                        icp->icmp_type = icmp_type_req;
                        icp->icmp_code = 0;
                        icp->icmp_id = htons(pid);
                        icp->icmp_seq = htons(seq);
                        if (config->payload_size >= 8) {
                                uint64_t *timestamp =
                                    (uint64_t *)(packet + header_size);
                                *timestamp = get_time_ns();
                        }
                        icp->icmp_cksum = 0;
                        icp->icmp_cksum = net_checksum(packet, total_len);
                } else {
                        struct icmp6_hdr *icp = (struct icmp6_hdr *)packet;
                        icp->icmp6_type = icmp_type_req;
                        icp->icmp6_code = 0;
                        icp->icmp6_id = htons(pid);
                        icp->icmp6_seq = htons(seq);
                        if (config->payload_size >= 8) {
                                uint64_t *timestamp =
                                    (uint64_t *)(packet + header_size);
                                *timestamp = get_time_ns();
                        }
                        icp->icmp6_cksum = 0;
                }

                uint64_t send_time = get_time_ns();
                if (config->flood) {
                        printf(".");
                        fflush(stdout);
                }

                if (net_send_icmp_packet(
                        sock, packet, total_len,
                        (struct sockaddr *)&config->target_addr,
                        config->target_addr_len) < 0) {
                        log_err("Failed to send ICMP packet");
                }
                sent++;

                uint64_t now = get_time_ns();
                uint64_t next_send = send_time + config->interval_ns;
                uint64_t wait_until =
                    config->flood ? next_send : (now + config->timeout_ns);

                if (config->deadline_ns > 0) {
                        uint64_t deadline_end =
                            ping_start_time + config->deadline_ns;
                        if (wait_until > deadline_end) {
                                wait_until = deadline_end;
                        }
                }

                uint64_t rtt_last = 0;
                bool got_reply = false;
                bool replied = false;
                while (get_time_ns() < wait_until && keep_running) {
                        int64_t timeout_ns = wait_until - get_time_ns();
                        if (timeout_ns <= 0)
                                break;
                        int timeout_ms = timeout_ns / 1000000;

                        int ret =
                            poll(&pfd, 1, timeout_ms > 0 ? timeout_ms : 1);
                        if (ret < 0) {
                                break;
                        }

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

                        int hlen = 0;
                        int ttl = -1;
                        if (config->family == AF_INET && !is_dgram) {
                                struct ip *ip_hdr = (struct ip *)recv_buf;
                                hlen = ip_hdr->ip_hl << 2;
                                ttl = ip_hdr->ip_ttl;
                        }

                        if (n < (ssize_t)(hlen + header_size))
                                continue;

                        uint16_t r_id, r_seq;
                        int r_type;
                        if (config->family == AF_INET) {
                                struct icmp *r_icp =
                                    (struct icmp *)(recv_buf + hlen);
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

                        if (r_type != icmp_type_rep ||
                            (!is_dgram && r_id != htons(pid))) {
                                continue;
                        }

                        if (config->flood) {
                                uint64_t recv_time = get_time_ns();
                                uint64_t rtt =
                                    time_diff_ns(send_time, recv_time);

                                if (rtt_min == 0 || rtt < rtt_min)
                                        rtt_min = rtt;
                                if (rtt > rtt_max)
                                        rtt_max = rtt;
                                rtt_sum += rtt;
                                uint64_t rtt_us = rtt / 1000;
                                rtt_sum_us += rtt_us;
                                rtt_sum_squares_us += rtt_us * rtt_us;
                                rtt_last = rtt;

                                received++;
                                got_reply = true;
                                replied = true;
                                printf("\b \b");
                                if (config->audible) {
                                        printf("\a");
                                }
                                fflush(stdout);

                                if (config->count > 0 &&
                                    received >= config->count) {
                                        keep_running = false;
                                }
                                break;
                        }

                        if (r_seq != htons(seq)) {
                                continue;
                        }

                        uint64_t recv_time = get_time_ns();
                        uint64_t rtt = 0;

                        if (recv_time >= send_time) {
                                rtt = time_diff_ns(send_time, recv_time);
                        }

                        if (rtt_min == 0 || rtt < rtt_min)
                                rtt_min = rtt;
                        if (rtt > rtt_max)
                                rtt_max = rtt;
                        rtt_sum += rtt;
                        uint64_t rtt_us = rtt / 1000;
                        rtt_sum_us += rtt_us;
                        rtt_sum_squares_us += rtt_us * rtt_us;
                        rtt_last = rtt;

                        char src_str[INET6_ADDRSTRLEN];
                        getnameinfo((struct sockaddr *)&src_addr, src_addr_len,
                                    src_str, sizeof(src_str), NULL, 0,
                                    NI_NUMERICHOST);

                        print_ping_reply(config, rtt, n, hlen, src_str, r_seq,
                                         ttl);

                        received++;
                        got_reply = true;
                        replied = true;
                        if (config->audible) {
                                printf("\a");
                                fflush(stdout);
                        }
                        break;
                }

                if (!keep_running)
                        break;

                if (!replied && !config->quiet && !config->flood) {
                        if (config->cisco_style) {
                                printf(".");
                                fflush(stdout);
                        } else {
                                printf("Timeout waiting for reply\n");
                        }
                }

                seq++;

                if (keep_running &&
                    (config->count == 0 || sent < config->count)) {
                        uint64_t current = get_time_ns();
                        uint64_t next_send_time =
                            send_time + config->interval_ns;

                        if (config->adaptive) {
                                uint64_t adaptive_interval =
                                    rtt_last > 0 ? rtt_last
                                                 : config->interval_ns;
                                if (adaptive_interval < 2000000ULL) {
                                        adaptive_interval = 2000000ULL;
                                }
                                next_send_time = send_time + adaptive_interval;
                        }

                        if (config->flood && got_reply) {
                        } else if (current < next_send_time) {
                                usleep((next_send_time - current) / 1000);
                        }
                }
        }

        net_close_raw_socket(sock);

        if (!config->quiet) {
                if (config->cisco_style) {
                        printf("\nSuccess rate is %u percent (%u/%u)",
                               sent == 0 ? 0 : ((received * 100) / sent),
                               received, sent);
                        if (received > 0 && config->payload_size >= 8) {
                                char min_buf[64], avg_buf[64], max_buf[64];
                                format_time(rtt_min, config->time_unit, min_buf,
                                            sizeof(min_buf));
                                format_time(rtt_sum / received,
                                            config->time_unit, avg_buf,
                                            sizeof(avg_buf));
                                format_time(rtt_max, config->time_unit, max_buf,
                                            sizeof(max_buf));
                                printf(", round-trip min/avg/max = %s/%s/%s",
                                       min_buf, avg_buf, max_buf);
                        }
                        printf("\n");
                } else {
                        printf("\n--- %s ping statistics ---\n", target_str);
                        printf("%u packets transmitted, %u packets received, "
                               "%d%% packet loss\n",
                               sent, received,
                               sent == 0 ? 0
                                         : ((sent - received) * 100) / sent);

                        if (received > 0 && config->payload_size >= 8) {
                                char min_buf[64], avg_buf[64], max_buf[64],
                                    mdev_buf[64];
                                format_time(rtt_min, config->time_unit, min_buf,
                                            sizeof(min_buf));
                                format_time(rtt_sum / received,
                                            config->time_unit, avg_buf,
                                            sizeof(avg_buf));
                                format_time(rtt_max, config->time_unit, max_buf,
                                            sizeof(max_buf));
                                uint64_t avg_us = rtt_sum_us / received;
                                uint64_t variance_us =
                                    (rtt_sum_squares_us / received) -
                                    (avg_us * avg_us);
                                uint64_t mdev_ns =
                                    integer_sqrt(variance_us) * 1000;
                                format_time(mdev_ns, config->time_unit,
                                            mdev_buf, sizeof(mdev_buf));
                                printf("rtt min/avg/max/mdev = %s/%s/%s/%s\n",
                                       min_buf, avg_buf, max_buf, mdev_buf);
                        }
                }
        }

        free(packet);
        return (received > 0) ? 0 : 1;
}
