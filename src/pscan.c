/***************************************************************************
 * pscan.c -- Port scanner utility logic                                   *
 *                                                                         *
 *********************IMPORTANT KNETUTILS LICENSE TERMS*********************
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

#include "cli.h"
#include "net.h"
#include "tools.h"
#include "utils.h"
#include <errno.h>
#include <netdb.h>
#include <netinet/icmp6.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* --- Configuration Struct --- */
typedef struct {
    u_short start_port;
    u_short end_port;
    u_int64_t timeout_ns;
    struct sockaddr_storage target_addr;
    socklen_t target_addr_len;
    int family;
    const char *bind_iface;
    u_int rate_limit;
    bool udp;
    bool randomize;
    bool json_output;
    bool banner_grab;
    bool os_fingerprint;
} pscan_config_t;

typedef struct {
    net_socket_t *sock;
    int send_fd;
    struct sockaddr_storage src_addr;
    socklen_t src_addr_len;
    char target_str[INET6_ADDRSTRLEN];
    u_short sport;
    u_int64_t *sent_time;
    u_int64_t *open_rtt;
    char (*banners)[128];
    char (*os_guesses)[32];
    bool *open_ports;
    bool *closed_ports;
} pscan_state_t;

static const char *
guess_os_from_ttl(u_char ttl, u_short win)
{
    if (ttl == 0)
        return "Unknown";

    if (ttl <= 64) {
        if (win == 5840 || win == 29200 || win == 65535)
            return "Linux";
        if (win == 65535 || win == 4128)
            return "macOS/iOS";
        if (win == 16384)
            return "OpenBSD";
        if (win == 65228)
            return "FreeBSD";
        return "Linux/Unix/macOS (Generic TTL=64)";
    }

    if (ttl <= 128) {
        if (win == 8192 || win == 64240 || win == 65535)
            return "Windows (Modern)";
        if (win == 16384 || win == 65535)
            return "Windows (Legacy)";
        return "Windows (Generic TTL=128)";
    }

    if (win == 4128 || win == 8760)
        return "Cisco Router/Switch";
    if (win == 65535)
        return "Solaris/AIX";
    return "Network Device/Legacy (Generic TTL=255)";
}

static void
init_pscan_state(const pscan_config_t *config, pscan_state_t *st)
{
    getnameinfo((struct sockaddr *)&config->target_addr,
                config->target_addr_len, st->target_str, sizeof(st->target_str),
                NULL, 0, NI_NUMERICHOST);

    st->src_addr_len = sizeof(st->src_addr);
    if (!get_source_ip_for(&config->target_addr, config->target_addr_len,
                           &st->src_addr, &st->src_addr_len)) {
        die("Failed to determine source IP for target");
    }

    st->sport = 1024 + (getpid() % 64000);
}

static void
grab_banner(const pscan_config_t *config, u_short port, char *banner_buf,
            size_t banner_len)
{
    int fd;
    struct timeval tv;
    struct sockaddr_storage dst;
    ssize_t n;
    ssize_t i;
    const char *http_req = "GET / HTTP/1.0\r\n\r\n";

    fd = socket(config->target_addr.ss_family, SOCK_STREAM, 0);
    if (fd < 0)
        goto out;

    tv.tv_sec = 0;
    tv.tv_usec = 500000;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    memcpy(&dst, &config->target_addr, config->target_addr_len);
    if (dst.ss_family == AF_INET) {
        ((struct sockaddr_in *)&dst)->sin_port = htons(port);
    } else {
        ((struct sockaddr_in6 *)&dst)->sin6_port = htons(port);
    }

    if (connect(fd, (struct sockaddr *)&dst, config->target_addr_len) != 0)
        goto err_close;

    n = recv(fd, banner_buf, banner_len - 1, 0);
    if (n <= 0) {
        send(fd, http_req, strlen(http_req), 0);
        n = recv(fd, banner_buf, banner_len - 1, 0);
    }
    if (n > 0 && n < 128) {
        banner_buf[n] = '\0';
        for (i = 0; i < n; i++) {
            if (banner_buf[i] == '\r' || banner_buf[i] == '\n') {
                banner_buf[i] = '\0';
                break;
            }
            if (banner_buf[i] < 32 || banner_buf[i] > 126) {
                banner_buf[i] = '.';
            }
        }
    }

err_close:
    close(fd);
out:
    return;
}

static void
send_probe(const pscan_config_t *config, pscan_state_t *st, u_short dport)
{
    struct sockaddr_storage dst;
    struct tcphdr tcph;
    u_char csum_buf[1024];
    int csum_len;

    csum_len = 0;

    if (config->udp) {
        memcpy(&dst, &config->target_addr, config->target_addr_len);
        if (dst.ss_family == AF_INET) {
            ((struct sockaddr_in *)&dst)->sin_port = htons(dport);
        } else {
            ((struct sockaddr_in6 *)&dst)->sin6_port = htons(dport);
        }
        if (dport >= config->start_port && dport <= config->end_port) {
            st->sent_time[dport - config->start_port] = get_time_ns();
        }
        sendto(st->send_fd, NULL, 0, 0, (struct sockaddr *)&dst,
               config->target_addr_len);
        goto out;
    }

    memset(&tcph, 0, sizeof(tcph));
    tcph.th_sport = htons(st->sport);
    tcph.th_dport = htons(dport);
    tcph.th_seq = htonl(1000 + dport);
    tcph.th_ack = 0;
    tcph.th_off = 5;

    tcph.th_flags = TH_SYN;
    tcph.th_win = htons(64240);
    tcph.th_sum = 0;

    if (config->target_addr.ss_family == AF_INET) {
        struct ipv4_pseudo_header psh;
        psh.src_addr = ((struct sockaddr_in *)&st->src_addr)->sin_addr.s_addr;
        psh.dst_addr =
            ((struct sockaddr_in *)&config->target_addr)->sin_addr.s_addr;
        psh.zero = 0;
        psh.protocol = IPPROTO_TCP;
        psh.tcp_length = htons(sizeof(struct tcphdr));

        memcpy(csum_buf, &psh, sizeof(psh));
        csum_len += sizeof(psh);
    } else {
        struct ipv6_pseudo_header psh;
        psh.src_addr = ((struct sockaddr_in6 *)&st->src_addr)->sin6_addr;
        psh.dst_addr = ((struct sockaddr_in6 *)&config->target_addr)->sin6_addr;
        psh.tcp_length = htonl(sizeof(struct tcphdr));
        memset(psh.zero, 0, 3);
        psh.next_header = IPPROTO_TCP;

        memcpy(csum_buf, &psh, sizeof(psh));
        csum_len += sizeof(psh);
    }

    memcpy(csum_buf + csum_len, &tcph, sizeof(tcph));
    csum_len += sizeof(tcph);

    tcph.th_sum = calculate_checksum(csum_buf, csum_len);

    memcpy(&dst, &config->target_addr, config->target_addr_len);
    if (dst.ss_family == AF_INET) {
        ((struct sockaddr_in *)&dst)->sin_port = htons(dport);
    } else {
        ((struct sockaddr_in6 *)&dst)->sin6_port = htons(dport);
    }

    if (send_ip_raw(st->sock, &tcph, sizeof(tcph), (struct sockaddr *)&dst,
                    config->target_addr_len) < 0) {
    }
    if (dport >= config->start_port && dport <= config->end_port) {
        st->sent_time[dport - config->start_port] = get_time_ns();
    }
out:
    return;
}

static void
process_packet(const pscan_config_t *config, pscan_state_t *st, u_char *buf,
               ssize_t len, const struct sockaddr_storage *src)
{
    char src_str[INET6_ADDRSTRLEN];
    struct tcphdr *tcph;
    u_char ttl;
    int port;
    u_int64_t rtt;
    char time_buf[64];
    const char *os_guess;
    u_short idx;

    if (config->udp) {
        if (config->target_addr.ss_family == AF_INET) {
            struct ip *iph;
            int hlen;
            struct icmp *icmph;
            struct ip *orig_iph;
            int orig_iph_len;
            struct udphdr *udph;
            int port;

            iph = (struct ip *)buf;
            hlen = iph->ip_hl << 2;
            if (len < hlen + 8)
                goto out;
            icmph = (struct icmp *)(buf + hlen);

            if (icmph->icmp_type == ICMP_UNREACH &&
                icmph->icmp_code == ICMP_UNREACH_PORT) {
                orig_iph = (struct ip *)&icmph->icmp_data;
                orig_iph_len = orig_iph->ip_hl << 2;
                if (len < hlen + 8 + orig_iph_len + 8)
                    goto out;
                udph = (struct udphdr *)((u_char *)orig_iph + orig_iph_len);
                port = ntohs(udph->uh_dport);
                if (port >= config->start_port && port <= config->end_port) {
                    st->closed_ports[port - config->start_port] = true;
                }
            }
        } else {
            struct icmp6_hdr *icmph;
            struct ip6_hdr *orig_iph;
            struct udphdr *udph;
            int port;

            if (len < 8)
                goto out;
            icmph = (struct icmp6_hdr *)buf;
            if (icmph->icmp6_type == ICMP6_DST_UNREACH &&
                icmph->icmp6_code == ICMP6_DST_UNREACH_NOPORT) {
                if (len < 8 + 40 + 8)
                    goto out;
                orig_iph = (struct ip6_hdr *)(buf + 8);
                udph = (struct udphdr *)((u_char *)orig_iph + 40);
                port = ntohs(udph->uh_dport);
                if (port >= config->start_port && port <= config->end_port) {
                    st->closed_ports[port - config->start_port] = true;
                }
            }
        }
        goto out;
    }

    if (len < (ssize_t)sizeof(struct tcphdr))
        goto out;

    getnameinfo((struct sockaddr *)src,
                src->ss_family == AF_INET ? sizeof(struct sockaddr_in)
                                          : sizeof(struct sockaddr_in6),
                src_str, sizeof(src_str), NULL, 0, NI_NUMERICHOST);

    if (strcmp(src_str, st->target_str) != 0)
        goto out;

    ttl = 0;
    if (src->ss_family == AF_INET) {
        struct ip *iph;
        int ip_hlen;

        iph = (struct ip *)buf;
        ip_hlen = iph->ip_hl << 2;
        if (len < ip_hlen + (ssize_t)sizeof(struct tcphdr))
            goto out;
        tcph = (struct tcphdr *)(buf + ip_hlen);
        ttl = iph->ip_ttl;
    } else {
        tcph = (struct tcphdr *)buf;
    }

    if (ntohs(tcph->th_dport) != st->sport)
        goto out;

    port = ntohs(tcph->th_sport);
    if (port < config->start_port || port > config->end_port)
        goto out;

    idx = port - config->start_port;

    if ((tcph->th_flags & TH_SYN) && (tcph->th_flags & TH_ACK)) {
        if (!st->open_ports[idx]) {
            st->open_ports[idx] = true;
            rtt = 0;
            if (st->sent_time[idx] > 0) {
                rtt = time_diff_ns(st->sent_time[idx], get_time_ns());
            }
            st->open_rtt[idx] = rtt;

            if (config->os_fingerprint && src->ss_family == AF_INET) {
                os_guess = guess_os_from_ttl(ttl, ntohs(tcph->th_win));
                strncpy(st->os_guesses[idx], os_guess,
                        sizeof(st->os_guesses[idx]) - 1);
            }

            if (!config->json_output) {
                strcpy(time_buf, "N/A");
                if (rtt > 0) {
                    format_time(rtt, NULL, time_buf, sizeof(time_buf));
                }

                printf(COLOR_BOLD COLOR_GREEN "Port %u is open" COLOR_RESET
                                              " (time=%s)",
                       port, time_buf);

                if (config->os_fingerprint && st->os_guesses[idx][0] != '\0') {
                    printf(" [OS: %s]", st->os_guesses[idx]);
                }

                printf("\n");
            }
        }
    }
out:
    return;
}

static void
drain_packets(const pscan_config_t *config, pscan_state_t *st)
{
    u_char buf[2048];
    struct sockaddr_storage src;
    socklen_t src_len;
    while (true) {
        struct pollfd pfd;
        ssize_t len;
        pfd.fd = get_socket_fd(st->sock);
        pfd.events = POLLIN;
        pfd.revents = 0;

        if (poll(&pfd, 1, 0) <= 0)
            break;

        src_len = sizeof(src);
        len = recv_ip_raw(st->sock, buf, sizeof(buf), &src, &src_len);
        if (len < 0)
            break;
        process_packet(config, st, buf, len, &src);
    }
}

static int
pscan_run(const pscan_config_t *config)
{
    pscan_state_t *st;
    u_int64_t last_time;
    double tokens = 1.0;
    double burst = 10.0;
    u_short port;
    u_int64_t start_wait;
    u_int num_ports;
    u_short *port_list;
    u_int i;
    u_short idx;

    st = calloc(1, sizeof(pscan_state_t));
    if (!st)
        die("Out of memory for pscan state");

    num_ports = config->end_port - config->start_port + 1;
    st->sent_time = calloc(num_ports, sizeof(*st->sent_time));
    st->open_rtt = calloc(num_ports, sizeof(*st->open_rtt));
    st->banners = calloc(num_ports, sizeof(*st->banners));
    st->os_guesses = calloc(num_ports, sizeof(*st->os_guesses));
    st->open_ports = calloc(num_ports, sizeof(*st->open_ports));
    st->closed_ports = calloc(num_ports, sizeof(*st->closed_ports));

    if (!st->sent_time || !st->open_rtt || !st->banners || !st->os_guesses ||
        !st->open_ports || !st->closed_ports) {
        die("Out of memory allocating scanner state arrays");
    }

    init_pscan_state(config, st);

    if (config->udp) {
        st->sock = open_icmp_socket(config->target_addr.ss_family);
        if (!st->sock || is_dgram(st->sock)) {
            die("UDP scan requires root for raw ICMP socket");
        }
        st->send_fd = socket(config->target_addr.ss_family, SOCK_DGRAM, 0);
        if (st->send_fd < 0) {
            die("Failed to open UDP socket");
        }
    } else {
        st->sock =
            open_ip_raw_socket(config->target_addr.ss_family, IPPROTO_TCP);
        st->send_fd = -1;
        if (!st->sock) {
            die("Failed to open raw TCP socket. Are you root?");
        }
    }

    if (config->bind_iface) {
#ifdef SO_BINDTODEVICE
        if (setsockopt(get_socket_fd(st->sock), SOL_SOCKET, SO_BINDTODEVICE,
                       config->bind_iface, strlen(config->bind_iface)) < 0) {
            die("Failed to bind to interface %s", config->bind_iface);
        }
        if (config->udp) {
            if (setsockopt(st->send_fd, SOL_SOCKET, SO_BINDTODEVICE,
                           config->bind_iface,
                           strlen(config->bind_iface)) < 0) {
                die("Failed to bind UDP socket to interface %s",
                    config->bind_iface);
            }
        }
#else
        log_warn("SO_BINDTODEVICE not supported on this platform");
#endif
    }

    if (!config->json_output) {
        log_info("Scanning %s ports %u to %u (rate: %u pps)...", st->target_str,
                 config->start_port, config->end_port, config->rate_limit);
    }

    port_list = malloc(num_ports * sizeof(u_short));
    if (!port_list)
        die("Out of memory allocating port list");
    for (i = 0; i < num_ports; i++) {
        port_list[i] = config->start_port + i;
    }

    if (config->randomize) {
        srand((unsigned int)get_time_ns());
        for (i = num_ports - 1; i > 0; i--) {
            u_int j = rand() % (i + 1);
            u_short temp = port_list[i];
            port_list[i] = port_list[j];
            port_list[j] = temp;
        }
    }

    last_time = get_time_ns();

    for (i = 0; i < num_ports; i++) {
        port = port_list[i];
        if (config->rate_limit > 0) {
            while (tokens < 1.0) {
                u_int64_t now = get_time_ns();
                u_int64_t delta_ns = now - last_time;
                last_time = now;

                tokens += (double)delta_ns * (double)config->rate_limit /
                          (double)NS_PER_S;
                if (tokens > burst) {
                    tokens = burst;
                }

                if (tokens < 1.0) {
                    drain_packets(config, st);
                    usleep(1000);
                }
            }
            tokens -= 1.0;
        }

        send_probe(config, st, port);
        drain_packets(config, st);

        if (config->rate_limit == 0) {
            usleep(100);
        }
    }

    start_wait = get_time_ns();
    while (get_time_ns() - start_wait < config->timeout_ns) {
        struct pollfd pfd = {get_socket_fd(st->sock), POLLIN, 0};
        if (poll(&pfd, 1, 100) > 0) {
            drain_packets(config, st);
        }
    }

    /* Phase 2: Grab banners for open TCP ports sequentially after scanning is
     * complete */
    if (config->banner_grab && !config->udp) {
        for (port = config->start_port; port <= config->end_port; port++) {
            idx = port - config->start_port;
            if (st->open_ports[idx]) {
                grab_banner(config, port, st->banners[idx],
                            sizeof(st->banners[idx]));
            }
        }
    }

    if (config->json_output) {
        bool first = true;
        printf("{\n");
        printf("  \"target\": \"%s\",\n", st->target_str);
        printf("  \"open_ports\": [\n");
        for (port = config->start_port; port <= config->end_port; port++) {
            idx = port - config->start_port;
            if (st->open_ports[idx] ||
                (config->udp && !st->closed_ports[idx])) {
                if (!first) {
                    printf(",\n");
                }
                first = false;
                printf("    {\n");
                printf("      \"port\": %u", port);
                if (!config->udp && st->open_rtt[idx] > 0) {
                    printf(",\n      \"rtt_ms\": %.3f",
                           (double)st->open_rtt[idx] / (double)NS_PER_MS);
                    if (config->os_fingerprint &&
                        st->os_guesses[idx][0] != '\0') {
                        printf(",\n      \"os_guess\": \"%s\"",
                               st->os_guesses[idx]);
                    }
                    if (config->banner_grab && st->banners[idx][0] != '\0') {
                        printf(",\n      \"banner\": \"%s\"\n",
                               st->banners[idx]);
                    } else {
                        printf("\n");
                    }
                } else if (config->udp) {
                    printf(",\n      \"state\": \"open|filtered\"\n");
                } else {
                    printf("\n");
                }
                printf("    }");
            }
        }
        printf("\n  ]\n");
        printf("}\n");
    } else {
        if (config->udp) {
            for (port = config->start_port; port <= config->end_port; port++) {
                idx = port - config->start_port;
                if (!st->closed_ports[idx]) {
                    printf(COLOR_BOLD COLOR_YELLOW
                           "Port %u is open|filtered" COLOR_RESET "\n",
                           port);
                }
            }
        } else if (config->banner_grab) {
            bool printed_hdr = false;
            for (port = config->start_port; port <= config->end_port; port++) {
                idx = port - config->start_port;
                if (st->open_ports[idx] && st->banners[idx][0] != '\0') {
                    if (!printed_hdr) {
                        printf("\n--- Service Banners ---\n");
                        printed_hdr = true;
                    }
                    printf("Port %u banner: %s\n", port, st->banners[idx]);
                }
            }
        }
    }

    free(port_list);
    free(st->sent_time);
    free(st->open_rtt);
    free(st->banners);
    free(st->os_guesses);
    free(st->open_ports);
    free(st->closed_ports);
    close_raw_socket(st->sock);
    if (st->send_fd >= 0) {
        close(st->send_fd);
    }
    free(st);
    return EXIT_SUCCESS;
}

static const cli_option_t pscan_options[] = {
    {'4', NULL, "use IPv4"},
    {'6', NULL, "use IPv6"},
    {'j', NULL, "output in JSON format"},
    {'O', NULL, "enable OS fingerprinting"},
    {'p', "ports", "port range to scan (e.g. 1-1024 or 80)"},
    {'R', NULL, "randomize port scanning order"},
    {'r', "rate", "max packets per second (rate limit)"},
    {'s', NULL, "service banner grabbing"},
    {'u', NULL, "use UDP scan instead of TCP SYN"},
    {'W', "timeout", "time to wait for a response, in seconds"},
    {'I', "iface/ip", "bind to a specific interface or IP address"},
    {'h', NULL, "print help and exit"},
    {0, NULL, NULL}};

static void
print_usage(const char *prog_name)
{
    cli_app_t app = {.prog_name = prog_name,
                     .usage_args = "[options] <destination>",
                     .options = pscan_options};
    cli_print_help(&app);
}

int
pscan_main(int c, char **av)
{
    pscan_config_t config;
    int ch;
    int ret = EXIT_SUCCESS;
    const char *target_ip_str;

    optind = 1;
    memset(&config, 0, sizeof(config));

    config.family = AF_UNSPEC;
    config.timeout_ns = 2 * NS_PER_S;
    config.start_port = 1;
    config.end_port = 1024;

    while ((ch = getopt(c, av, "46jOp:r:W:I:Rsuh")) != -1) {
        switch (ch) {
        case 'u':
            config.udp = true;
            break;
        case 's':
            config.banner_grab = true;
            break;
        case 'O':
            config.os_fingerprint = true;
            break;
        case 'j':
            config.json_output = true;
            break;
        case 'R':
            config.randomize = true;
            break;
        case '4':
            config.family = AF_INET;
            break;
        case '6':
            config.family = AF_INET6;
            break;
        case 'p': {
            char *dash = strchr(optarg, '-');
            if (dash) {
                *dash = '\0';
                config.start_port = (u_short)atoi(optarg);
                config.end_port = (u_short)atoi(dash + 1);
            } else {
                config.start_port = (u_short)atoi(optarg);
                config.end_port = config.start_port;
            }
            if (config.start_port == 0 || config.end_port == 0 ||
                config.start_port > config.end_port) {
                die("Invalid port range");
            }
            break;
        }
        case 'W':
            config.timeout_ns = (u_int64_t)atoi(optarg) * NS_PER_S;
            break;
        case 'r':
            config.rate_limit = (u_int)atoi(optarg);
            break;
        case 'I':
            config.bind_iface = optarg;
            break;
        case 'h':
            print_usage(*av);
            goto out;
        default:
            print_usage(*av);
            ret = EXIT_FAILURE;
            goto out;
        }
    }

    c -= optind;
    av += optind;

    if (c < 1) {
        log_err("Target IP/hostname is required");
        ret = EXIT_FAILURE;
        goto out;
    }

    target_ip_str = *av;

    if (!resolve_host(target_ip_str, config.family, &config.target_addr,
                      &config.target_addr_len)) {
        die("Invalid target IP address or hostname: %s", target_ip_str);
    }

    ret = pscan_run(&config);
out:
    return ret;
}
