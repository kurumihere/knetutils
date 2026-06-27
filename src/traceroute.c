/***************************************************************************
 * traceroute.c -- Traceroute utility logic                                *
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

#include "cli.h"
#include "net.h"
#include "tools.h"
#include "utils.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/icmp6.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* --- Configuration Struct --- */
typedef struct {
    const char *iface;
    u_int target_ip;
    u_int source_ip;
    u_char source_mac[ETH_ALEN];
    u_int count;
    u_int64_t timeout_ns;
    u_int64_t interval_ns;
    bool quiet;
    bool unsolicited;
    bool dad;
    bool gateway;
    bool cisco_style;
    bool quit_on_reply;
    bool use_reply;
    bool keep_broadcast;
    const char *time_unit;
} arping_config_t;

#define PING_MAX_PATTERN_LEN 16

typedef struct {
    u_int count;
    u_int64_t timeout_ns;
    u_int64_t interval_ns;
    u_int payload_size;
    u_char ttl;
    bool quiet;
    const char *time_unit;
    struct sockaddr_storage target_addr;
    socklen_t target_addr_len;
    int family;
    bool cisco_style;
    bool flood;
    bool audible;
    bool adaptive;
    const char *bind_iface;
    u_char pattern[PING_MAX_PATTERN_LEN];
    size_t pattern_len;
    u_int64_t deadline_ns;
    int tos;
    bool has_tos;
} ping_config_t;

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
    const char *iface;
    int max_packets;
    int verbosity;
    const char *pcap_file;
} sniff_config_t;

typedef struct {
    u_short port;
    u_int count;
    u_int64_t timeout_ns;
    u_int64_t interval_ns;
    struct sockaddr_storage target_addr;
    socklen_t target_addr_len;
    int family;
    const char *bind_iface;
    bool quiet;
} tcping_config_t;

typedef struct {
    u_char first_ttl;
    u_char max_ttl;
    u_char queries;
    u_int64_t timeout_ns;
    struct sockaddr_storage target_addr;
    socklen_t target_addr_len;
    int family;
    const char *bind_iface;
    bool resolve_hostnames;
    bool use_udp;
} traceroute_config_t;

#define TRACEROUTE_PORT_BASE 33434
#define RECV_BUF_SIZE 4096
#define PID_MASK 0xFFFF
#define IPV4_HLEN_SHIFT 2
#define ICMP_ERROR_HDR_OFFSET 8

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
    bool target_reached;

    net_socket_t *sock;
    int udp_sock;

    u_char *packet;
    size_t header_size;

    struct sockaddr_storage last_hop_addr;
} traceroute_state_t;

static bool
is_our_probe_v4(const u_char *buf, ssize_t len, u_short expected_id,
                u_short expected_seq, bool use_udp, u_short expected_port)
{
    struct ip *ip_hdr;
    int hlen;
    struct icmp *icp;
    bool ret_val = false;

    if (len < (ssize_t)sizeof(struct ip)) {
        goto out;
    }

    ip_hdr = (struct ip *)buf;
    hlen = ip_hdr->ip_hl << IPV4_HLEN_SHIFT;

    if (len < (ssize_t)(hlen + sizeof(struct icmp))) {
        goto out;
    }

    icp = (struct icmp *)(buf + hlen);

    if (!use_udp && icp->icmp_type == ICMP_ECHOREPLY) {
        ret_val =
            (icp->icmp_id == expected_id && icp->icmp_seq == expected_seq);
        goto out;
    }

    if (icp->icmp_type == ICMP_TIMXCEED || icp->icmp_type == ICMP_UNREACH) {
        struct ip *inner_ip;
        int inner_hlen;

        if (len < (ssize_t)(hlen + ICMP_ERROR_HDR_OFFSET + sizeof(struct ip))) {
            goto out;
        }

        inner_ip = (struct ip *)icp->icmp_data;

        inner_hlen = inner_ip->ip_hl << IPV4_HLEN_SHIFT;

        if (use_udp) {
            struct udphdr *inner_udp;

            if (len < (ssize_t)(hlen + ICMP_ERROR_HDR_OFFSET + inner_hlen +
                                sizeof(struct udphdr))) {
                goto out;
            }

            inner_udp = (struct udphdr *)((u_char *)inner_ip + inner_hlen);
            ret_val = (ntohs(inner_udp->uh_dport) == expected_port);
            goto out;
        }

        {
            struct icmp *inner_icp;

            if (len < (ssize_t)hlen + ICMP_ERROR_HDR_OFFSET + inner_hlen +
                          ICMP_ERROR_HDR_OFFSET) {
                goto out;
            }

            inner_icp = (struct icmp *)((u_char *)inner_ip + inner_hlen);
            ret_val = (inner_icp->icmp_id == expected_id &&
                       inner_icp->icmp_seq == expected_seq);
            goto out;
        }
    }

out:
    return ret_val;
}

static bool
is_our_probe_v6(const u_char *buf, ssize_t len, u_short expected_id,
                u_short expected_seq, bool use_udp, u_short expected_port)
{
    struct icmp6_hdr *icp;
    bool ret_val = false;

    if (len < (ssize_t)sizeof(struct icmp6_hdr)) {
        goto out;
    }

    icp = (struct icmp6_hdr *)buf;

    if (!use_udp && icp->icmp6_type == ICMP6_ECHO_REPLY) {
        ret_val =
            (icp->icmp6_id == expected_id && icp->icmp6_seq == expected_seq);
        goto out;
    }

    if (icp->icmp6_type == ICMP6_TIME_EXCEEDED ||
        icp->icmp6_type == ICMP6_DST_UNREACH) {
        struct ip6_hdr *inner_ip;

        if (len < (ssize_t)(sizeof(struct icmp6_hdr) + sizeof(struct ip6_hdr) +
                            ICMP_ERROR_HDR_OFFSET)) {
            goto out;
        }

        inner_ip = (struct ip6_hdr *)(icp + 1);

        if (use_udp) {
            struct udphdr *inner_udp;

            inner_udp =
                (struct udphdr *)((u_char *)inner_ip + sizeof(struct ip6_hdr));
            ret_val = (ntohs(inner_udp->uh_dport) == expected_port);
            goto out;
        }

        {
            struct icmp6_hdr *inner_icp;

            inner_icp = (struct icmp6_hdr *)((u_char *)inner_ip +
                                             sizeof(struct ip6_hdr));
            ret_val = (inner_icp->icmp6_id == expected_id &&
                       inner_icp->icmp6_seq == expected_seq);
            goto out;
        }
    }

out:
    return ret_val;
}

static void
setup_traceroute_sockets(const traceroute_config_t *config,
                         traceroute_state_t *st)
{
    st->sock = open_icmp_socket(config->family);

    if (!st->sock) {
        die("Failed to open ICMP socket. Are you root?");
    }

    st->udp_sock = -1;

    if (config->use_udp) {
        st->udp_sock = socket(config->family, SOCK_DGRAM, IPPROTO_UDP);
        if (st->udp_sock < 0) {
            die("Failed to open UDP socket");
        }
    }

    if (config->bind_iface) {
        struct sockaddr_storage bind_addr;

        memset(&bind_addr, 0, sizeof(bind_addr));

        if (inet_pton(AF_INET, config->bind_iface,
                      &((struct sockaddr_in *)&bind_addr)->sin_addr) == 1) {
            bind_addr.ss_family = AF_INET;
            if (bind(get_socket_fd(st->sock), (struct sockaddr *)&bind_addr,
                     sizeof(struct sockaddr_in)) < 0) {
                die("Failed to bind to IP %s", config->bind_iface);
            }
        } else if (inet_pton(AF_INET6, config->bind_iface,
                             &((struct sockaddr_in6 *)&bind_addr)->sin6_addr) ==
                   1) {
            bind_addr.ss_family = AF_INET6;
            if (bind(get_socket_fd(st->sock), (struct sockaddr *)&bind_addr,
                     sizeof(struct sockaddr_in6)) < 0) {
                die("Failed to bind to IP %s", config->bind_iface);
            }
        } else {
            if (setsockopt(get_socket_fd(st->sock), SOL_SOCKET, SO_BINDTODEVICE,
                           config->bind_iface,
                           strlen(config->bind_iface)) < 0) {
                die("Failed to bind to interface %s", config->bind_iface);
            }
        }
    }
}

static void
init_traceroute_state(const traceroute_config_t *config, traceroute_state_t *st)
{
    memset(st, 0, sizeof(*st));

    st->pid = getpid() & PID_MASK;
    st->seq = 1;

    st->header_size = (config->family == AF_INET6) ? sizeof(struct icmp6_hdr)
                                                   : sizeof(struct icmp);

    st->packet = calloc(1, st->header_size);

    if (!st->packet) {
        die("Memory allocation failed");
    }
}

static bool
send_traceroute_probe(const traceroute_config_t *config, traceroute_state_t *st,
                      u_char ttl, u_short dest_port)
{
    int level;
    int optname;
    int ttl_val;
    bool ret_val = false;

    level = (config->family == AF_INET6) ? IPPROTO_IPV6 : IPPROTO_IP;
    optname = (config->family == AF_INET6) ? IPV6_UNICAST_HOPS : IP_TTL;
    ttl_val = ttl;

    if (config->use_udp) {
        struct sockaddr_storage target;
        char dummy[1];

        dummy[0] = 0;

        setsockopt(st->udp_sock, level, optname, &ttl_val, sizeof(ttl_val));

        target = config->target_addr;
        if (config->family == AF_INET) {
            ((struct sockaddr_in *)&target)->sin_port = htons(dest_port);
        } else {
            ((struct sockaddr_in6 *)&target)->sin6_port = htons(dest_port);
        }

        if (sendto(st->udp_sock, dummy, 0, 0, (struct sockaddr *)&target,
                   config->target_addr_len) < 0) {
            goto out;
        }

        ret_val = true;
        goto out;
    }

    setsockopt(get_socket_fd(st->sock), level, optname, &ttl_val,
               sizeof(ttl_val));

    if (config->family == AF_INET) {
        struct icmp *icp = (struct icmp *)st->packet;

        icp->icmp_type = ICMP_ECHO;
        icp->icmp_code = 0;
        icp->icmp_id = htons(st->pid);
        icp->icmp_seq = htons(st->seq);
        icp->icmp_cksum = 0;

        icp->icmp_cksum = calculate_checksum(st->packet, st->header_size);
    } else {
        struct icmp6_hdr *icp = (struct icmp6_hdr *)st->packet;

        icp->icmp6_type = ICMP6_ECHO_REQUEST;
        icp->icmp6_code = 0;
        icp->icmp6_id = htons(st->pid);
        icp->icmp6_seq = htons(st->seq);
        icp->icmp6_cksum = 0;
    }

    if (send_icmp_packet(st->sock, st->packet, st->header_size,
                         (struct sockaddr *)&config->target_addr,
                         config->target_addr_len) < 0) {
        goto out;
    }

    ret_val = true;

out:
    return ret_val;
}

static bool
check_is_target(const traceroute_config_t *config, const u_char *recv_buf,
                ssize_t n)
{
    bool ret_val = false;

    if (config->family == AF_INET) {
        struct ip *ip_hdr;
        int hlen;

        ip_hdr = (struct ip *)recv_buf;
        hlen = ip_hdr->ip_hl << IPV4_HLEN_SHIFT;

        if (n >= (ssize_t)(hlen + sizeof(struct icmp))) {
            struct icmp *icp = (struct icmp *)(recv_buf + hlen);

            if (icp->icmp_type == ICMP_ECHOREPLY ||
                (config->use_udp && icp->icmp_type == ICMP_UNREACH)) {
                ret_val = true;
                goto out;
            }
        }
    } else {
        if (n >= (ssize_t)sizeof(struct icmp6_hdr)) {
            struct icmp6_hdr *icp = (struct icmp6_hdr *)recv_buf;

            if (icp->icmp6_type == ICMP6_ECHO_REPLY ||
                (config->use_udp && icp->icmp6_type == ICMP6_DST_UNREACH)) {
                ret_val = true;
                goto out;
            }
        }
    }

out:
    return ret_val;
}

static void
print_hop_info(const traceroute_config_t *config, traceroute_state_t *st,
               struct sockaddr_storage *src_addr, socklen_t src_addr_len)
{

    if (memcmp(&st->last_hop_addr, src_addr, sizeof(st->last_hop_addr)) != 0) {
        char host_str[NI_MAXHOST];
        char ip_str[INET6_ADDRSTRLEN];

        getnameinfo((struct sockaddr *)src_addr, src_addr_len, ip_str,
                    sizeof(ip_str), NULL, 0, NI_NUMERICHOST);

        if (config->resolve_hostnames &&
            getnameinfo((struct sockaddr *)src_addr, src_addr_len, host_str,
                        sizeof(host_str), NULL, 0, NI_NAMEREQD) == 0) {
            printf("%s (%s)  ", host_str, ip_str);
        } else {
            printf("%s  ", ip_str);
        }

        memcpy(&st->last_hop_addr, src_addr, sizeof(st->last_hop_addr));
    }
}

static bool
recv_traceroute_reply(const traceroute_config_t *config, traceroute_state_t *st,
                      u_int64_t wait_until, u_int64_t send_time,
                      u_short dest_port)
{
    struct pollfd pfd;
    bool ret_val = false;

    pfd.fd = get_socket_fd(st->sock);
    pfd.events = POLLIN;

    while (get_time_ns() < wait_until && keep_running) {
        int64_t timeout_ns;
        int timeout_ms;
        int ret;
        __attribute__((aligned(8))) u_char recv_buf[RECV_BUF_SIZE];
        struct sockaddr_storage src_addr;
        socklen_t src_addr_len = sizeof(src_addr);
        ssize_t n;
        bool is_mine = false;
        u_int64_t recv_time;
        u_int64_t rtt;
        char time_buf[64];

        timeout_ns = wait_until - get_time_ns();
        if (timeout_ns <= 0) {
            break;
        }

        timeout_ms = timeout_ns / NS_PER_MS;
        ret = poll(&pfd, 1, timeout_ms > 0 ? timeout_ms : 1);

        if (ret <= 0 || !(pfd.revents & POLLIN)) {
            continue;
        }

        n = recv_icmp_packet(st->sock, recv_buf, sizeof(recv_buf), &src_addr,
                             &src_addr_len);

        if (n <= 0) {
            continue;
        }

        if (config->family == AF_INET) {
            is_mine =
                is_our_probe_v4(recv_buf, n, htons(st->pid), htons(st->seq),
                                config->use_udp, dest_port);
        } else {
            is_mine =
                is_our_probe_v6(recv_buf, n, htons(st->pid), htons(st->seq),
                                config->use_udp, dest_port);
        }

        if (!is_mine) {
            continue;
        }

        recv_time = get_time_ns();
        rtt = time_diff_ns(send_time, recv_time);

        print_hop_info(config, st, &src_addr, src_addr_len);

        format_time(rtt, NULL, time_buf, sizeof(time_buf));
        printf("%s  ", time_buf);
        fflush(stdout);

        if (check_is_target(config, recv_buf, n)) {
            st->target_reached = true;
        }

        ret_val = true;
        goto out;
    }

out:
    return ret_val;
}

static int
traceroute_run(const traceroute_config_t *config)
{
    struct sigaction sa;
    traceroute_state_t st;
    char target_str[INET6_ADDRSTRLEN];
    u_char ttl;
    u_char probe;

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = handle_sigint;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGQUIT, &sa, NULL);

    init_traceroute_state(config, &st);
    setup_traceroute_sockets(config, &st);

    if (setgid(getgid()) != 0) {
        log_warn("Failed to drop group privileges");
    }
    if (setuid(getuid()) != 0) {
        log_warn("Failed to drop user privileges");
    }

    getnameinfo((struct sockaddr *)&config->target_addr,
                config->target_addr_len, target_str, sizeof(target_str), NULL,
                0, NI_NUMERICHOST);

    printf("traceroute to %s, %u hops max\n", target_str, config->max_ttl);

    for (ttl = config->first_ttl;
         ttl <= config->max_ttl && keep_running && !st.target_reached; ttl++) {
        u_short dest_port;
        u_int64_t send_time;
        u_int64_t wait_until;
        bool got_reply;

        printf("%2u  ", ttl);
        fflush(stdout);

        memset(&st.last_hop_addr, 0, sizeof(st.last_hop_addr));

        for (probe = 0; probe < config->queries && keep_running; probe++) {
            dest_port =
                TRACEROUTE_PORT_BASE + (ttl - 1) * config->queries + probe;
            send_time = get_time_ns();

            if (!send_traceroute_probe(config, &st, ttl, dest_port)) {
                printf("* ");
                fflush(stdout);
                st.seq++;
                continue;
            }

            wait_until = send_time + config->timeout_ns;

            got_reply = recv_traceroute_reply(config, &st, wait_until,
                                              send_time, dest_port);

            if (!got_reply) {
                printf("* ");
                fflush(stdout);
            }

            st.seq++;
        }

        printf("\n");
    }

    free(st.packet);

    if (st.udp_sock >= 0) {
        close(st.udp_sock);
    }

    close_raw_socket(st.sock);

    return EXIT_SUCCESS;
}

static const cli_option_t traceroute_options[] = {
    {'4', NULL, "use IPv4"},
    {'6', NULL, "use IPv6"},
    {'f', "first_ttl", "start from the given first_ttl hop"},
    {'m', "max_ttl", "set the max number of hops (max TTL)"},
    {'q', "nqueries", "set the number of probes per hop"},
    {'U', NULL, "use UDP instead of ICMP ECHO"},
    {'w', "timeout", "wait time for a response, in seconds"},
    {'I', "iface/ip", "bind to a specific interface or IP address"},
    {'n', NULL, "do not resolve IP addresses to their domain names"},
    {'h', NULL, "print help and exit"},
    {0, NULL, NULL}};

static void
print_usage(const char *prog_name)
{
    cli_app_t app = {.prog_name = prog_name,
                     .usage_args = "[options] <destination>",
                     .options = traceroute_options};

    cli_print_help(&app);
}

int
traceroute_main(int c, char **av)
{
    traceroute_config_t config;
    int ch;
    const char *target_ip_str;
    const char *prog_name;

    int ret = EXIT_FAILURE;

    prog_name = *av;

    memset(&config, 0, sizeof(config));

    config.first_ttl = 1;
    config.max_ttl = 30;
    config.queries = 3;
    config.timeout_ns = 3 * NS_PER_S;
    config.family = AF_UNSPEC;
    config.resolve_hostnames = true;

    while ((ch = getopt(c, av, "46f:m:q:w:I:nUh")) != -1) {
        switch (ch) {
        case '4':

            config.family = AF_INET;
            break;
        case '6':
            config.family = AF_INET6;
            break;
        case 'f':
            config.first_ttl = (u_char)atoi(optarg);
            break;
        case 'm':
            config.max_ttl = (u_char)atoi(optarg);
            break;
        case 'q':
            config.queries = (u_char)atoi(optarg);
            break;
        case 'w':
            config.timeout_ns = (u_int64_t)atoi(optarg) * NS_PER_S;
            break;
        case 'I':
            config.bind_iface = optarg;
            break;
        case 'n':
            config.resolve_hostnames = false;
            break;
        case 'U':
            config.use_udp = true;
            break;
        case 'h':
            print_usage(prog_name);
            ret = EXIT_SUCCESS;
            goto out;
        default:
            goto usage_err;
        }
    }

    c -= optind;
    av += optind;

    if (c < 1) {
        log_err("Target IP/hostname is required");
        goto usage_err;
    }

    target_ip_str = *av;

    if (!resolve_host(target_ip_str, config.family, &config.target_addr,
                      &config.target_addr_len)) {
        die("Invalid target IP address or hostname: %s", target_ip_str);
    }

    config.family = config.target_addr.ss_family;

    if (config.first_ttl == 0) {
        config.first_ttl = 1;
    }

    if (getuid() != 0) {

        log_warn("traceroute requires root privileges to open raw "
                 "sockets.");
    }

    ret = traceroute_run(&config);
    goto out;

usage_err:
    print_usage(prog_name);

out:
    return ret;
}
