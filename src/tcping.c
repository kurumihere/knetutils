/***************************************************************************
 * tcping.c -- TCP ping utility logic                                      *
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

#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* --- Configuration Struct --- */
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

#ifndef TH_SYN
#define TH_SYN 0x02
#endif
#ifndef TH_RST
#define TH_RST 0x04
#endif
#ifndef TH_ACK
#define TH_ACK 0x10
#endif

#define EPHEMERAL_PORT_BASE 1024
#define EPHEMERAL_PORT_RANGE 64000
#define INITIAL_SEQ 1000
#define DEFAULT_TCP_WIN 64240
#define RECV_BUF_SIZE 4096
#define PERCENT_MULTIPLIER 100
#define IPV4_HLEN_SHIFT 2

static volatile sig_atomic_t keep_running = 1;

static void
handle_sigint(int sig)
{
    (void)sig;
    keep_running = 0;
}

typedef struct {
    u_short sport;
    u_int seq;
    u_int sent;
    u_int received;

    net_socket_t *sock;

    char target_str[INET6_ADDRSTRLEN];
    struct sockaddr_storage src_addr;
    socklen_t src_addr_len;

    u_int64_t *sent_times;
    bool *replied_or_timeout;
    u_short next_timeout_check_seq;
} tcping_state_t;

static void
setup_tcping_socket(const tcping_config_t *config, tcping_state_t *st)
{
    st->sock = open_ip_raw_socket(config->family, IPPROTO_TCP);

    if (!st->sock) {
        die("Failed to open raw TCP socket. Are you root?");
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
init_tcping_state(const tcping_config_t *config, tcping_state_t *st)
{
    memset(st, 0, sizeof(*st));

    getnameinfo((struct sockaddr *)&config->target_addr,
                config->target_addr_len, st->target_str, sizeof(st->target_str),
                NULL, 0, NI_NUMERICHOST);

    st->src_addr_len = sizeof(st->src_addr);
    if (!get_source_ip_for(&config->target_addr, config->target_addr_len,
                           &st->src_addr, &st->src_addr_len)) {
        die("Failed to determine source IP for target");
    }

    st->sent_times = calloc(65536, sizeof(u_int64_t));
    st->replied_or_timeout = calloc(65536, sizeof(bool));
    if (!st->sent_times || !st->replied_or_timeout) {
        die("Memory allocation failed for state tracking");
    }

    st->sport = EPHEMERAL_PORT_BASE + (getpid() % EPHEMERAL_PORT_RANGE);
    st->seq = INITIAL_SEQ;
    st->next_timeout_check_seq = INITIAL_SEQ;
}

static void
send_tcping_probe(const tcping_config_t *config, tcping_state_t *st)
{
    struct tcphdr tcph;
    u_int64_t csum_buf_aligned[128];
    u_char *csum_buf = (u_char *)csum_buf_aligned;
    size_t csum_len = 0;

    memset(&tcph, 0, sizeof(tcph));
    tcph.th_sport = htons(st->sport);
    tcph.th_dport = htons(config->port);
    tcph.th_seq = htonl(st->seq);
    tcph.th_ack = 0;
    tcph.th_off = (sizeof(struct tcphdr) >> 2);
    tcph.th_flags = TH_SYN;
    tcph.th_win = htons(DEFAULT_TCP_WIN);
    tcph.th_sum = 0;
    tcph.th_urp = 0;

    if (config->family == AF_INET) {
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
        memset(psh.zero, 0, sizeof(psh.zero));
        psh.next_header = IPPROTO_TCP;

        memcpy(csum_buf, &psh, sizeof(psh));
        csum_len += sizeof(psh);
    }

    memcpy(csum_buf + csum_len, &tcph, sizeof(tcph));
    csum_len += sizeof(tcph);

    tcph.th_sum = calculate_checksum(csum_buf, csum_len);

    if (send_ip_raw(st->sock, &tcph, sizeof(tcph),
                    (struct sockaddr *)&config->target_addr,
                    config->target_addr_len) < 0) {
        log_err("Failed to send TCP SYN packet");
    }
    st->sent++;
}

static void
print_tcping_reply(const tcping_config_t *config, const tcping_state_t *st,
                   const struct tcphdr *r_tcph, u_int64_t rtt)
{
    char time_buf[64];

    if (config->quiet) {
        return;
    }

    format_time(rtt, NULL, time_buf, sizeof(time_buf));

    if ((r_tcph->th_flags & TH_SYN) && (r_tcph->th_flags & TH_ACK)) {
        printf("Reply from %s:%u (SYN-ACK) time=%s\n", st->target_str,
               config->port, time_buf);

    } else if (r_tcph->th_flags & TH_RST) {
        printf("Reply from %s:%u (RST) time=%s\n", st->target_str, config->port,
               time_buf);
    }
}

static void
drain_tcping_replies(const tcping_config_t *config, tcping_state_t *st)
{
    struct pollfd pfd;
    pfd.fd = get_socket_fd(st->sock);
    pfd.events = POLLIN;

    while (keep_running && poll(&pfd, 1, 0) > 0) {
        __attribute__((aligned(8))) u_char recv_buf[RECV_BUF_SIZE];
        struct sockaddr_storage from_addr;
        socklen_t from_addr_len = sizeof(from_addr);
        ssize_t n;
        int hlen = 0;
        struct tcphdr *r_tcph;
        u_int64_t recv_time;
        u_int64_t rtt = 0;
        u_int raw_seq;
        u_short short_seq;

        if (!(pfd.revents & POLLIN)) {
            break;
        }

        n = recv_ip_raw(st->sock, recv_buf, sizeof(recv_buf), &from_addr,
                        &from_addr_len);

        if (n <= 0) {
            continue;
        }

        if (config->family == AF_INET) {
            struct ip *ip_hdr = (struct ip *)recv_buf;
            hlen = ip_hdr->ip_hl << IPV4_HLEN_SHIFT;
        }

        if (n < (ssize_t)(hlen + sizeof(struct tcphdr))) {
            continue;
        }

        r_tcph = (struct tcphdr *)(recv_buf + hlen);

        if (r_tcph->th_dport != htons(st->sport) ||
            r_tcph->th_sport != htons(config->port)) {
            continue;
        }

        if (((r_tcph->th_flags & TH_SYN) && (r_tcph->th_flags & TH_ACK)) ||
            (r_tcph->th_flags & TH_RST)) {

            raw_seq = ntohl(r_tcph->th_ack);
            if (raw_seq > 0) {
                raw_seq = raw_seq - 1;
            }
            short_seq = (u_short)(raw_seq & 0xFFFF);

            if (st->replied_or_timeout[short_seq]) {
                continue;
            }

            recv_time = get_time_ns();
            if (st->sent_times[short_seq] > 0 &&
                recv_time >= st->sent_times[short_seq]) {
                rtt = time_diff_ns(st->sent_times[short_seq], recv_time);
            }

            st->replied_or_timeout[short_seq] = true;
            st->received++;
            print_tcping_reply(config, st, r_tcph, rtt);
        }
    }
}

static void
print_tcping_stats(const tcping_config_t *config, const tcping_state_t *st)
{
    u_int loss_pct;

    if (config->quiet) {
        return;
    }

    printf("\n--- %s:%u tcping statistics ---\n", st->target_str, config->port);

    loss_pct =
        (st->sent == 0)
            ? 0
            : ((st->sent - st->received) * PERCENT_MULTIPLIER) / st->sent;

    printf("%u packets transmitted, %u packets received, %u%% packet loss\n",
           st->sent, st->received, loss_pct);
}

static int
tcping_run(const tcping_config_t *config)
{
    struct sigaction sa;
    tcping_state_t st;
    u_int64_t next_send_time;

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = handle_sigint;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGQUIT, &sa, NULL);

    init_tcping_state(config, &st);
    setup_tcping_socket(config, &st);

    if (setgid(getgid()) != 0) {
        log_warn("Failed to drop group privileges");
    }
    if (setuid(getuid()) != 0) {
        log_warn("Failed to drop user privileges");
    }

    if (!config->quiet) {
        printf("TCPING %s:%u\n", st.target_str, config->port);
    }

    next_send_time = get_time_ns();

    while (keep_running) {
        u_int64_t now = get_time_ns();
        int timeout_ms = 1;
        struct pollfd pfd;
        int ret;

        if ((config->count == 0 || st.sent < config->count) &&
            now >= next_send_time) {
            u_short short_seq = (u_short)(st.seq & 0xFFFF);
            st.sent_times[short_seq] = now;
            st.replied_or_timeout[short_seq] = false;
            send_tcping_probe(config, &st);
            st.seq++;
            next_send_time = now + config->interval_ns;
        }

        now = get_time_ns();
        while (st.next_timeout_check_seq != (u_short)(st.seq & 0xFFFF)) {
            u_short chk_seq = st.next_timeout_check_seq;
            if (st.replied_or_timeout[chk_seq]) {
                st.next_timeout_check_seq++;
                continue;
            }
            if (now >= st.sent_times[chk_seq] + config->timeout_ns) {
                st.replied_or_timeout[chk_seq] = true;
                if (!config->quiet) {
                    printf("Timeout waiting for reply from %s:%u\n",
                           st.target_str, config->port);
                }
                st.next_timeout_check_seq++;
            } else {
                break;
            }
        }

        if (config->count > 0 && st.sent >= config->count &&
            st.next_timeout_check_seq == (u_short)(st.seq & 0xFFFF)) {
            break;
        }

        if (config->count == 0 || st.sent < config->count) {
            if (next_send_time > now) {
                u_int64_t diff = next_send_time - now;
                timeout_ms = diff / NS_PER_MS;
                if (timeout_ms <= 0)
                    timeout_ms = 1;
            } else {
                timeout_ms = 0;
            }
        } else {
            if (st.next_timeout_check_seq != (u_short)(st.seq & 0xFFFF)) {
                u_int64_t to_wait = (st.sent_times[st.next_timeout_check_seq] +
                                     config->timeout_ns) -
                                    now;
                timeout_ms = to_wait / NS_PER_MS;
                if (timeout_ms <= 0)
                    timeout_ms = 1;
            }
        }

        pfd.fd = get_socket_fd(st.sock);
        pfd.events = POLLIN;
        ret = poll(&pfd, 1, timeout_ms);
        if (ret > 0 && (pfd.revents & POLLIN)) {
            drain_tcping_replies(config, &st);
        }
    }

    close_raw_socket(st.sock);

    free(st.sent_times);
    free(st.replied_or_timeout);

    print_tcping_stats(config, &st);

    if (st.received > 0) {
        return EXIT_SUCCESS;
    }
    return EXIT_FAILURE;
}

static const cli_option_t tcping_options[] = {
    {'4', NULL, "use IPv4"},
    {'6', NULL, "use IPv6"},
    {'c', "count", "stop after sending count packets"},
    {'W', "timeout", "time to wait for a response, in seconds"},
    {'i', "interval", "wait interval milliseconds between sending each packet"},
    {'I', "iface/ip", "bind to a specific interface or IP address"},
    {'q', NULL, "quiet output"},
    {'h', NULL, "print help and exit"},
    {0, NULL, NULL}};

static void
print_usage(const char *prog_name)
{
    cli_app_t app = {.prog_name = prog_name,
                     .usage_args = "[options] <destination> <port>",
                     .options = tcping_options};

    cli_print_help(&app);
}

int
tcping_main(int c, char **av)
{
    tcping_config_t config;
    int ch;
    const char *target_ip_str;
    const char *prog_name;

    int ret = EXIT_FAILURE;

    prog_name = *av;

    optind = 1;
    memset(&config, 0, sizeof(config));

    config.count = 0;
    config.timeout_ns = NS_PER_S;
    config.interval_ns = NS_PER_S;
    config.family = AF_UNSPEC;

    while ((ch = getopt(c, av, "46c:W:i:I:qh")) != -1) {
        switch (ch) {
        case '4':

            config.family = AF_INET;
            break;
        case '6':

            config.family = AF_INET6;
            break;
        case 'c':
            config.count = (u_int)atoi(optarg);
            break;
        case 'W':
            config.timeout_ns = (u_int64_t)atoi(optarg) * NS_PER_S;
            break;
        case 'i':
            config.interval_ns = (u_int64_t)atoi(optarg) * NS_PER_MS;
            break;
        case 'I':
            config.bind_iface = optarg;
            break;
        case 'q':
            config.quiet = true;
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

    if (c < 2) {
        log_err("Target port is required");
        goto usage_err;
    }

    target_ip_str = *av;
    config.port = (u_short)atoi(*(av + 1));

    if (config.port == 0) {
        die("Invalid port: %s", *(av + 1));
    }

    if (!resolve_host(target_ip_str, config.family, &config.target_addr,
                      &config.target_addr_len)) {
        die("Invalid target IP address or hostname: %s", target_ip_str);
    }

    config.family = config.target_addr.ss_family;

    if (getuid() != 0) {
        log_warn("tcping requires root privileges to open raw sockets.");
    }

    ret = tcping_run(&config);
    goto out;

usage_err:
    print_usage(prog_name);

out:
    return ret;
}
