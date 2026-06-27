/***************************************************************************
 * arping.c -- ARP ping utility logic                                      *
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
#include <net/if_arp.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
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

#ifndef IPV4_ALEN
#define IPV4_ALEN 4
#endif

#ifndef ETH_P_ARP
#define ETH_P_ARP ETHERTYPE_ARP
#endif

#ifndef ETH_P_IP
#define ETH_P_IP ETHERTYPE_IP
#endif

static volatile sig_atomic_t keep_running = 1;

static void
handle_sigint(int sig)
{
    (void)sig;
    keep_running = 0;
}

static void
print_mac(const u_char *mac)
{
    printf("%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3],
           mac[4], mac[5]);
}

typedef struct {
    u_int sent;
    u_int received;
    net_socket_t *sock;

    u_char current_target_mac[ETH_ALEN];
    u_char target_mac_broadcast[ETH_ALEN];
    u_char target_mac_zero[ETH_ALEN];

    struct in_addr target_in;
    struct in_addr source_in;

    u_int64_t *sent_times;
    bool *replied_or_timeout;
    u_short next_timeout_check_seq;
} arping_state_t;

static int
setup_arping_socket(const arping_config_t *config, arping_state_t *st)
{
    st->sock = open_raw_socket(config->iface, ETH_P_ARP);
    if (!st->sock) {
        log_err("Failed to open raw socket on interface %s", config->iface);
        return -1;
    }

    if (config->dad) {
        if (!set_promiscuous(st->sock)) {
            log_warn("Failed to set promiscuous mode for DAD. "
                     "Detection might be incomplete.");
        }
    }
    return 0;
}

static void
init_arping_state(const arping_config_t *config, arping_state_t *st)
{
    u_char bc[ETH_ALEN] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    u_char zero[ETH_ALEN] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

    memset(st, 0, sizeof(*st));

    st->target_in.s_addr = config->target_ip;
    st->source_in.s_addr = config->source_ip;

    memcpy(st->target_mac_broadcast, bc, ETH_ALEN);
    memcpy(st->target_mac_zero, zero, ETH_ALEN);
    memcpy(st->current_target_mac, bc, ETH_ALEN);

    st->sent_times = calloc(65536, sizeof(u_int64_t));
    st->replied_or_timeout = calloc(65536, sizeof(bool));
    if (!st->sent_times || !st->replied_or_timeout) {
        die("Memory allocation failed for state tracking");
    }
}

static bool
send_arping_probe(const arping_config_t *config, arping_state_t *st)
{
    u_char buffer[sizeof(struct ether_header) + sizeof(struct ether_arp)];
    struct ether_header *eth = (struct ether_header *)buffer;
    struct ether_arp *arp =
        (struct ether_arp *)(buffer + sizeof(struct ether_header));

    memcpy(eth->ether_dhost, st->current_target_mac, ETH_ALEN);
    memcpy(eth->ether_shost, config->source_mac, ETH_ALEN);
    eth->ether_type = htons(ETH_P_ARP);

    arp->arp_hrd = htons(ARPHRD_ETHER);
    arp->arp_pro = htons(ETH_P_IP);
    arp->arp_hln = ETH_ALEN;
    arp->arp_pln = IPV4_ALEN;
    arp->arp_op = config->use_reply ? htons(ARPOP_REPLY) : htons(ARPOP_REQUEST);

    memcpy(arp->arp_sha, config->source_mac, ETH_ALEN);
    memcpy(arp->arp_spa, &config->source_ip, IPV4_ALEN);

    if (memcmp(st->current_target_mac, st->target_mac_broadcast, ETH_ALEN) ==
        0) {
        memcpy(arp->arp_tha, st->target_mac_zero, ETH_ALEN);
    } else {
        memcpy(arp->arp_tha, st->current_target_mac, ETH_ALEN);
    }

    memcpy(arp->arp_tpa, &config->target_ip, IPV4_ALEN);

    if (send_packet(st->sock, buffer, sizeof(buffer), st->current_target_mac) <
        0) {
        log_err("Failed to send ARP packet");
        return false;
    }

    st->sent++;
    return true;
}

static bool
handle_arp_reply(const arping_config_t *config, arping_state_t *st,
                 struct ether_arp *r_arp, u_int64_t rtt)
{
    u_int reply_spa;
    memcpy(&reply_spa, r_arp->arp_spa, IPV4_ALEN);

    if (reply_spa != config->target_ip) {
        return false;
    }

    if (!config->quiet) {
        if (config->cisco_style) {
            printf("!");
            fflush(stdout);
        } else {
            char time_buf[64];
            format_time(rtt, config->time_unit, time_buf, sizeof(time_buf));
            printf("Unicast reply from %s [", inet_ntoa(st->target_in));
            print_mac(r_arp->arp_sha);
            printf("]  %s\n", time_buf);
        }
    }

    if (!config->keep_broadcast) {
        memcpy(st->current_target_mac, r_arp->arp_sha, ETH_ALEN);
    }

    st->received++;
    return true;
}

static void
drain_arping_replies(const arping_config_t *config, arping_state_t *st)
{
    struct pollfd pfd;
    pfd.fd = get_socket_fd(st->sock);
    pfd.events = POLLIN;

    while (keep_running && poll(&pfd, 1, 0) > 0) {
        __attribute__((aligned(8))) u_char recv_buf[4096];
        ssize_t n;
        struct ether_header *r_eth;
        struct ether_arp *r_arp;
        u_int64_t recv_time;
        u_int64_t rtt = 0;
        u_short match_seq;

        if (!(pfd.revents & POLLIN))
            break;

        n = recv_packet(st->sock, recv_buf, sizeof(recv_buf));
        if (n < 0)
            continue;

        if ((size_t)n <
            sizeof(struct ether_header) + sizeof(struct ether_arp)) {
            continue;
        }

        r_eth = (struct ether_header *)recv_buf;

        if (ntohs(r_eth->ether_type) != ETH_P_ARP) {
            continue;
        }

        r_arp = (struct ether_arp *)(recv_buf + sizeof(struct ether_header));
        if (ntohs(r_arp->arp_op) != ARPOP_REPLY) {
            continue;
        }

        recv_time = get_time_ns();

        match_seq = st->next_timeout_check_seq;
        while (match_seq != (u_short)(st->sent & 0xFFFF) &&
               st->replied_or_timeout[match_seq]) {
            match_seq++;
        }

        if (match_seq != (u_short)(st->sent & 0xFFFF)) {
            if (st->sent_times[match_seq] > 0 &&
                recv_time >= st->sent_times[match_seq]) {
                rtt = time_diff_ns(st->sent_times[match_seq], recv_time);
            }
            st->replied_or_timeout[match_seq] = true;
        }

        if (handle_arp_reply(config, st, r_arp, rtt)) {
            if (config->dad || config->count == 1 || config->quit_on_reply) {
                keep_running = false;
            }
        }
    }
}

static void
print_arping_stats(const arping_config_t *config, const arping_state_t *st)
{
    if (config->quiet)
        return;

    if (config->cisco_style) {
        printf("\nSuccess rate is %u percent (%u/%u)\n",
               st->sent == 0 ? 0 : ((st->received * 100) / st->sent),
               st->received, st->sent);
    } else {
        printf("\n--- %s arping statistics ---\n", inet_ntoa(st->target_in));
        printf("%u packets transmitted, %u packets received, %u%% "
               "packet loss\n",
               st->sent, st->received,
               st->sent == 0 ? 0
                             : ((st->sent - st->received) * 100 / st->sent));
    }
}

static int
arping_run(const arping_config_t *config)
{
    arping_state_t st;
    struct sigaction sa;
    u_int64_t next_send_time;

    init_arping_state(config, &st);

    if (setup_arping_socket(config, &st) < 0) {
        free(st.sent_times);
        free(st.replied_or_timeout);
        return EXIT_FAILURE;
    }

    if (setgid(getgid()) != 0) {
        log_warn("Failed to drop group privileges");
    }
    if (setuid(getuid()) != 0) {
        log_warn("Failed to drop user privileges");
    }

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = handle_sigint;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGQUIT, &sa, NULL);

    if (!config->quiet) {
        if (config->cisco_style) {
            char tgt_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &st.target_in, tgt_str, sizeof(tgt_str));
            printf("Sending %u, 28-byte ARP Requests to %s, "
                   "timeout is %u seconds:\n",
                   config->count, tgt_str,
                   (unsigned int)(config->timeout_ns / NS_PER_S));
        } else {
            char tgt_str[INET_ADDRSTRLEN], src_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &st.target_in, tgt_str, sizeof(tgt_str));
            inet_ntop(AF_INET, &st.source_in, src_str, sizeof(src_str));
            printf("ARPING %s from %s %s\n", tgt_str, src_str, config->iface);
        }
    }

    next_send_time = get_time_ns();

    while (keep_running) {
        u_int64_t now = get_time_ns();
        int timeout_ms = 1;
        struct pollfd pfd;
        int ret;

        if ((config->count == 0 || st.sent < config->count) &&
            now >= next_send_time) {
            u_short short_seq = (u_short)(st.sent & 0xFFFF);
            st.sent_times[short_seq] = now;
            st.replied_or_timeout[short_seq] = false;

            if (!send_arping_probe(config, &st)) {
                break;
            }

            next_send_time = now + config->interval_ns;
        }

        now = get_time_ns();
        while (st.next_timeout_check_seq != (u_short)(st.sent & 0xFFFF)) {
            u_short chk_seq = st.next_timeout_check_seq;
            if (st.replied_or_timeout[chk_seq]) {
                st.next_timeout_check_seq++;
                continue;
            }
            if (now >= st.sent_times[chk_seq] + config->timeout_ns) {
                st.replied_or_timeout[chk_seq] = true;
                if (!config->quiet) {
                    if (config->cisco_style) {
                        printf(".");
                        fflush(stdout);
                    } else {
                        printf("Timeout waiting for reply from %s\n",
                               inet_ntoa(st.target_in));
                    }
                }
                st.next_timeout_check_seq++;
            } else {
                break;
            }
        }

        if (config->count > 0 && st.sent >= config->count &&
            st.next_timeout_check_seq == (u_short)(st.sent & 0xFFFF)) {
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
            if (st.next_timeout_check_seq != (u_short)(st.sent & 0xFFFF)) {
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
            drain_arping_replies(config, &st);
        }
    }

    print_arping_stats(config, &st);
    close_raw_socket(st.sock);

    free(st.sent_times);
    free(st.replied_or_timeout);

    if (config->dad) {
        return (st.received > 0) ? EXIT_FAILURE : EXIT_SUCCESS;
    }
    return (st.received > 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

static const cli_option_t arping_options[] = {
    {'I', "interface", "specify network interface (e.g. eth0)"},
    {'c', "count", "stop after sending count ARP requests"},
    {'w', "timeout", "time to wait for reply in milliseconds (default 1000)"},
    {'i', "interval",
     "time to wait between requests in milliseconds (default 1000)"},
    {'S', "source_ip", "specify source IP address (default is interface IP)"},
    {'U', NULL, "unsolicited ARP mode (updates neighbors' ARP caches)"},
    {'d', NULL, "duplicate address detection (DAD) mode"},
    {'G', NULL, "use default gateway as target"},
    {'C', NULL, "cisco style output (! for reply, . for timeout)"},
    {'f', NULL, "quit on first reply"},
    {'A', NULL, "send ARP reply instead of request"},
    {'b', NULL,
     "keep broadcasting (do not switch to unicast after first reply)"},
    {'u', "unit", "time unit for output (ns, μs, ms). default: auto-scaling"},
    {'q', NULL, "quiet output"},
    {'h', NULL, "print help and exit"},
    {0, NULL, NULL}};

static void
print_usage(const char *prog_name)
{
    cli_app_t app = {.prog_name = prog_name,
                     .usage_args = "-I interface [options] <destination>",
                     .options = arping_options};
    cli_print_help(&app);
}

int
arping_main(int c, char **av)
{
    arping_config_t config;
    const char *source_ip_str = NULL;
    int ch;
    const char *target_ip_str;

    optind = 1;
    memset(&config, 0, sizeof(config));

    config.count = 0;
    config.timeout_ns = NS_PER_S;
    config.interval_ns = NS_PER_S;

    while ((ch = getopt(c, av, "I:c:w:i:S:qUdGCfAbu:h")) != -1) {
        switch (ch) {
        case 'I':
            config.iface = optarg;
            break;
        case 'c':
            config.count = (u_int)atoi(optarg);
            break;
        case 'w':
            config.timeout_ns = (u_int64_t)atoi(optarg) * NS_PER_MS;
            break;
        case 'i':
            config.interval_ns = (u_int64_t)atoi(optarg) * NS_PER_MS;
            break;
        case 'S':
            source_ip_str = optarg;
            break;
        case 'q':
            config.quiet = true;
            break;
        case 'U':
            config.unsolicited = true;
            break;
        case 'd':
            config.dad = true;
            break;
        case 'G':
            config.gateway = true;
            break;
        case 'C':
            config.cisco_style = true;
            break;
        case 'f':
            config.quit_on_reply = true;
            break;
        case 'A':
            config.use_reply = true;
            break;
        case 'b':
            config.keep_broadcast = true;
            break;
        case 'u':
            config.time_unit = optarg;
            break;
        case 'h':
            print_usage(*av);
            return EXIT_SUCCESS;
        default:
            print_usage(*av);
            goto err;
        }
    }

    if (!config.iface) {
        log_err("Network interface is required (-I option)");
        print_usage(*av);
        goto err;
    }

    c -= optind;
    av += optind;

    if (c < 1 && !config.gateway && !config.unsolicited) {
        log_err("Target IP/hostname is required");
        goto err;
    }

    if (!get_iface_mac(config.iface, config.source_mac)) {
        die("Failed to get MAC address for interface %s", config.iface);
    }

    if (config.dad) {

        config.source_ip = 0;
    } else if (source_ip_str) {
        if (!resolve_ipv4(source_ip_str, &config.source_ip)) {
            die("Invalid source IP address or hostname: %s", source_ip_str);
        }
    } else {
        if (!get_iface_addr(config.iface, &config.source_ip)) {
            log_warn("Failed to get IP address for interface %s, "
                     "using 0.0.0.0",
                     config.iface);
            config.source_ip = 0;
        }
    }

    if (config.gateway) {

        if (!get_default_gateway(config.iface, &config.target_ip)) {
            die("Failed to automatically determine the default "
                "gateway");
        }
    } else if (config.unsolicited) {
        config.target_ip = config.source_ip;
    } else {
        if (c < 1) {
            log_err("Missing destination IP address");
            print_usage(*av);
            goto err;
        }
        target_ip_str = *av;
        if (!resolve_ipv4(target_ip_str, &config.target_ip)) {
            die("Invalid target IP address or hostname: %s", target_ip_str);
        }
    }

    if (config.cisco_style && config.count == 0) {
        config.count = 5;
    }

    if (getuid() != 0) {
        log_warn("arping may require root privileges to open raw sockets.");
    }

    return arping_run(&config);

err:
    return EXIT_FAILURE;
}
