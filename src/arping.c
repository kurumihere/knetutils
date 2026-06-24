#include "arping.h"
#include "net.h"
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

#ifndef ETH_P_ARP
#define ETH_P_ARP ETHERTYPE_ARP
#endif

#ifndef ETH_P_IP
#define ETH_P_IP ETHERTYPE_IP
#endif

static volatile bool keep_running = true;

static void
handle_sigint(int sig)
{
        (void)sig;
        keep_running = false;
}

static void
print_mac(const uint8_t *mac)
{
        printf("%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3],
               mac[4], mac[5]);
}

int
arping_run(const arping_config_t *config)
{
        net_socket_t *sock = net_open_raw_socket(config->iface, ETH_P_ARP);
        if (!sock) {
                log_err("Failed to open raw socket on interface %s",
                        config->iface);
                return -1;
        }

        if (setgid(getgid()) != 0) {
                log_warn("Failed to drop group privileges");
        }
        if (setuid(getuid()) != 0) {
                log_warn("Failed to drop user privileges");
        }

        struct sigaction sa;
        memset(&sa, 0, sizeof(sa));
        sa.sa_handler = handle_sigint;
        sigaction(SIGINT, &sa, NULL);

        struct in_addr target_in = {.s_addr = config->target_ip};
        struct in_addr source_in = {.s_addr = config->source_ip};

        if (!config->quiet) {
                if (config->cisco_style) {
                        char tgt_str[INET_ADDRSTRLEN];
                        inet_ntop(AF_INET, &target_in, tgt_str,
                                  sizeof(tgt_str));
                        printf(
                            "Sending %u, 28-byte ARP Requests to %s, timeout "
                            "is %u seconds:\n",
                            config->count, tgt_str,
                            (unsigned int)(config->timeout_ns / 1000000000ULL));
                } else {
                        char tgt_str[INET_ADDRSTRLEN], src_str[INET_ADDRSTRLEN];
                        inet_ntop(AF_INET, &target_in, tgt_str,
                                  sizeof(tgt_str));
                        inet_ntop(AF_INET, &source_in, src_str,
                                  sizeof(src_str));
                        printf("ARPING %s from %s %s\n", tgt_str, src_str,
                               config->iface);
                }
        }

        uint8_t target_mac_broadcast[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
        uint8_t target_mac_zero[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
        uint8_t current_target_mac[6];
        memcpy(current_target_mac, target_mac_broadcast, 6);

        uint32_t sent = 0;
        uint32_t received = 0;

        struct pollfd pfd;
        pfd.fd = net_get_fd(sock);
        pfd.events = POLLIN;

        while (keep_running && (config->count == 0 || sent < config->count)) {
                uint8_t buffer[sizeof(struct ether_header) +
                               sizeof(struct ether_arp)];
                struct ether_header *eth = (struct ether_header *)buffer;
                struct ether_arp *arp =
                    (struct ether_arp *)(buffer + sizeof(struct ether_header));

                memcpy(eth->ether_dhost, current_target_mac, 6);
                memcpy(eth->ether_shost, config->source_mac, 6);
                eth->ether_type = htons(ETH_P_ARP);

                arp->arp_hrd = htons(ARPHRD_ETHER);
                arp->arp_pro = htons(ETH_P_IP);
                arp->arp_hln = 6;
                arp->arp_pln = 4;
                arp->arp_op = config->use_reply ? htons(ARPOP_REPLY)
                                                : htons(ARPOP_REQUEST);

                memcpy(arp->arp_sha, config->source_mac, 6);
                memcpy(arp->arp_spa, &config->source_ip, 4);
                memcpy(arp->arp_tha,
                       memcmp(current_target_mac, target_mac_broadcast, 6) == 0
                           ? target_mac_zero
                           : current_target_mac,
                       6);
                memcpy(arp->arp_tpa, &config->target_ip, 4);

                uint64_t send_time = get_time_ns();
                if (net_send_packet(sock, buffer, sizeof(buffer),
                                    current_target_mac) < 0) {
                        log_err("Failed to send ARP packet");
                        break;
                }
                sent++;

                uint64_t now = get_time_ns();
                uint64_t expire = now + config->timeout_ns;

                bool got_reply = false;
                while (get_time_ns() < expire && keep_running) {
                        int64_t timeout_ns = expire - get_time_ns();
                        if (timeout_ns <= 0)
                                break;
                        int timeout_ms = timeout_ns / 1000000;

                        int ret =
                            poll(&pfd, 1, timeout_ms > 0 ? timeout_ms : 1);
                        if (ret < 0) {
                                break;
                        } else if (ret == 0) {
                                break;
                        }

                        if (!(pfd.revents & POLLIN))
                                continue;

                        uint8_t recv_buf[4096];
                        ssize_t n =
                            net_recv_packet(sock, recv_buf, sizeof(recv_buf));
                        if (n < 0)
                                continue;

                        if ((size_t)n < sizeof(struct ether_header) +
                                            sizeof(struct ether_arp)) {
                                continue;
                        }

                        struct ether_header *r_eth =
                            (struct ether_header *)recv_buf;
                        if (ntohs(r_eth->ether_type) != ETH_P_ARP) {
                                continue;
                        }

                        struct ether_arp *r_arp =
                            (struct ether_arp *)(recv_buf +
                                                 sizeof(struct ether_header));
                        if (ntohs(r_arp->arp_op) != ARPOP_REPLY) {
                                continue;
                        }

                        uint32_t reply_spa;
                        memcpy(&reply_spa, r_arp->arp_spa, 4);

                        if (reply_spa != config->target_ip) {
                                continue;
                        }

                        uint64_t recv_time = get_time_ns();
                        uint64_t rtt = time_diff_ns(send_time, recv_time);
                        if (!config->quiet) {
                                if (config->cisco_style) {
                                        printf("!");
                                        fflush(stdout);
                                } else {
                                        char time_buf[64];
                                        format_time(rtt, config->time_unit,
                                                    time_buf, sizeof(time_buf));
                                        printf("Unicast reply from %s [",
                                               inet_ntoa(target_in));
                                        print_mac(r_arp->arp_sha);
                                        printf("]  %s\n", time_buf);
                                }
                        }

                        if (!config->keep_broadcast) {
                                memcpy(current_target_mac, r_arp->arp_sha, 6);
                        }

                        received++;
                        got_reply = true;
                        if (config->dad || config->count == 1 ||
                            config->quit_on_reply) {
                                keep_running = false;
                        }
                        break;
                }

                if (!keep_running)
                        break;

                if (!got_reply && !config->quiet) {
                        if (config->cisco_style) {
                                printf(".");
                                fflush(stdout);
                        } else {
                                printf("Timeout waiting for reply from %s\n",
                                       inet_ntoa(target_in));
                        }
                }

                if (keep_running &&
                    (config->count == 0 || sent < config->count)) {
                        uint64_t current = get_time_ns();
                        uint64_t next_send = send_time + config->interval_ns;
                        if (current < next_send) {
                                usleep((next_send - current) / 1000);
                        }
                }
        }

        if (!config->quiet) {
                if (config->cisco_style) {
                        printf("\nSuccess rate is %u percent (%u/%u)\n",
                               sent == 0 ? 0 : ((received * 100) / sent),
                               received, sent);
                } else {
                        printf("\n--- %s arping statistics ---\n",
                               inet_ntoa(target_in));
                        printf(
                            "%u packets transmitted, %u packets received, %u%% "
                            "packet loss\n",
                            sent, received,
                            sent == 0 ? 0 : ((sent - received) * 100 / sent));
                }
        }

        net_close_raw_socket(sock);

        if (config->dad) {
                return (received > 0) ? 1 : 0;
        }
        return (received > 0) ? 0 : 1;
}
