#include "sniff.h"
#include "net.h"
#include "utils.h"

#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/icmp6.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifndef ETH_P_ALL
#define ETH_P_ALL 0x0003
#endif

static volatile sig_atomic_t keep_running = 1;

static void
handle_sigint(int sig)
{
        (void)sig;
        keep_running = 0;
}

typedef struct {
        net_socket_t *sock;
        int packets_captured;
} sniff_state_t;

static void
print_hex_dump(const uint8_t *data, size_t len)
{
        for (size_t i = 0; i < len; i += 16) {
                printf("  \033[90m%04zx\033[0m  ", i);
                for (size_t j = 0; j < 16; j++) {
                        if (i + j < len) {
                                printf("%02x ", data[i + j]);
                        } else {
                                printf("   ");
                        }
                }
                printf(" \033[90m|\033[0m ");
                for (size_t j = 0; j < 16; j++) {
                        if (i + j < len) {
                                uint8_t c = data[i + j];
                                if (c >= 32 && c <= 126) {
                                        printf("%c", c);
                                } else {
                                        printf(".");
                                }
                        } else {
                                break;
                        }
                }
                printf("\n");
        }
}

static size_t
handle_tcp(const uint8_t *buf, size_t offset, ssize_t n)
{
        if (n < (ssize_t)(offset + sizeof(struct tcphdr)))
                return offset;

        struct tcphdr *tcp = (struct tcphdr *)(buf + offset);
        printf("    \033[1;36m[TCP]\033[0m %u -> %u [", ntohs(tcp->th_sport),
               ntohs(tcp->th_dport));
        if (tcp->th_flags & TH_SYN)
                printf("S");
        if (tcp->th_flags & TH_ACK)
                printf("A");
        if (tcp->th_flags & TH_FIN)
                printf("F");
        if (tcp->th_flags & TH_RST)
                printf("R");
        if (tcp->th_flags & TH_PUSH)
                printf("P");
        if (tcp->th_flags & TH_URG)
                printf("U");
        printf("] Seq: %u, Ack: %u, Win: %u\n", ntohl(tcp->th_seq),
               ntohl(tcp->th_ack), ntohs(tcp->th_win));

        return offset + (tcp->th_off << 2);
}

static size_t
handle_udp(const uint8_t *buf, size_t offset, ssize_t n)
{
        if (n < (ssize_t)(offset + sizeof(struct udphdr)))
                return offset;

        struct udphdr *udp = (struct udphdr *)(buf + offset);
        printf("    \033[1;36m[UDP]\033[0m %u -> %u (Len: %u)\n",
               ntohs(udp->uh_sport), ntohs(udp->uh_dport), ntohs(udp->uh_ulen));

        return offset + sizeof(struct udphdr);
}

static size_t
handle_icmp(const uint8_t *buf, size_t offset, ssize_t n)
{
        if (n < (ssize_t)(offset + 8))
                return offset;

        struct icmp *icmp = (struct icmp *)(buf + offset);
        printf("    \033[1;36m[ICMP]\033[0m Type: %u, Code: %u\n",
               icmp->icmp_type, icmp->icmp_code);

        return offset + 8;
}

static size_t
handle_icmpv6(const uint8_t *buf, size_t offset, ssize_t n)
{
        if (n < (ssize_t)(offset + sizeof(struct icmp6_hdr)))
                return offset;

        struct icmp6_hdr *icmp6 = (struct icmp6_hdr *)(buf + offset);
        printf("    \033[1;36m[ICMPv6]\033[0m Type: %u, Code: %u\n",
               icmp6->icmp6_type, icmp6->icmp6_code);

        return offset + sizeof(struct icmp6_hdr);
}

static size_t
handle_l4_protocol(const uint8_t *buf, size_t offset, ssize_t n,
                   uint8_t l4_proto)
{
        if (l4_proto == IPPROTO_TCP) {
                return handle_tcp(buf, offset, n);
        } else if (l4_proto == IPPROTO_UDP) {
                return handle_udp(buf, offset, n);
        } else if (l4_proto == IPPROTO_ICMP) {
                return handle_icmp(buf, offset, n);
        } else if (l4_proto == IPPROTO_ICMPV6) {
                return handle_icmpv6(buf, offset, n);
        }
        return offset;
}

static size_t
handle_ipv4(const uint8_t *buf, size_t offset, ssize_t n, uint8_t *l4_proto)
{
        if (n < (ssize_t)(offset + sizeof(struct ip)))
                return offset;

        struct ip *ip_hdr = (struct ip *)(buf + offset);
        int hlen = ip_hdr->ip_hl << 2;
        *l4_proto = ip_hdr->ip_p;

        char src_ip[INET_ADDRSTRLEN];
        char dst_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &ip_hdr->ip_src, src_ip, sizeof(src_ip));
        inet_ntop(AF_INET, &ip_hdr->ip_dst, dst_ip, sizeof(dst_ip));

        printf("\033[1;32m[IPv4]\033[0m %s -> %s (Proto: %u, Len: %u)\n",
               src_ip, dst_ip, ip_hdr->ip_p, ntohs(ip_hdr->ip_len));

        return offset + hlen;
}

static size_t
handle_ipv6(const uint8_t *buf, size_t offset, ssize_t n, uint8_t *l4_proto)
{
        if (n < (ssize_t)(offset + sizeof(struct ip6_hdr)))
                return offset;

        struct ip6_hdr *ip6 = (struct ip6_hdr *)(buf + offset);
        *l4_proto = ip6->ip6_nxt;

        char src_ip[INET6_ADDRSTRLEN];
        char dst_ip[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &ip6->ip6_src, src_ip, sizeof(src_ip));
        inet_ntop(AF_INET6, &ip6->ip6_dst, dst_ip, sizeof(dst_ip));

        printf("\033[1;32m[IPv6]\033[0m %s -> %s (Next: %u)\n", src_ip, dst_ip,
               ip6->ip6_nxt);

        return offset + sizeof(struct ip6_hdr);
}

static void
process_packet(const sniff_config_t *config, const uint8_t *buf, ssize_t n)
{
        if (n < (ssize_t)sizeof(struct ether_header))
                return;

        struct ether_header *eth = (struct ether_header *)buf;
        uint16_t eth_type = ntohs(eth->ether_type);

        printf("\n\033[1;34m[MAC]\033[0m %02x:%02x:%02x:%02x:%02x:%02x -> "
               "%02x:%02x:%02x:%02x:%02x:%02x (Type: 0x%04x)\n",
               eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2],
               eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5],
               eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2],
               eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5],
               eth_type);

        uint8_t l4_proto = 0;
        size_t offset = sizeof(struct ether_header);
        size_t next_offset = offset;

        if (eth_type == ETHERTYPE_IP) {
                next_offset = handle_ipv4(buf, offset, n, &l4_proto);
        } else if (eth_type == ETHERTYPE_IPV6) {
                next_offset = handle_ipv6(buf, offset, n, &l4_proto);
        }

        offset = next_offset;

        if (config->verbosity >= 1 && l4_proto != 0) {
                offset = handle_l4_protocol(buf, offset, n, l4_proto);
        }

        if (config->verbosity >= 3 && n > 0) {
                printf("    \033[1;35m[Full Packet Dump]\033[0m\n");
                print_hex_dump(buf, n);
        } else if (config->verbosity >= 2 && (ssize_t)offset < n) {
                printf("    \033[1;35m[Payload Dump]\033[0m\n");
                print_hex_dump(buf + offset, n - offset);
        }
}

int
sniff_run(const sniff_config_t *config)
{
        if (!config->iface) {
                log_err("Interface is required for sniffing");
                return EXIT_FAILURE;
        }

        struct sigaction sa;
        memset(&sa, 0, sizeof(sa));
        sa.sa_handler = handle_sigint;
        sigaction(SIGINT, &sa, NULL);
        sigaction(SIGTERM, &sa, NULL);
        sigaction(SIGQUIT, &sa, NULL);

        sniff_state_t st;
        st.packets_captured = 0;
        st.sock = net_open_raw_socket(config->iface, ETH_P_ALL);

        if (!st.sock) {
                die("Failed to open raw socket. Are you root?");
        }

        if (!net_set_promiscuous(st.sock)) {
                log_warn("Failed to set promiscuous mode. Sniffing might be "
                         "limited.");
        }

        if (setuid(getuid()) != 0) {
                log_warn("Failed to drop user privileges");
        }

        log_info("Sniffing on interface %s...", config->iface);

        __attribute__((aligned(8))) uint8_t buf[65536];

        while (keep_running && (config->max_packets == 0 ||
                                st.packets_captured < config->max_packets)) {
                ssize_t n = net_recv_packet(st.sock, buf, sizeof(buf));
                if (n <= 0)
                        continue;

                process_packet(config, buf, n);
                st.packets_captured++;
        }

        net_close_raw_socket(st.sock);
        printf("\n");
        log_info("Captured %d packets", st.packets_captured);

        return EXIT_SUCCESS;
}
