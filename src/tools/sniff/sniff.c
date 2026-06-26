/***************************************************************************
 * sniff.c -- Network sniffer utility logic                                *
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
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#ifndef ETH_P_ALL
#define ETH_P_ALL 0x0003
#endif

#define PCAP_MAGIC_NUMBER 0xa1b2c3d4
#define PCAP_VERSION_MAJOR 2
#define PCAP_VERSION_MINOR 4
#define PCAP_LINKTYPE_ETHERNET 1
#define PCAP_SNAPLEN 65535

#define HEXDUMP_ROW_LEN 16
#define PRINTABLE_MIN 32
#define PRINTABLE_MAX 126
#define TCP_HDR_LEN_SHIFT 2
#define IPV4_HLEN_SHIFT 2
#define ICMP_MIN_HDR_LEN 8
#define SNIFF_BUF_SIZE 65536

typedef struct {
        u_int magic_number;
        u_short version_major;
        u_short version_minor;
        int thiszone;
        u_int sigfigs;
        u_int snaplen;
        u_int network;
} pcap_hdr_t;

typedef struct {
        u_int ts_sec;
        u_int ts_usec;
        u_int incl_len;
        u_int orig_len;
} pcaprec_hdr_t;

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
        FILE *pcap_fp;
} sniff_state_t;

static void
write_pcap_packet(FILE *fp, const u_char *buf, ssize_t len)
{
        struct timespec ts;
        pcaprec_hdr_t rec;

        if (!fp) {
                return;
        }

        clock_gettime(CLOCK_REALTIME, &ts);
        rec.ts_sec = (u_int)ts.tv_sec;
        rec.ts_usec = (u_int)(ts.tv_nsec / NS_PER_US);
        rec.incl_len = (u_int)len;
        rec.orig_len = (u_int)len;

        fwrite(&rec, sizeof(rec), 1, fp);
        fwrite(buf, 1, len, fp);
        fflush(fp);
}

inline static void
print_hex_dump_line(const u_char *data, size_t len, size_t offset)
{
        size_t j;
        u_char c;

        for (j = 0; j < HEXDUMP_ROW_LEN; j++) {
                if (offset + j < len) {
                        printf("%02x ", data[offset + j]);
                        continue;
                }
                printf("   ");
        }

        printf(" \033[90m|\033[0m ");

        for (j = 0; j < HEXDUMP_ROW_LEN; j++) {
                if (offset + j >= len) {
                        break;
                }

                c = data[offset + j];
                if (c >= PRINTABLE_MIN && c <= PRINTABLE_MAX) {
                        printf("%c", c);
                        continue;
                }
                printf(".");
        }
        printf("\n");
}

static void
print_hex_dump(const u_char *data, size_t len)
{
        size_t i;

        for (i = 0; i < len; i += HEXDUMP_ROW_LEN) {
                printf("  \033[90m%04zx\033[0m  ", i);
                print_hex_dump_line(data, len, i);
        }
}

static size_t
handle_tcp(const u_char *buf, size_t offset, ssize_t n)
{
        struct tcphdr *tcp;

        if (n < (ssize_t)(offset + sizeof(struct tcphdr))) {
                return offset;
        }

        tcp = (struct tcphdr *)(buf + offset);

        printf("    \033[1;36m[TCP]\033[0m %u -> %u [", ntohs(tcp->th_sport),
               ntohs(tcp->th_dport));

        if (tcp->th_flags & TH_SYN) {
                printf("S");
        }
        if (tcp->th_flags & TH_ACK) {
                printf("A");
        }
        if (tcp->th_flags & TH_FIN) {
                printf("F");
        }
        if (tcp->th_flags & TH_RST) {
                printf("R");
        }
        if (tcp->th_flags & TH_PUSH) {
                printf("P");
        }
        if (tcp->th_flags & TH_URG) {
                printf("U");
        }

        printf("] Seq: %u, Ack: %u, Win: %u\n", ntohl(tcp->th_seq),
               ntohl(tcp->th_ack), ntohs(tcp->th_win));

        return offset + (tcp->th_off << TCP_HDR_LEN_SHIFT);
}

static size_t
handle_udp(const u_char *buf, size_t offset, ssize_t n)
{
        struct udphdr *udp;

        if (n < (ssize_t)(offset + sizeof(struct udphdr))) {
                return offset;
        }

        udp = (struct udphdr *)(buf + offset);

        printf("    \033[1;36m[UDP]\033[0m %u -> %u (Len: %u)\n",
               ntohs(udp->uh_sport), ntohs(udp->uh_dport), ntohs(udp->uh_ulen));

        return offset + sizeof(struct udphdr);
}

static size_t
handle_icmp(const u_char *buf, size_t offset, ssize_t n)
{
        struct icmp *icmp;

        if (n < (ssize_t)(offset + ICMP_MIN_HDR_LEN)) {
                return offset;
        }

        icmp = (struct icmp *)(buf + offset);

        printf("    \033[1;36m[ICMP]\033[0m Type: %u, Code: %u\n",
               icmp->icmp_type, icmp->icmp_code);

        return offset + ICMP_MIN_HDR_LEN;
}

static size_t
handle_icmpv6(const u_char *buf, size_t offset, ssize_t n)
{
        struct icmp6_hdr *icmp6;

        if (n < (ssize_t)(offset + sizeof(struct icmp6_hdr))) {
                return offset;
        }

        icmp6 = (struct icmp6_hdr *)(buf + offset);

        printf("    \033[1;36m[ICMPv6]\033[0m Type: %u, Code: %u\n",
               icmp6->icmp6_type, icmp6->icmp6_code);

        return offset + sizeof(struct icmp6_hdr);
}

static size_t
handle_l4_protocol(const u_char *buf, size_t offset, ssize_t n, u_char l4_proto)
{
        if (l4_proto == IPPROTO_TCP) {
                return handle_tcp(buf, offset, n);
        }

        if (l4_proto == IPPROTO_UDP) {
                return handle_udp(buf, offset, n);
        }

        if (l4_proto == IPPROTO_ICMP) {
                return handle_icmp(buf, offset, n);
        }

        if (l4_proto == IPPROTO_ICMPV6) {
                return handle_icmpv6(buf, offset, n);
        }

        return offset;
}

static size_t
handle_ipv4(const u_char *buf, size_t offset, ssize_t n, u_char *l4_proto)
{
        struct ip *ip_hdr;
        int hlen;
        char src_ip[INET_ADDRSTRLEN];
        char dst_ip[INET_ADDRSTRLEN];

        if (n < (ssize_t)(offset + sizeof(struct ip))) {
                return offset;
        }

        ip_hdr = (struct ip *)(buf + offset);

        hlen = ip_hdr->ip_hl << IPV4_HLEN_SHIFT;

        *l4_proto = ip_hdr->ip_p;

        inet_ntop(AF_INET, &ip_hdr->ip_src, src_ip, sizeof(src_ip));
        inet_ntop(AF_INET, &ip_hdr->ip_dst, dst_ip, sizeof(dst_ip));

        printf("\033[1;32m[IPv4]\033[0m %s -> %s (Proto: %u, Len: %u)\n",
               src_ip, dst_ip, ip_hdr->ip_p, ntohs(ip_hdr->ip_len));

        return offset + hlen;
}

static size_t
handle_ipv6(const u_char *buf, size_t offset, ssize_t n, u_char *l4_proto)
{
        struct ip6_hdr *ip6;
        char src_ip[INET6_ADDRSTRLEN];
        char dst_ip[INET6_ADDRSTRLEN];

        if (n < (ssize_t)(offset + sizeof(struct ip6_hdr))) {
                return offset;
        }

        ip6 = (struct ip6_hdr *)(buf + offset);

        *l4_proto = ip6->ip6_nxt;

        inet_ntop(AF_INET6, &ip6->ip6_src, src_ip, sizeof(src_ip));
        inet_ntop(AF_INET6, &ip6->ip6_dst, dst_ip, sizeof(dst_ip));

        printf("\033[1;32m[IPv6]\033[0m %s -> %s (Next: %u)\n", src_ip, dst_ip,
               ip6->ip6_nxt);

        return offset + sizeof(struct ip6_hdr);
}

static void
process_packet(const sniff_config_t *config, const u_char *buf, ssize_t n)
{
        struct ether_header *eth;
        u_short eth_type;
        u_char l4_proto;
        size_t offset;
        size_t next_offset;

        l4_proto = 0;

        if (n < (ssize_t)sizeof(struct ether_header)) {
                return;
        }

        eth = (struct ether_header *)buf;

        eth_type = ntohs(eth->ether_type);

        printf("\n\033[1;34m[MAC]\033[0m %02x:%02x:%02x:%02x:%02x:%02x -> "
               "%02x:%02x:%02x:%02x:%02x:%02x (Type: 0x%04x)\n",
               eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2],
               eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5],
               eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2],
               eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5],
               eth_type);

        offset = sizeof(struct ether_header);
        next_offset = offset;

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
        struct sigaction sa;
        sniff_state_t st;
        __attribute__((aligned(8))) u_char buf[SNIFF_BUF_SIZE];
        ssize_t n;
        int ret = EXIT_SUCCESS;

        if (!config->iface) {
                log_err("Interface is required for sniffing");
                ret = EXIT_FAILURE;
                goto out;
        }

        memset(&sa, 0, sizeof(sa));
        sa.sa_handler = handle_sigint;
        sigaction(SIGINT, &sa, NULL);
        sigaction(SIGTERM, &sa, NULL);
        sigaction(SIGQUIT, &sa, NULL);

        st.packets_captured = 0;
        st.pcap_fp = NULL;
        st.sock = net_open_raw_socket(config->iface, ETH_P_ALL);

        if (!st.sock) {
                die("Failed to open raw socket. Are you root?");
        }

        if (config->pcap_file) {
                st.pcap_fp = fopen(config->pcap_file, "wb");
                if (!st.pcap_fp) {
                        log_warn("Failed to open PCAP file for writing: %s",
                                 config->pcap_file);
                } else {
                        pcap_hdr_t hdr;

                        memset(&hdr, 0, sizeof(hdr));
                        hdr.magic_number = PCAP_MAGIC_NUMBER;
                        hdr.version_major = PCAP_VERSION_MAJOR;
                        hdr.version_minor = PCAP_VERSION_MINOR;
                        hdr.thiszone = 0;
                        hdr.sigfigs = 0;
                        hdr.snaplen = PCAP_SNAPLEN;
                        hdr.network = PCAP_LINKTYPE_ETHERNET;

                        fwrite(&hdr, sizeof(hdr), 1, st.pcap_fp);
                        log_info("Writing packets to PCAP file: %s",
                                 config->pcap_file);
                }
        }

        if (!net_set_promiscuous(st.sock)) {
                log_warn("Failed to set promiscuous mode. Sniffing might be "
                         "limited.");
        }

        if (setuid(getuid()) != 0) {
                log_warn("Failed to drop user privileges");
        }

        log_info("Sniffing on interface %s...", config->iface);

        while (keep_running) {
                if (config->max_packets > 0 &&
                    st.packets_captured >= config->max_packets) {
                        break;
                }

                n = net_recv_packet(st.sock, buf, sizeof(buf));
                if (n <= 0) {
                        continue;
                }

                process_packet(config, buf, n);
                write_pcap_packet(st.pcap_fp, buf, n);

                st.packets_captured++;
        }

        if (st.pcap_fp) {
                fclose(st.pcap_fp);
        }

        if (st.sock) {
                net_close_raw_socket(st.sock);
        }
        printf("\n");
        log_info("Captured %d packets", st.packets_captured);

out:
        return ret;
}
