import re

sniff_c = r"""/***************************************************************************
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

/*
 *		H A N D L E _ S I G I N T
 *
 * Signal handler for SIGINT, gracefully stops the capture loop.
 */
static void
handle_sigint(int sig)
{
        (void)sig;
        /* Set flag to break out of the loop gracefully */
        keep_running = 0;
}

typedef struct {
        net_socket_t *sock;
        int packets_captured;
        FILE *pcap_fp;
} sniff_state_t;

/*
 *		W R I T E _ P C A P _ P A C K E T
 *
 * Append a captured packet to the PCAP file.
 */
static void
write_pcap_packet(FILE *fp, const u_char *buf, ssize_t len)
{
        struct timespec ts;
        pcaprec_hdr_t rec;

        /* If no file pointer is provided, return early */
        if (!fp) {
                return;
        }

        /* Fetch current time for PCAP timestamp */
        clock_gettime(CLOCK_REALTIME, &ts);
        rec.ts_sec = (u_int)ts.tv_sec;
        rec.ts_usec = (u_int)(ts.tv_nsec / NS_PER_US);
        rec.incl_len = (u_int)len;
        rec.orig_len = (u_int)len;

        /* Write header and packet data to disk */
        fwrite(&rec, sizeof(rec), 1, fp);
        fwrite(buf, 1, len, fp);
        fflush(fp);
}

/*
 *		P R I N T _ H E X _ D U M P _ L I N E
 *
 * Helper function to print a single line of a hex dump.
 */
inline static void
print_hex_dump_line(const u_char *data, size_t len, size_t offset)
{
        size_t j;
        u_char c;

        /* Print hex values for the current row */
        for (j = 0; j < HEXDUMP_ROW_LEN; j++) {
                if (offset + j < len) {
                        printf("%02x ", data[offset + j]);
                        continue;
                }
                /* Pad for incomplete rows */
                printf("   ");
        }

        printf(" \033[90m|\033[0m ");

        /* Print ASCII representation for the current row */
        for (j = 0; j < HEXDUMP_ROW_LEN; j++) {
                if (offset + j >= len) {
                        break;
                }
                
                c = data[offset + j];
                /* Check if character is printable ASCII */
                if (c >= PRINTABLE_MIN && c <= PRINTABLE_MAX) {
                        printf("%c", c);
                        continue;
                }
                /* Print dot for non-printable characters */
                printf(".");
        }
        printf("\n");
}

/*
 *		P R I N T _ H E X _ D U M P
 *
 * Print a buffer in canonical hex dump format.
 */
static void
print_hex_dump(const u_char *data, size_t len)
{
        size_t i;

        /* Iterate through buffer in rows and print them */
        for (i = 0; i < len; i += HEXDUMP_ROW_LEN) {
                printf("  \033[90m%04zx\033[0m  ", i);
                print_hex_dump_line(data, len, i);
        }
}

/*
 *		H A N D L E _ T C P
 *
 * Parse TCP header and print connection details.
 */
static size_t
handle_tcp(const u_char *buf, size_t offset, ssize_t n)
{
        struct tcphdr *tcp;

        /* Verify buffer contains enough data for TCP header */
        if (n < (ssize_t)(offset + sizeof(struct tcphdr))) {
                return offset;
        }

        tcp = (struct tcphdr *)(buf + offset);
        
        /* Print source and destination ports */
        printf("    \033[1;36m[TCP]\033[0m %u -> %u [", ntohs(tcp->th_sport),
               ntohs(tcp->th_dport));
               
        /* Print TCP flags */
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
                
        /* Print sequence, acknowledgment, and window size */
        printf("] Seq: %u, Ack: %u, Win: %u\n", ntohl(tcp->th_seq),
               ntohl(tcp->th_ack), ntohs(tcp->th_win));

        /* Return new offset including TCP header */
        return offset + (tcp->th_off << TCP_HDR_LEN_SHIFT);
}

/*
 *		H A N D L E _ U D P
 *
 * Parse UDP header and print details.
 */
static size_t
handle_udp(const u_char *buf, size_t offset, ssize_t n)
{
        struct udphdr *udp;

        /* Verify buffer contains enough data for UDP header */
        if (n < (ssize_t)(offset + sizeof(struct udphdr))) {
                return offset;
        }

        udp = (struct udphdr *)(buf + offset);
        
        /* Print UDP source, destination, and length */
        printf("    \033[1;36m[UDP]\033[0m %u -> %u (Len: %u)\n",
               ntohs(udp->uh_sport), ntohs(udp->uh_dport), ntohs(udp->uh_ulen));

        /* Return new offset including UDP header */
        return offset + sizeof(struct udphdr);
}

/*
 *		H A N D L E _ I C M P
 *
 * Parse ICMP header and print type and code.
 */
static size_t
handle_icmp(const u_char *buf, size_t offset, ssize_t n)
{
        struct icmp *icmp;

        /* Verify buffer contains enough data for ICMP header */
        if (n < (ssize_t)(offset + ICMP_MIN_HDR_LEN)) {
                return offset;
        }

        icmp = (struct icmp *)(buf + offset);
        
        /* Print ICMP type and code */
        printf("    \033[1;36m[ICMP]\033[0m Type: %u, Code: %u\n",
               icmp->icmp_type, icmp->icmp_code);

        /* Return new offset including ICMP minimum header */
        return offset + ICMP_MIN_HDR_LEN;
}

/*
 *		H A N D L E _ I C M P V 6
 *
 * Parse ICMPv6 header and print type and code.
 */
static size_t
handle_icmpv6(const u_char *buf, size_t offset, ssize_t n)
{
        struct icmp6_hdr *icmp6;

        /* Verify buffer contains enough data for ICMPv6 header */
        if (n < (ssize_t)(offset + sizeof(struct icmp6_hdr))) {
                return offset;
        }

        icmp6 = (struct icmp6_hdr *)(buf + offset);
        
        /* Print ICMPv6 type and code */
        printf("    \033[1;36m[ICMPv6]\033[0m Type: %u, Code: %u\n",
               icmp6->icmp6_type, icmp6->icmp6_code);

        /* Return new offset including ICMPv6 header */
        return offset + sizeof(struct icmp6_hdr);
}

/*
 *		H A N D L E _ L 4 _ P R O T O C O L
 *
 * Route packet to correct layer 4 handler based on protocol number.
 */
static size_t
handle_l4_protocol(const u_char *buf, size_t offset, ssize_t n, u_char l4_proto)
{
        /* Dispatch to the appropriate protocol handler */
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
        
        /* If protocol is unknown, just return current offset */
        return offset;
}

/*
 *		H A N D L E _ I P V 4
 *
 * Parse an IPv4 header, print addressing info, and determine L4 protocol.
 */
static size_t
handle_ipv4(const u_char *buf, size_t offset, ssize_t n, u_char *l4_proto)
{
        struct ip *ip_hdr;
        int hlen;
        char src_ip[INET_ADDRSTRLEN];
        char dst_ip[INET_ADDRSTRLEN];

        /* Verify buffer contains enough data for IPv4 header */
        if (n < (ssize_t)(offset + sizeof(struct ip))) {
                return offset;
        }

        ip_hdr = (struct ip *)(buf + offset);
        hlen = ip_hdr->ip_hl << IPV4_HLEN_SHIFT;
        
        /* Extract L4 protocol from IPv4 header */
        *l4_proto = ip_hdr->ip_p;

        /* Convert source and destination IPs to strings */
        inet_ntop(AF_INET, &ip_hdr->ip_src, src_ip, sizeof(src_ip));
        inet_ntop(AF_INET, &ip_hdr->ip_dst, dst_ip, sizeof(dst_ip));

        /* Print IPv4 addressing and protocol information */
        printf("\033[1;32m[IPv4]\033[0m %s -> %s (Proto: %u, Len: %u)\n",
               src_ip, dst_ip, ip_hdr->ip_p, ntohs(ip_hdr->ip_len));

        /* Return new offset including IPv4 header */
        return offset + hlen;
}

/*
 *		H A N D L E _ I P V 6
 *
 * Parse an IPv6 header, print addressing info, and determine L4 protocol.
 */
static size_t
handle_ipv6(const u_char *buf, size_t offset, ssize_t n, u_char *l4_proto)
{
        struct ip6_hdr *ip6;
        char src_ip[INET6_ADDRSTRLEN];
        char dst_ip[INET6_ADDRSTRLEN];

        /* Verify buffer contains enough data for IPv6 header */
        if (n < (ssize_t)(offset + sizeof(struct ip6_hdr))) {
                return offset;
        }

        ip6 = (struct ip6_hdr *)(buf + offset);
        
        /* Extract L4 protocol from IPv6 next header field */
        *l4_proto = ip6->ip6_nxt;

        /* Convert source and destination IPs to strings */
        inet_ntop(AF_INET6, &ip6->ip6_src, src_ip, sizeof(src_ip));
        inet_ntop(AF_INET6, &ip6->ip6_dst, dst_ip, sizeof(dst_ip));

        /* Print IPv6 addressing and protocol information */
        printf("\033[1;32m[IPv6]\033[0m %s -> %s (Next: %u)\n", src_ip, dst_ip,
               ip6->ip6_nxt);

        /* Return new offset including IPv6 header */
        return offset + sizeof(struct ip6_hdr);
}

/*
 *		P R O C E S S _ P A C K E T
 *
 * Decode Ethernet frames and dispatch to specific network layer handlers.
 */
static void
process_packet(const sniff_config_t *config, const u_char *buf, ssize_t n)
{
        struct ether_header *eth;
        u_short eth_type;
        u_char l4_proto;
        size_t offset;
        size_t next_offset;
        
        l4_proto = 0;

        /* Ensure buffer contains at least an Ethernet header */
        if (n < (ssize_t)sizeof(struct ether_header)) {
                return;
        }

        eth = (struct ether_header *)buf;
        eth_type = ntohs(eth->ether_type);

        /* Print Ethernet MAC addresses and frame type */
        printf("\n\033[1;34m[MAC]\033[0m %02x:%02x:%02x:%02x:%02x:%02x -> "
               "%02x:%02x:%02x:%02x:%02x:%02x (Type: 0x%04x)\n",
               eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2],
               eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5],
               eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2],
               eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5],
               eth_type);

        offset = sizeof(struct ether_header);
        next_offset = offset;

        /* Branch based on the Ethernet type field */
        if (eth_type == ETHERTYPE_IP) {
                next_offset = handle_ipv4(buf, offset, n, &l4_proto);
        } else if (eth_type == ETHERTYPE_IPV6) {
                next_offset = handle_ipv6(buf, offset, n, &l4_proto);
        }

        offset = next_offset;

        /* If verbosity allows and L4 proto is known, parse L4 header */
        if (config->verbosity >= 1 && l4_proto != 0) {
                offset = handle_l4_protocol(buf, offset, n, l4_proto);
        }

        /* Print full or partial hex dumps based on verbosity */
        if (config->verbosity >= 3 && n > 0) {
                printf("    \033[1;35m[Full Packet Dump]\033[0m\n");
                print_hex_dump(buf, n);
        } else if (config->verbosity >= 2 && (ssize_t)offset < n) {
                printf("    \033[1;35m[Payload Dump]\033[0m\n");
                print_hex_dump(buf + offset, n - offset);
        }
}

/*
 *		S N I F F _ R U N
 *
 * Main sniffing loop, captures packets and processes them.
 */
int
sniff_run(const sniff_config_t *config)
{
        struct sigaction sa;
        sniff_state_t st;
        __attribute__((aligned(8))) u_char buf[SNIFF_BUF_SIZE];
        ssize_t n;

        /* Interface is required to capture packets */
        if (!config->iface) {
                log_err("Interface is required for sniffing");
                return EXIT_FAILURE;
        }

        /* Register signal handlers to gracefully shut down on interrupt */
        memset(&sa, 0, sizeof(sa));
        sa.sa_handler = handle_sigint;
        sigaction(SIGINT, &sa, NULL);
        sigaction(SIGTERM, &sa, NULL);
        sigaction(SIGQUIT, &sa, NULL);

        /* Initialize capture state */
        st.packets_captured = 0;
        st.pcap_fp = NULL;
        st.sock = net_open_raw_socket(config->iface, ETH_P_ALL);

        /* Check for proper privileges */
        if (!st.sock) {
                die("Failed to open raw socket. Are you root?");
        }

        /* Open PCAP file if requested and write global header */
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

        /* Attempt to enable promiscuous mode for full visibility */
        if (!net_set_promiscuous(st.sock)) {
                log_warn("Failed to set promiscuous mode. Sniffing might be "
                         "limited.");
        }

        /* Drop privileges for security if running as root */
        if (setuid(getuid()) != 0) {
                log_warn("Failed to drop user privileges");
        }

        log_info("Sniffing on interface %s...", config->iface);

        /* Main capture loop */
        while (keep_running) {
                /* Check if packet count limit has been reached */
                if (config->max_packets > 0 && st.packets_captured >= config->max_packets) {
                        break;
                }
                
                n = net_recv_packet(st.sock, buf, sizeof(buf));
                /* Skip on read error or empty packet */
                if (n <= 0) {
                        continue;
                }

                /* Process and optionally record the packet */
                process_packet(config, buf, n);
                write_pcap_packet(st.pcap_fp, buf, n);
                
                st.packets_captured++;
        }

        /* Close PCAP file if it was opened */
        if (st.pcap_fp) {
                fclose(st.pcap_fp);
        }

        /* Clean up raw socket */
        net_close_raw_socket(st.sock);
        printf("\n");
        log_info("Captured %d packets", st.packets_captured);

        return EXIT_SUCCESS;
}
"""

sniff_cli_c = r"""/***************************************************************************
 * sniff_cli.c -- CLI wrapper for the sniff utility                        *
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
#include "utils.h"

#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "cli.h"

static const cli_option_t sniff_options[] = {
    {'I', "iface", "interface to sniff on (required)"},
    {'c', "count", "stop after receiving count packets"},
    {'w', "file", "write packets to a PCAP file"},
    {'v', NULL,
     "increase verbosity (max level: 3, e.g. -vvv)\n-v   : show L4 headers "
     "(TCP/UDP/ICMP)\n-vv  : show L4 headers + payload hex-dump\n-vvv : show "
     "L4 headers + full packet hex-dump"},
    {'h', NULL, "print help and exit"},
    {0, NULL, NULL}};

/*
 *		P R I N T _ U S A G E
 *
 * Print the usage instructions for the sniff CLI utility.
 */
static void
print_usage(const char *prog_name)
{
        cli_app_t app = {.prog_name = prog_name,
                         .usage_args = "[options]",
                         .options = sniff_options};
                         
        /* Delegate to common CLI help printer */
        cli_print_help(&app);
}

/*
 *		S N I F F _ C L I _ M A I N
 *
 * Parse arguments and execute the sniff tool.
 */
int
sniff_cli_main(int c, char **av)
{
        sniff_config_t config;
        int ch;
        const char *prog_name;
        
        prog_name = *av;

        /* Ensure configuration is fully zero-initialized */
        memset(&config, 0, sizeof(config));

        /* Parse CLI options using getopt */
        while ((ch = getopt(c, av, "I:c:w:vh")) != -1) {
                switch (ch) {
                case 'I':
                        config.iface = optarg;
                        break;
                case 'c':
                        config.max_packets = atoi(optarg);
                        break;
                case 'w':
                        config.pcap_file = optarg;
                        break;
                case 'v':
                        config.verbosity++;
                        break;
                case 'h':
                        print_usage(prog_name);
                        return EXIT_SUCCESS;
                default:
                        print_usage(prog_name);
                        return EXIT_FAILURE;
                }
        }
        
        /* Adjust argument counts using strict pointer arithmetic */
        c -= optind;
        av += optind;

        /* The interface flag is mandatory for sniffing */
        if (!config.iface) {
                log_err("Interface is required (-I)");
                print_usage(prog_name);
                return EXIT_FAILURE;
        }

        /* Check for root permissions */
        if (getuid() != 0) {
                log_warn("sniff requires root privileges to open raw sockets.");
        }

        /* Delegate to the core run logic */
        return sniff_run(&config);
}
"""

with open('src/tools/sniff/sniff.c', 'w') as f:
    f.write(sniff_c)

with open('src/tools/sniff/sniff_cli.c', 'w') as f:
    f.write(sniff_cli_c)

