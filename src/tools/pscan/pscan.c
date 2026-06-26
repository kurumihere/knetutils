#include "pscan.h"
#include "net.h"
#include "utils.h"
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef struct {
        net_socket_t *sock;
        struct sockaddr_storage src_addr;
        socklen_t src_addr_len;
        char target_str[INET6_ADDRSTRLEN];
        uint16_t sport;
} pscan_state_t;

struct ipv6_pseudo_header {
        struct in6_addr src_addr;
        struct in6_addr dst_addr;
        uint32_t tcp_length;
        uint8_t zero[3];
        uint8_t next_header;
} __attribute__((packed));

struct ipv4_pseudo_header {
        uint32_t src_addr;
        uint32_t dst_addr;
        uint8_t zero;
        uint8_t protocol;
        uint16_t tcp_length;
} __attribute__((packed));

static void
init_pscan_state(const pscan_config_t *config, pscan_state_t *st)
{
        memset(st, 0, sizeof(*st));

        getnameinfo((struct sockaddr *)&config->target_addr,
                    config->target_addr_len, st->target_str,
                    sizeof(st->target_str), NULL, 0, NI_NUMERICHOST);

        st->src_addr_len = sizeof(st->src_addr);
        if (!net_get_source_ip_for(&config->target_addr,
                                   config->target_addr_len, &st->src_addr,
                                   &st->src_addr_len)) {
                die("Failed to determine source IP for target");
        }

        st->sport = 1024 + (getpid() % 64000);
}

static void
send_syn_probe(const pscan_config_t *config, pscan_state_t *st, uint16_t dport)
{
        struct tcphdr tcph;
        memset(&tcph, 0, sizeof(tcph));
        tcph.th_sport = htons(st->sport);
        tcph.th_dport = htons(dport);
        tcph.th_seq = htonl(1000 + dport);
        tcph.th_ack = 0;
        tcph.th_off = 5;
        tcph.th_flags = TH_SYN;
        tcph.th_win = htons(64240);
        tcph.th_sum = 0;

        uint8_t csum_buf[1024];
        int csum_len = 0;

        if (config->target_addr.ss_family == AF_INET) {
                struct ipv4_pseudo_header psh;
                psh.src_addr =
                    ((struct sockaddr_in *)&st->src_addr)->sin_addr.s_addr;
                psh.dst_addr = ((struct sockaddr_in *)&config->target_addr)
                                   ->sin_addr.s_addr;
                psh.zero = 0;
                psh.protocol = IPPROTO_TCP;
                psh.tcp_length = htons(sizeof(struct tcphdr));

                memcpy(csum_buf, &psh, sizeof(psh));
                csum_len += sizeof(psh);
        } else {
                struct ipv6_pseudo_header psh;
                psh.src_addr =
                    ((struct sockaddr_in6 *)&st->src_addr)->sin6_addr;
                psh.dst_addr =
                    ((struct sockaddr_in6 *)&config->target_addr)->sin6_addr;
                psh.tcp_length = htonl(sizeof(struct tcphdr));
                memset(psh.zero, 0, 3);
                psh.next_header = IPPROTO_TCP;

                memcpy(csum_buf, &psh, sizeof(psh));
                csum_len += sizeof(psh);
        }

        memcpy(csum_buf + csum_len, &tcph, sizeof(tcph));
        csum_len += sizeof(tcph);

        tcph.th_sum = net_checksum(csum_buf, csum_len);

        struct sockaddr_storage dst;
        memcpy(&dst, &config->target_addr, config->target_addr_len);
        if (dst.ss_family == AF_INET) {
                ((struct sockaddr_in *)&dst)->sin_port = htons(dport);
        } else {
                ((struct sockaddr_in6 *)&dst)->sin6_port = htons(dport);
        }

        if (net_send_ip_raw(st->sock, &tcph, sizeof(tcph),
                            (struct sockaddr *)&dst,
                            config->target_addr_len) < 0) {
        }
}

static void
process_packet(const pscan_config_t *config, const pscan_state_t *st,
               uint8_t *buf, ssize_t len, const struct sockaddr_storage *src)
{
        if (len < (ssize_t)sizeof(struct tcphdr))
                return;

        char src_str[INET6_ADDRSTRLEN];
        getnameinfo((struct sockaddr *)src,
                    src->ss_family == AF_INET ? sizeof(struct sockaddr_in)
                                              : sizeof(struct sockaddr_in6),
                    src_str, sizeof(src_str), NULL, 0, NI_NUMERICHOST);

        if (strcmp(src_str, st->target_str) != 0)
                return;

        struct tcphdr *tcph;
        if (src->ss_family == AF_INET) {
                struct ip *iph = (struct ip *)buf;
                int ip_hlen = iph->ip_hl << 2;
                if (len < ip_hlen + (ssize_t)sizeof(struct tcphdr))
                        return;
                tcph = (struct tcphdr *)(buf + ip_hlen);
        } else {
                tcph = (struct tcphdr *)buf;
        }

        if (ntohs(tcph->th_dport) != st->sport)
                return;

        uint16_t port = ntohs(tcph->th_sport);
        if (port < config->start_port || port > config->end_port)
                return;

        if ((tcph->th_flags & TH_SYN) && (tcph->th_flags & TH_ACK)) {
                printf("Port %u is open\n", port);
        }
}

static void
drain_packets(const pscan_config_t *config, pscan_state_t *st)
{
        uint8_t buf[2048];
        struct sockaddr_storage src;
        socklen_t src_len;
        while (true) {
                struct pollfd pfd = {net_get_fd(st->sock), POLLIN, 0};
                if (poll(&pfd, 1, 0) <= 0)
                        break;

                src_len = sizeof(src);
                ssize_t len =
                    net_recv_ip_raw(st->sock, buf, sizeof(buf), &src, &src_len);
                if (len < 0)
                        break;
                process_packet(config, st, buf, len, &src);
        }
}

int
pscan_run(const pscan_config_t *config)
{
        pscan_state_t st;
        init_pscan_state(config, &st);

        st.sock =
            net_open_ip_raw_socket(config->target_addr.ss_family, IPPROTO_TCP);
        if (!st.sock) {
                die("Failed to open raw TCP socket. Are you root?");
        }

        if (config->bind_iface) {
#ifdef SO_BINDTODEVICE
                if (setsockopt(net_get_fd(st.sock), SOL_SOCKET, SO_BINDTODEVICE,
                               config->bind_iface,
                               strlen(config->bind_iface)) < 0) {
                        die("Failed to bind to interface %s",
                            config->bind_iface);
                }
#else
                log_warn("SO_BINDTODEVICE not supported on this platform");
#endif
        }

        printf("Scanning %s ports %u to %u...\n", st.target_str,
               config->start_port, config->end_port);

        for (uint16_t port = config->start_port; port <= config->end_port;
             port++) {
                send_syn_probe(config, &st, port);
                drain_packets(config, &st);
                usleep(100);
        }

        uint64_t start_wait = get_time_ns();
        while (get_time_ns() - start_wait < config->timeout_ns) {
                struct pollfd pfd = {net_get_fd(st.sock), POLLIN, 0};
                if (poll(&pfd, 1, 100) > 0) {
                        drain_packets(config, &st);
                }
        }

        net_close_raw_socket(st.sock);
        return EXIT_SUCCESS;
}
