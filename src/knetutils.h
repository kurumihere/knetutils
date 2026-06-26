/***************************************************************************
 * knetutils.h -- Unified header for knetutils suite                       *
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

#ifndef KNETUTILS_H
#define KNETUTILS_H

#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <sys/socket.h>
#include <sys/types.h>

/* --- CLI helper declarations --- */
typedef struct {
    char short_opt;
    const char *arg_name;
    const char *description;
} cli_option_t;

typedef struct {
    const char *prog_name;
    const char *usage_args;
    const cli_option_t *options;
} cli_app_t;

void cli_print_help(const cli_app_t *app);

/* --- Networking helper declarations --- */
#ifndef ETH_ALEN
#ifdef ETHER_ADDR_LEN
#define ETH_ALEN ETHER_ADDR_LEN
#else
#define ETH_ALEN 6
#endif
#endif

typedef struct net_socket net_socket_t;

bool get_iface_mac(const char *iface, u_char *mac);
bool get_iface_addr(const char *iface, u_int *ip);
int get_iface_index(const char *iface);
net_socket_t *open_raw_socket(const char *iface, u_short protocol);
void close_raw_socket(net_socket_t *sock);
bool set_promiscuous(net_socket_t *sock);
ssize_t send_packet(net_socket_t *sock, const void *buf, size_t len,
                    const u_char *dst_mac);
ssize_t recv_packet(net_socket_t *sock, void *buf, size_t len);
int get_socket_fd(net_socket_t *sock);
bool resolve_host(const char *hostname, int family, struct sockaddr_storage *ss,
                  socklen_t *ss_len);
bool resolve_ipv4(const char *hostname, u_int *ip);
bool parse_mac(const char *mac_str, u_char *mac);
bool get_default_gateway(const char *iface, u_int *gateway_ip);
net_socket_t *open_icmp_socket(int family);
bool is_dgram(net_socket_t *sock);
ssize_t send_icmp_packet(net_socket_t *sock, const void *buf, size_t len,
                         const struct sockaddr *dest, socklen_t dest_len);
ssize_t recv_icmp_packet(net_socket_t *sock, void *buf, size_t len,
                         struct sockaddr_storage *src, socklen_t *src_len);
ssize_t send_ip_raw(net_socket_t *sock, const void *buf, size_t len,
                    const struct sockaddr *dest, socklen_t dest_len);
ssize_t recv_ip_raw(net_socket_t *sock, void *buf, size_t len,
                    struct sockaddr_storage *src, socklen_t *src_len);
net_socket_t *open_ip_raw_socket(int family, int protocol);
bool get_source_ip_for(const struct sockaddr_storage *dst, socklen_t dst_len,
                       struct sockaddr_storage *src, socklen_t *src_len);
u_short calculate_checksum(const void *b, int len);

/* --- Utility helper declarations --- */
#define COLOR_RESET "\x1b[0m"
#define COLOR_RED "\x1b[31m"
#define COLOR_GREEN "\x1b[32m"
#define COLOR_YELLOW "\x1b[33m"
#define COLOR_BLUE "\x1b[34m"
#define COLOR_CYAN "\x1b[36m"
#define COLOR_BOLD "\x1b[1m"

#define NS_PER_S 1000000000ULL
#define NS_PER_MS 1000000ULL
#define NS_PER_US 1000ULL

void log_err(const char *fmt, ...);
void log_warn(const char *fmt, ...);
void log_info(const char *fmt, ...);
void die(const char *fmt, ...) __attribute__((noreturn));
u_int64_t get_time_ns(void);
u_int64_t time_diff_ns(u_int64_t start, u_int64_t end);
const char *format_time(u_int64_t time_ns, const char *unit_choice, char *buf,
                        size_t buf_size);

/* --- Tool Configuration Structs --- */

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

/* --- Tool Main Entrypoints --- */
int arping_main(int c, char **av);
int ping_main(int c, char **av);
int sniff_main(int c, char **av);
int tcping_main(int c, char **av);
int traceroute_main(int c, char **av);
int pscan_main(int c, char **av);

#endif /* KNETUTILS_H */
