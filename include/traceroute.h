#ifndef KNETUTILS_TRACEROUTE_H
#define KNETUTILS_TRACEROUTE_H

#include <stdbool.h>
#include <stdint.h>
#include <sys/socket.h>

typedef struct {
        uint8_t first_ttl;
        uint8_t max_ttl;
        uint8_t queries;
        uint64_t timeout_ns;
        struct sockaddr_storage target_addr;
        socklen_t target_addr_len;
        int family;
        const char *bind_iface;
        bool resolve_hostnames;
        bool use_udp;
} traceroute_config_t;

int traceroute_run(const traceroute_config_t *config);

#endif
