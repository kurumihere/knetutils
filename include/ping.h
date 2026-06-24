#ifndef KNETUTILS_PING_H
#define KNETUTILS_PING_H

#include <stdbool.h>
#include <stdint.h>
#include <sys/socket.h>

typedef struct {
        uint32_t count;
        uint64_t timeout_ns;
        uint64_t interval_ns;
        uint32_t payload_size;
        uint8_t ttl;
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
        uint8_t pattern[16];
        size_t pattern_len;
} ping_config_t;

int ping_run(const ping_config_t *config);

#endif
