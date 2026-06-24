#ifndef KNETUTILS_TCPING_H
#define KNETUTILS_TCPING_H

#include <stdbool.h>
#include <stdint.h>
#include <sys/socket.h>

typedef struct {
        uint16_t port;
        uint32_t count;
        uint64_t timeout_ns;
        uint64_t interval_ns;
        struct sockaddr_storage target_addr;
        socklen_t target_addr_len;
        int family;
        const char *bind_iface;
        bool quiet;
} tcping_config_t;

int tcping_run(const tcping_config_t *config);

#endif
