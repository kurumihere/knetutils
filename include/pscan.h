#ifndef KNETUTILS_PSCAN_H
#define KNETUTILS_PSCAN_H

#include <stdbool.h>
#include <stdint.h>
#include <sys/socket.h>

typedef struct {
        uint16_t start_port;
        uint16_t end_port;
        uint64_t timeout_ns;
        struct sockaddr_storage target_addr;
        socklen_t target_addr_len;
        int family;
        const char *bind_iface;
} pscan_config_t;

int pscan_run(const pscan_config_t *config);

#endif
