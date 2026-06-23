#ifndef KNETUTILS_PING_H
#define KNETUTILS_PING_H

#include <stdbool.h>
#include <stdint.h>

typedef struct {
        uint32_t target_ip;
        uint32_t count;
        uint64_t timeout_ns;
        uint64_t interval_ns;
        uint32_t payload_size;
        uint8_t ttl;
        bool quiet;
        const char *time_unit;
} ping_config_t;

int ping_run(const ping_config_t *config);

#endif
