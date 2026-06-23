#ifndef KNETUTILS_ARPING_H
#define KNETUTILS_ARPING_H

#include <stdbool.h>
#include <stdint.h>

typedef struct {
        const char *iface;
        uint32_t target_ip;
        uint32_t source_ip;
        uint8_t source_mac[6];
        uint32_t count;
        uint64_t timeout_ns;
        uint64_t interval_ns;
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

int arping_run(const arping_config_t *config);

#endif
