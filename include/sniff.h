#ifndef KNETUTILS_SNIFF_H
#define KNETUTILS_SNIFF_H

#include <stdbool.h>

typedef struct {
        const char *iface;
        int max_packets;
} sniff_config_t;

int sniff_run(const sniff_config_t *config);

#endif
