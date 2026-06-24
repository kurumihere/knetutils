#include "sniff.h"
#include "utils.h"

#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void
print_usage(const char *prog_name)
{
        fprintf(stderr, "Usage: %s [options]\n", prog_name);
        fprintf(stderr, "Options:\n");
        fprintf(stderr, "  -I <iface>      interface to sniff on (required)\n");
        fprintf(stderr,
                "  -c <count>      stop after receiving count packets\n");
        fprintf(
            stderr,
            "  -v              increase verbosity (max level: 3, e.g. -vvv)\n");
        fprintf(stderr,
                "                    -v   : show L4 headers (TCP/UDP/ICMP)\n");
        fprintf(
            stderr,
            "                    -vv  : show L4 headers + payload hex-dump\n");
        fprintf(stderr, "                    -vvv : show L4 headers + full "
                        "packet hex-dump\n");
        fprintf(stderr, "  -h              print help and exit\n");
}

int
sniff_cli_main(int argc, char *argv[])
{
        sniff_config_t config;
        memset(&config, 0, sizeof(config));

        int opt;
        while ((opt = getopt(argc, argv, "I:c:vh")) != -1) {
                switch (opt) {
                case 'I':
                        config.iface = optarg;
                        break;
                case 'c':
                        config.max_packets = atoi(optarg);
                        break;
                case 'v':
                        config.verbosity++;
                        break;
                case 'h':
                        print_usage(argv[0]);
                        return EXIT_SUCCESS;
                default:
                        print_usage(argv[0]);
                        return EXIT_FAILURE;
                }
        }

        if (!config.iface) {
                log_err("Interface is required (-I)");
                print_usage(argv[0]);
                return EXIT_FAILURE;
        }

        if (getuid() != 0) {
                log_warn("sniff requires root privileges to open raw sockets.");
        }

        return sniff_run(&config);
}
