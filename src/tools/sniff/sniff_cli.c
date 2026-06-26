#include "sniff.h"
#include "utils.h"

#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "cli.h"

static const cli_option_t sniff_options[] = {
    {'I', "iface", "interface to sniff on (required)"},
    {'c', "count", "stop after receiving count packets"},
    {'w', "file", "write packets to a PCAP file"},
    {'v', NULL,
     "increase verbosity (max level: 3, e.g. -vvv)\n-v   : show L4 headers "
     "(TCP/UDP/ICMP)\n-vv  : show L4 headers + payload hex-dump\n-vvv : show "
     "L4 headers + full packet hex-dump"},
    {'h', NULL, "print help and exit"},
    {0, NULL, NULL}};

static void
print_usage(const char *prog_name)
{
        cli_app_t app = {.prog_name = prog_name,
                         .usage_args = "[options]",
                         .options = sniff_options};
        cli_print_help(&app);
}

int
sniff_cli_main(int argc, char *argv[])
{
        sniff_config_t config;
        int opt;

        memset(&config, 0, sizeof(config));

        while ((opt = getopt(argc, argv, "I:c:w:vh")) != -1) {
                switch (opt) {
                case 'I':
                        config.iface = optarg;
                        break;
                case 'c':
                        config.max_packets = atoi(optarg);
                        break;
                case 'w':
                        config.pcap_file = optarg;
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
